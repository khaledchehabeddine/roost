#!/usr/bin/env python3
"""Collect checked mobile outputs, verify signed candidates, and publish unchanged bytes."""

import argparse
import base64
import fnmatch
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import zipfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE_REPO = "RelayNet/roost"
OWNER = "KhaledChehabeddine"
FINGERPRINT = "8C936E5EE86B909B53B607EA0EEDE342BC541851"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def gh(*args):
    return subprocess.check_output(["gh", *args])


def api(path, payload=None, method=None, missing=False):
    args = ["gh", "api", "--hostname", "github.com", path]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as body:
        if payload is not None:
            json.dump(payload, body)
            body.flush()
            args += ["--input", body.name, "--method", method or "POST"]
        result = subprocess.run(args, capture_output=True, check=False)
    if missing and result.returncode and b"(HTTP 404)" in result.stderr:
        return None
    require(result.returncode == 0, f"GitHub request failed: {path}")
    return json.loads(result.stdout) if result.stdout else None


def digest(data):
    return hashlib.sha256(data).hexdigest()


def inputs():
    revision = os.environ["ROOST_SOURCE_REVISION"]
    require(re.fullmatch(r"[0-9a-f]{40}", revision), "source must be a full commit SHA")
    head = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
    if head == revision:
        manifest = (ROOT / "Cargo.toml").read_text()
    else:
        manifest = base64.b64decode(api(f"repos/{SOURCE_REPO}/contents/Cargo.toml?ref={revision}")["content"]).decode()
    version = tomllib.loads(manifest)["workspace"]["package"]["version"]
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version), "release version must be stable")
    require(version != "0.15.0", "v0.15.0 is historical")
    files = [f"Roost-v{version}.xcframework.zip", f"roost-{version}.aar", f"roost-{version}.pom"]
    pins = json.loads(os.environ["ROOST_SHA256_JSON"])
    require(isinstance(pins, dict) and set(pins) == set(files), "pin the XCFramework ZIP, AAR and POM")
    require(all(isinstance(pin, str) and re.fullmatch(r"[0-9a-f]{64}", pin) for pin in pins.values()),
            "invalid SHA-256 pin")
    return revision, version, {name: pins[name] for name in files}


def checked_run(repo, run_id, workflow, job, attempt=None):
    require(re.fullmatch(r"[0-9]+", run_id), "invalid workflow run ID")
    run = api(f"repos/{repo}/actions/runs/{run_id}")
    if attempt is not None:
        require(re.fullmatch(r"[0-9]+", attempt), "invalid workflow attempt")
        run = api(f"repos/{repo}/actions/runs/{run_id}/attempts/{attempt}")
    require(run["event"] == "workflow_dispatch" and run["head_branch"] == "main"
            and run["path"] == f".github/workflows/{workflow}"
            and run["head_repository"]["full_name"] == repo
            and run["status"] == "completed" and run["conclusion"] == "success",
            f"untrusted or unsuccessful candidate run in {repo}")
    require(run["actor"]["login"] == OWNER and run["triggering_actor"]["login"] == OWNER,
            "candidate initial and rerun actors must be the release owner")
    require(api(f"repos/{repo}/compare/{run['head_sha']}...main")["status"] in ("ahead", "identical"),
            f"{repo} candidate is outside trusted main history")
    jobs = api(f"repos/{repo}/actions/runs/{run_id}/attempts/{run['run_attempt']}/jobs")["jobs"]
    require(any(item["name"] == job and item["conclusion"] == "success" for item in jobs),
            f"missing successful {job} job")
    return run


def download(repo, run, name, expected, output):
    artifacts = api(f"repos/{repo}/actions/runs/{run['id']}/artifacts?per_page=100")["artifacts"]
    matches = [item for item in artifacts if item["name"] == name and not item["expired"]]
    require(len(matches) == 1, "missing or ambiguous candidate artifact")
    artifact = matches[0]
    require(artifact["workflow_run"]["head_sha"] == run["head_sha"], "artifact source mismatch")
    data = gh("api", "--hostname", "github.com", f"repos/{repo}/actions/artifacts/{artifact['id']}/zip")
    require(artifact.get("digest") == f"sha256:{digest(data)}", "GitHub artifact digest mismatch")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        require(sorted(archive.namelist()) == sorted(expected), "unexpected candidate files")
        for name in expected:
            (output / name).write_bytes(archive.read(name))


def verify_files(output, pins):
    for name, pin in pins.items():
        require(digest((output / name).read_bytes()) == pin, f"pinned SHA-256 mismatch: {name}")


def verify_signed(output, revision, version, pins):
    expected = f"# Roost v{version}\n\nSource: `{revision}`\nWorkspace version: `{version}`\n"
    require((output / "release-notes.md").read_text().startswith(expected), "candidate source/version differs from the selected release")
    verify_files(output, pins)
    for name, pin in pins.items():
        subprocess.run([str(ROOT / "scripts/release/verify-artifact.sh"), str(output / name),
                        str(output / f"{name}.asc"), str(output / f"{name}.sha256"),
                        str(output / "roost-release-key.asc"), pin], check=True,
                       env={**os.environ, "ROOST_RELEASE_FINGERPRINT": FINGERPRINT})


def swift_manifest(revision, version, pin, asset_id):
    require(re.fullmatch(r"[0-9]+", str(asset_id)), "invalid Swift release asset ID")
    return f'''// swift-tools-version: 5.9
// Roost source: {revision}
import PackageDescription

let package = Package(
    name: "Roost",
    platforms: [.iOS(.v13)],
    products: [.library(name: "Roost", targets: ["Roost"])],
    targets: [.binaryTarget(
        name: "Roost",
        url: "https://api.github.com/repos/RelayNet/roost-swift/releases/assets/{asset_id}-Roost-v{version}.xcframework.zip",
        checksum: "{pin}"
    )]
)
'''


def collect(output, revision, version, pins):
    require(api(f"repos/{SOURCE_REPO}/commits/main")["sha"] == revision, "source must be current main")
    require(subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip() == revision,
            "prepare from the exact source checkout")
    runs = api(f"repos/{SOURCE_REPO}/actions/workflows/ci.yml/runs?head_sha={revision}&event=push")["workflow_runs"]
    rust = next((run for run in runs if run["head_branch"] == "main" and run["status"] == "completed"
                 and run["conclusion"] == "success" and run["head_repository"]["full_name"] == SOURCE_REPO), None)
    require(rust is not None, "the exact source revision needs successful Rust CI")
    jobs = api(f"repos/{SOURCE_REPO}/actions/runs/{rust['id']}/attempts/{rust['run_attempt']}/jobs")["jobs"]
    require(any(job["name"] == "check" and job["conclusion"] == "success" for job in jobs), "missing successful Rust check job")
    notes = [f"# Roost v{version}\n\nSource: `{revision}`\nWorkspace version: `{version}`\n",
             f"Rust CI: {rust['html_url']}\n"]
    for platform, names in (("swift", list(pins)[:1]), ("kotlin", list(pins)[1:])):
        repo = f"RelayNet/roost-{platform}"
        run = checked_run(repo, os.environ[f"ROOST_{platform.upper()}_RUN"], "check.yml", "check")
        require(api(f"repos/{repo}/commits/main")["sha"] == run["head_sha"], "rerun native checks after package repository changes")
        name = f"roost-{platform}-{revision}-v{version}-{run['run_attempt']}"
        download(repo, run, name, [*names, f"{platform}-notes.md"], output)
        notes += [f"\n{platform.title()} CI: {run['html_url']} (attempt {run['run_attempt']})\n",
                  (output / f"{platform}-notes.md").read_text()]
        (output / f"{platform}-notes.md").unlink()
    verify_files(output, pins)
    notes += [f"\nSigner: `{FINGERPRINT}`\n\nSHA-256:\n", *[f"- `{name}`: `{pin}`\n" for name, pin in pins.items()],
              "\nRelay adoption, published-package resolution, app, extension and device validation remain in #268.\n"]
    (output / "release-notes.md").write_text("".join(notes))


def fetch_signed(output, revision, version, pins, run_id):
    selection = run_id.split("/")
    require(len(selection) == 2, "select the signed candidate as run-id/attempt")
    run = checked_run(SOURCE_REPO, selection[0], "prepare-mobile.yml", "prepare", selection[1])
    require(run["head_sha"] == revision, "prepared candidate has a different source revision")
    require(run["display_title"] == f"Prepare {revision} Swift {os.environ['ROOST_SWIFT_RUN']} Kotlin {os.environ['ROOST_KOTLIN_RUN']}",
            "native candidate runs differ from the signed preparation")
    names = [name + suffix for name in pins for suffix in ("", ".asc", ".sha256")]
    names += ["roost-release-key.asc", "release-notes.md"]
    download(SOURCE_REPO, run, f"roost-signed-{revision}-v{version}-{run['run_attempt']}", names, output)
    verify_signed(output, revision, version, pins)
    native_runs(output)


def native_runs(output):
    notes = (output / "release-notes.md").read_text()
    runs = []
    for platform in ("swift", "kotlin"):
        run_id = os.environ[f"ROOST_{platform.upper()}_RUN"]
        require(re.fullmatch(r"[0-9]+", run_id), "invalid native run ID")
        pattern = rf"^{platform.title()} CI: https://github.com/RelayNet/roost-{platform}/actions/runs/{run_id} \(attempt ([0-9]+)\)$"
        attempts = re.findall(pattern, notes, re.MULTILINE)
        require(len(attempts) == 1, "native run does not match the preparation's release description")
        runs.append(checked_run(f"RelayNet/roost-{platform}", run_id, "check.yml", "check", attempts[0]))
    return runs


def release_controls(repo, tag):
    metadata = api(f"repos/{repo}")
    require(metadata["full_name"] == repo and metadata["private"], "distribution must remain private")
    require(api(f"repos/{repo}/immutable-releases")["enabled"], f"enable immutable releases in {repo}")
    protected = set()
    for summary in api(f"repos/{repo}/rulesets?per_page=100"):
        if summary["target"] != "tag" or summary["enforcement"] != "active":
            continue
        rule = api(f"repos/{repo}/rulesets/{summary['id']}")
        refs = rule["conditions"]["ref_name"]
        applies = any(pattern == "~ALL" or fnmatch.fnmatchcase(f"refs/tags/{tag}", pattern)
                      for pattern in refs["include"])
        excluded = any(fnmatch.fnmatchcase(f"refs/tags/{tag}", pattern) for pattern in refs["exclude"])
        if applies and not excluded and not rule.get("bypass_actors"):
            protected.update(item["type"] for item in rule["rules"])
    require({"update", "deletion"} <= protected, f"protect {repo} version tags against updates and deletion")


def tag_commit(repo, tag):
    ref = api(f"repos/{repo}/git/ref/tags/{tag}", missing=True)
    if ref is None:
        return None
    obj = ref["object"]
    for _ in range(5):
        if obj["type"] == "commit":
            return obj["sha"]
        require(obj["type"] == "tag", "release tag does not name a commit")
        obj = api(f"repos/{repo}/git/tags/{obj['sha']}")["object"]
    raise ValueError("release tag nesting is unsupported")


def release_by_tag(repo, tag):
    # The tag endpoint alone cannot recover a draft whose tag does not exist yet.
    matches = gh("api", "--hostname", "github.com", "--paginate", f"repos/{repo}/releases?per_page=100",
                 "--jq", f'.[] | select(.tag_name == "{tag}") | .id').decode().splitlines()
    require(len(matches) <= 1, f"ambiguous releases for {repo} {tag}")
    if not matches:
        return None
    require(re.fullmatch(r"[0-9]+", matches[0]), "invalid release ID")
    return api(f"repos/{repo}/releases/{matches[0]}")


def uploaded_assets(repo, release, output, files, allow_incomplete=False):
    missing = set(files)
    incomplete = []
    for asset in release["assets"]:
        require(asset["name"] in missing, f"unexpected or duplicate release asset in {repo}")
        if allow_incomplete and asset["state"] == "starter" and asset["size"] == 0:
            incomplete.append(asset["id"])
            continue
        require(asset["state"] == "uploaded", "release contains an incomplete asset")
        remote = gh("api", "--hostname", "github.com", "-H", "Accept: application/octet-stream",
                    f"repos/{repo}/releases/assets/{asset['id']}")
        require(digest(remote) == digest((output / asset["name"]).read_bytes()),
                f"existing release bytes differ: {asset['name']}; use a new version")
        missing.remove(asset["name"])
    return missing, incomplete


class PackageRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, *args, **kwargs):
        redirected = super().redirect_request(request, *args, **kwargs)
        if redirected and urllib.parse.urlsplit(redirected.full_url).netloc != urllib.parse.urlsplit(request.full_url).netloc:
            redirected.remove_header("Authorization")
        return redirected


def maven_file(version, name, data=None):
    url = f"https://maven.pkg.github.com/relaynet/roost-kotlin/io/github/relaynet/roost/{version}/{name}"
    credential = base64.b64encode(f"{OWNER}:{os.environ['GH_TOKEN']}".encode()).decode()
    request = urllib.request.Request(url, data=data, method="GET" if data is None else "PUT",
                                    headers={"Authorization": f"Basic {credential}",
                                             "Content-Type": "application/octet-stream"})
    try:
        with urllib.request.build_opener(PackageRedirect).open(request, timeout=120) as response:
            return response.read()
    except urllib.error.HTTPError as error:
        if data is None and error.code == 404:
            return None
        raise ValueError(f"Maven request failed for {name}: HTTP {error.code}") from error


def publish(output, revision, version, pins):
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and os.environ.get("GITHUB_REF") == "refs/heads/main"
            and os.environ.get("GITHUB_ACTOR") == OWNER
            and os.environ.get("GITHUB_TRIGGERING_ACTOR") == OWNER,
            "publication requires the owner's manual workflow, including reruns")
    verify_signed(output, revision, version, pins)
    auth = subprocess.run(["gh", "auth", "status", "--hostname", "github.com"], capture_output=True)
    require(auth.returncode == 0 and b"'project'" in auth.stdout + auth.stderr, "publication credential needs project scope")
    require(api("user")["login"] == OWNER, "unexpected publication account")
    require(api(f"repos/{SOURCE_REPO}/compare/{revision}...main")["status"] in ("ahead", "identical"),
            "source is outside trusted main history")
    tag = f"v{version}"
    swift, kotlin = native_runs(output)
    names = list(pins)
    destinations = [("RelayNet/roost-swift", swift["head_sha"], names[:1]),
                    ("RelayNet/roost-kotlin", kotlin["head_sha"], names[1:]),
                    (SOURCE_REPO, revision, [])]
    pending = []
    # Inspect every destination before creating tags or uploading any bytes.
    for repo, parent, artifacts in destinations:
        release_controls(repo, tag)
        commit = tag_commit(repo, tag)
        release = release_by_tag(repo, tag)
        if commit is not None:
            if repo.endswith("roost-swift"):
                require(release is not None, "Swift tag is missing its binary release")
                assets = [item for item in release["assets"] if item["name"] == names[0] and item["state"] == "uploaded"]
                require(len(assets) == 1, "Swift tag is missing its completed binary asset")
                manifest = swift_manifest(revision, version, pins[names[0]], assets[0]["id"])
                existing = api(f"repos/{repo}/contents/Package.swift?ref={commit}")
                require(base64.b64decode(existing["content"]).decode() == manifest, "released Swift metadata differs")
                require([item["sha"] for item in api(f"repos/{repo}/git/commits/{commit}")["parents"]] == [parent],
                        "Swift tag must derive from the checked package repository revision")
            else:
                require(commit == parent, f"{repo} tag points at another revision")
        files = [name + suffix for name in artifacts for suffix in ("", ".asc", ".sha256")]
        files += ["roost-release-key.asc"]
        missing = set(files)
        incomplete = []
        if release:
            require(release["body"] == (output / "release-notes.md").read_text(),
                    f"{repo} release description differs from the verified candidate")
            missing, incomplete = uploaded_assets(repo, release, output, files, release["draft"] and commit is None)
            require(release["draft"] or (commit is not None and not missing and release.get("immutable")),
                    "published release is incomplete or mutable")
        pending.append((repo, parent, commit, release, files, missing, incomplete))
    maven_missing = []
    for name in [name + suffix for name in names[1:] for suffix in ("", ".asc", ".sha256")]:
        remote = maven_file(version, name)
        if remote is None:
            maven_missing.append(name)
        else:
            require(digest(remote) == digest((output / name).read_bytes()), f"Maven bytes differ: {name}; use a new version")

    for repo, parent, commit, release, files, missing, incomplete in pending:
        if release is None:
            release = api(f"repos/{repo}/releases", {"tag_name": tag, "name": f"Roost {tag}",
                          "target_commitish": parent, "body": (output / "release-notes.md").read_text(), "draft": True})
        if release["draft"]:
            for asset_id in incomplete:
                gh("api", "--hostname", "github.com", "--method", "DELETE", f"repos/{repo}/releases/assets/{asset_id}")
            if missing:
                gh("release", "upload", tag, "--repo", f"github.com/{repo}",
                   *[str(output / name) for name in sorted(missing)])
            release = api(f"repos/{repo}/releases/{release['id']}")
            require(not uploaded_assets(repo, release, output, files)[0], "draft is missing verified assets")
        if commit is None:
            commit = parent
            if repo.endswith("roost-swift"):
                asset = next(item for item in release["assets"] if item["name"] == names[0])
                manifest = swift_manifest(revision, version, pins[names[0]], asset["id"])
                tree = api(f"repos/{repo}/git/commits/{parent}")["tree"]["sha"]
                tree = api(f"repos/{repo}/git/trees", {"base_tree": tree, "tree": [
                    {"path": "Package.swift", "mode": "100644", "type": "blob", "content": manifest}]})["sha"]
                commit = api(f"repos/{repo}/git/commits", {
                    "message": f"chore: publish Roost {version}\n- Pin the verified binary from {revision}\n\nCo-Authored-By: Codex <noreply@openai.com>",
                    "tree": tree, "parents": [parent]})["sha"]
            api(f"repos/{repo}/git/refs", {"ref": f"refs/tags/{tag}", "sha": commit})
        if release["draft"]:
            api(f"repos/{repo}/releases/{release['id']}", {"draft": False}, method="PATCH")
        require(api(f"repos/{repo}/releases/{release['id']}").get("immutable"), "release did not become immutable")
        require(tag_commit(repo, tag) == commit, "release tag changed during publication")
    for name in maven_missing:
        # Recheck to refuse replacement if a previous upload or another run finished meanwhile.
        data = (output / name).read_bytes()
        remote = maven_file(version, name)
        if remote is None:
            maven_file(version, name, data)
            remote = maven_file(version, name)
        require(remote is not None and digest(remote) == digest(data), f"Maven upload verification failed: {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["collect", "verify", "fetch", "publish"])
    parser.add_argument("directory", type=Path)
    parser.add_argument("--run", default="")
    args = parser.parse_args()
    revision, version, pins = inputs()
    output = args.directory.resolve()
    if args.command in ("collect", "fetch"):
        output.mkdir(parents=True, exist_ok=False)
    if args.command == "collect":
        collect(output, revision, version, pins)
    elif args.command == "fetch":
        fetch_signed(output, revision, version, pins, args.run)
    elif args.command == "verify":
        verify_signed(output, revision, version, pins)
    else:
        publish(output, revision, version, pins)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError, zipfile.BadZipFile) as error:
        raise SystemExit(str(error)) from error
