"""Release CLI regressions with small files and isolated external-tool responses.

The provenance tests stub GitHub and GPG at process boundaries. Signature tests use real GPG
with a temporary keyring. No production credentials or mobile binaries are test inputs.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[2]
COMMAND = ROOT / "scripts/release/mobile.py"
FINGERPRINT = "8C936E5EE86B909B53B607EA0EEDE342BC541851"
ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

# Stub only process/network boundaries. Unexpected traffic fails instead of reaching GitHub.
GITHUB = '''#!/usr/bin/env python3
import base64, json, os, sys
from pathlib import Path
p = Path(os.environ["TEST_RESPONSES"])
state = json.loads(p.read_text())
args = sys.argv[1:]
if args[:2] == ["auth", "status"]:
    print("Token scopes: 'repo', 'project'")
    sys.exit(0)
assert args[0] == "api", args
path = next(arg for arg in args if arg.startswith("repos/") or arg == "user")
method = args[args.index("--method") + 1] if "--method" in args else "GET"
key = method + " " + path
assert key in state["github"], key
response = state["github"][key]
if response is None:
    print("not found (HTTP 404)", file=sys.stderr)
    sys.exit(1)
if method != "GET":
    body = json.loads(Path(args[args.index("--input") + 1]).read_text()) if "--input" in args else {}
    state["writes"].append([key, body])
    if path.endswith("/git/trees"):
        state["manifest"] = body["tree"][0]["content"]
    if path.endswith("/git/commits"):
        repo = path.split("/git/")[0]
        state["github"]["GET " + repo + "/git/commits/" + response["sha"]] = {"parents": [{"sha": parent} for parent in body["parents"]]}
        state["github"]["GET " + repo + "/contents/Package.swift?ref=" + response["sha"]] = {"content": base64.b64encode(state["manifest"].encode()).decode()}
    if path.endswith("/git/refs"):
        state["github"]["GET " + path[:-1] + "/" + body["ref"][5:]] = {"object": {"type": "commit", "sha": body["sha"]}}
    if method == "PATCH":
        state["github"]["GET " + path] = response
p.write_text(json.dumps(state))
if isinstance(response, dict) and "$raw" in response:
    sys.stdout.buffer.write(base64.b64decode(response["$raw"]))
else:
    print(json.dumps(response))
'''

MAVEN = '''import base64, io, json, os, urllib.error, urllib.request
from pathlib import Path
class Registry:
    def open(self, request, **kwargs):
        assert request.full_url.startswith("https://maven.pkg.github.com/relaynet/roost-kotlin/")
        p = Path(os.environ["TEST_RESPONSES"])
        state = json.loads(p.read_text())
        name = request.full_url.rsplit("/", 1)[-1]
        if request.get_method() == "PUT":
            state["writes"].append(["PUT " + name, base64.b64encode(request.data).decode()])
            state["maven"][name] = base64.b64encode(request.data).decode()
            p.write_text(json.dumps(state))
            return io.BytesIO(b"")
        assert request.get_method() == "GET"
        if name not in state["maven"]:
            raise urllib.error.HTTPError(request.full_url, 404, "missing", {}, None)
        return io.BytesIO(base64.b64decode(state["maven"][name]))
urllib.request.build_opener = lambda *args: Registry()
'''


class CandidateCommands(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate"
        self.candidate.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.revision = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
        self.version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
        self.names = [f"Roost-v{self.version}.xcframework.zip", f"roost-{self.version}.aar", f"roost-{self.version}.pom"]
        self.env = {**os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}",
                    "ROOST_SOURCE_REVISION": self.revision, "ROOST_SWIFT_RUN": "101", "ROOST_KOTLIN_RUN": "102",
                    "ROOST_SHA256_JSON": '{' + ','.join(f'"{name}":"{ABC_SHA256}"' for name in self.names) + '}'}
        for name in self.names:
            (self.candidate / name).write_bytes(b"abc")
            (self.candidate / f"{name}.asc").write_text("test signature\n")
            (self.candidate / f"{name}.sha256").write_text(f"{ABC_SHA256}  {name}\n")
        (self.candidate / "roost-release-key.asc").write_text("test public key\n")
        gpg = self.bin / "gpg"
        gpg.write_text(f'#!/bin/sh\nprintf "[GNUPG:] VALIDSIG {FINGERPRINT}\\n"\n')
        gpg.chmod(0o755)
        self.notes = f"# Roost v{self.version}\n\nSource: `{self.revision}`\nWorkspace version: `{self.version}`\n"
        (self.candidate / "release-notes.md").write_text(self.notes)

    def run_command(self, command="verify", *args):
        directory = self.root / "download" if command == "fetch" else self.candidate
        return subprocess.run([sys.executable, str(COMMAND), command, str(directory), *args],
                              env=self.env, capture_output=True, text=True)

    def test_verify_rejects_a_candidate_from_another_source(self):
        (self.candidate / "release-notes.md").write_text(self.notes.replace(self.revision, "0" * 40))
        result = self.run_command()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("source/version", result.stderr)

    def publication(self):
        self.env.update(GITHUB_ACTIONS="true", GITHUB_EVENT_NAME="workflow_dispatch", GITHUB_REF="refs/heads/main",
                        GITHUB_ACTOR="KhaledChehabeddine", GITHUB_TRIGGERING_ACTOR="KhaledChehabeddine", GH_TOKEN="test-token")
        routes = {"GET user": {"login": "KhaledChehabeddine"},
                  f"GET repos/RelayNet/roost/compare/{self.revision}...main": {"status": "ahead"}}
        self.notes += "\nSwift CI: https://github.com/RelayNet/roost-swift/actions/runs/101 (attempt 1)\n"
        self.notes += "\nKotlin CI: https://github.com/RelayNet/roost-kotlin/actions/runs/102 (attempt 1)\n"
        (self.candidate / "release-notes.md").write_text(self.notes)
        tag = f"v{self.version}"
        for index, (repo, parent, files) in enumerate([
            ("RelayNet/roost-swift", "1" * 40, self.names[:1]),
            ("RelayNet/roost-kotlin", "2" * 40, self.names[1:]),
            ("RelayNet/roost", self.revision, []),
        ], start=1):
            prefix = "repos/" + repo
            if index < 3:
                run_id = 100 + index
                run = {"id": run_id, "run_attempt": 1, "event": "workflow_dispatch", "head_branch": "main",
                       "path": ".github/workflows/check.yml", "head_repository": {"full_name": repo},
                       "status": "completed", "conclusion": "success", "head_sha": parent,
                       "actor": {"login": "KhaledChehabeddine"}, "triggering_actor": {"login": "KhaledChehabeddine"}}
                routes[f"GET {prefix}/actions/runs/{run_id}"] = run
                routes[f"GET {prefix}/actions/runs/{run_id}/attempts/1"] = run
                routes[f"GET {prefix}/actions/runs/{run_id}/attempts/1/jobs"] = {"jobs": [{"name": "check", "conclusion": "success"}]}
                routes[f"GET {prefix}/compare/{parent}...main"] = {"status": "ahead"}
            routes[f"GET {prefix}"] = {"full_name": repo, "private": True}
            routes[f"GET {prefix}/immutable-releases"] = {"enabled": True}
            routes[f"GET {prefix}/rulesets?per_page=100"] = [{"id": 1, "target": "tag", "enforcement": "active"}]
            routes[f"GET {prefix}/rulesets/1"] = {"conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
                                                "rules": [{"type": "update"}, {"type": "deletion"}], "bypass_actors": []}
            routes[f"GET {prefix}/git/ref/tags/{tag}"] = None if index == 1 else {"object": {"type": "commit", "sha": parent}}
            routes[f"GET {prefix}/releases?per_page=100"] = {"$raw": base64.b64encode(f"{index}\n".encode()).decode()}
            assets = []
            for number, name in enumerate([n + suffix for n in files for suffix in ("", ".asc", ".sha256")] + ["roost-release-key.asc"], start=index * 10):
                data = (self.candidate / name).read_bytes()
                assets.append({"id": number, "name": name, "state": "uploaded", "size": len(data)})
                routes[f"GET {prefix}/releases/assets/{number}"] = {"$raw": base64.b64encode(data).decode()}
            release = {"id": index, "tag_name": tag, "draft": index == 1, "immutable": index != 1, "assets": assets, "body": self.notes}
            routes[f"GET {prefix}/releases/{index}"] = release
            routes[f"PATCH {prefix}/releases/{index}"] = {**release, "draft": False, "immutable": True}
            if index == 1:
                routes[f"GET {prefix}/git/commits/{parent}"] = {"tree": {"sha": "3" * 40}}
                routes[f"POST {prefix}/git/trees"] = {"sha": "4" * 40}
                routes[f"POST {prefix}/git/commits"] = {"sha": "5" * 40}
                routes[f"POST {prefix}/git/refs"] = {}
        state = {"github": routes, "maven": {}, "writes": []}
        for name in [name + suffix for name in self.names[1:] for suffix in ("", ".asc", ".sha256")]:
            state["maven"][name] = base64.b64encode((self.candidate / name).read_bytes()).decode()
        self.responses = self.root / "responses.json"
        self.responses.write_text(json.dumps(state))
        self.env.update(TEST_RESPONSES=str(self.responses), PYTHONPATH=str(self.bin))
        (self.bin / "gh").write_text(GITHUB)
        (self.bin / "gh").chmod(0o755)
        (self.bin / "sitecustomize.py").write_text(MAVEN)
        return state

    def test_publication_resumes_a_draft_and_only_missing_maven_bytes_after_main_advances(self):
        state = self.publication()
        missing = self.names[2] + ".asc"
        del state["maven"][missing]
        self.responses.write_text(json.dumps(state))
        result = self.run_command("publish")
        self.assertEqual(result.returncode, 0, result.stderr)
        state = json.loads(self.responses.read_text())
        self.assertEqual([write[0] for write in state["writes"] if write[0].startswith("PUT")], ["PUT " + missing])
        self.assertIn(f"assets/10-Roost-v{self.version}.xcframework.zip", state["manifest"])
        self.assertIn(ABC_SHA256, state["manifest"])
        # A further retry must leave every completed destination untouched.
        previous = state["writes"]
        result = self.run_command("publish")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.responses.read_text())["writes"], previous)

    def test_publication_rejects_a_draft_with_another_candidates_description(self):
        state = self.publication()
        state["github"]["GET repos/RelayNet/roost-swift/releases/1"]["body"] = "another candidate's notes"
        self.responses.write_text(json.dumps(state))
        result = self.run_command("publish")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("release description differs", result.stderr)
        self.assertEqual(json.loads(self.responses.read_text())["writes"], [])

    def prepared_run(self, state):
        run = {"id": 103, "run_attempt": 1, "event": "workflow_dispatch", "head_branch": "main",
               "path": ".github/workflows/prepare-mobile.yml", "head_repository": {"full_name": "RelayNet/roost"},
               "status": "completed", "conclusion": "success", "head_sha": self.revision,
               "actor": {"login": "KhaledChehabeddine"}, "triggering_actor": {"login": "KhaledChehabeddine"},
               "display_title": f"Prepare {self.revision} Swift 101 Kotlin 102"}
        state["github"]["GET repos/RelayNet/roost/actions/runs/103"] = run
        state["github"]["GET repos/RelayNet/roost/actions/runs/103/attempts/1"] = run
        state["github"]["GET repos/RelayNet/roost/actions/runs/103/attempts/1/jobs"] = {"jobs": [{"name": "prepare", "conclusion": "success"}]}
        return run

    def test_fetch_rejects_an_unauthorized_rerun_actor(self):
        state = self.publication()
        self.prepared_run(state)["triggering_actor"]["login"] = "another-writer"
        self.responses.write_text(json.dumps(state))
        result = self.run_command("fetch", "--run", "103/1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rerun actors", result.stderr)

    def test_fetch_rejects_a_different_source_revision(self):
        state = self.publication()
        self.prepared_run(state)["head_sha"] = "f" * 40
        state["github"][f"GET repos/RelayNet/roost/compare/{'f' * 40}...main"] = {"status": "ahead"}
        self.responses.write_text(json.dumps(state))
        result = self.run_command("fetch", "--run", "103/1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("different source revision", result.stderr)

    def test_fetch_rejects_substituted_native_checks(self):
        state = self.publication()
        self.prepared_run(state)
        self.env["ROOST_SWIFT_RUN"] = "999"
        self.responses.write_text(json.dumps(state))
        result = self.run_command("fetch", "--run", "103/1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("native candidate runs differ", result.stderr)

    def test_fetch_rejects_a_corrupted_github_archive_before_extraction(self):
        state = self.publication()
        self.prepared_run(state)
        state["github"]["GET repos/RelayNet/roost/actions/runs/103/artifacts?per_page=100"] = {"artifacts": [
            {"id": 9, "name": f"roost-signed-{self.revision}-v{self.version}-1", "expired": False,
             "workflow_run": {"head_sha": self.revision}, "digest": "sha256:" + "0" * 64}]}
        state["github"]["GET repos/RelayNet/roost/actions/artifacts/9/zip"] = {"$raw": base64.b64encode(b"corrupt download").decode()}
        self.responses.write_text(json.dumps(state))
        result = self.run_command("fetch", "--run", "103/1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("GitHub artifact digest mismatch", result.stderr)
        self.assertEqual(list((self.root / "download").iterdir()), [])

    def test_publication_refuses_existing_maven_bytes_that_differ(self):
        state = self.publication()
        state["maven"][self.names[1]] = base64.b64encode(b"another build").decode()
        self.responses.write_text(json.dumps(state))
        result = self.run_command("publish")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Maven bytes differ", result.stderr)
        self.assertEqual(json.loads(self.responses.read_text())["writes"], [])

    def test_publication_refuses_existing_release_bytes_that_differ(self):
        state = self.publication()
        state["github"]["GET repos/RelayNet/roost-swift/releases/assets/10"] = {"$raw": base64.b64encode(b"another build").decode()}
        self.responses.write_text(json.dumps(state))
        result = self.run_command("publish")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("existing release bytes differ", result.stderr)
        self.assertEqual(json.loads(self.responses.read_text())["writes"], [])


class SignatureCommands(unittest.TestCase):
    def test_sign_and_verify_require_the_bytes_pin_and_signer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            keyring = root / "gpg"
            keyring.mkdir(mode=0o700)
            env = {**os.environ, "GNUPGHOME": str(keyring), "ROOST_RELEASE_PASSPHRASE": ""}
            try:
                generated = subprocess.run(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
                                            "--quick-generate-key", "Roost temporary test key", "ed25519", "sign", "0"],
                                           env=env, capture_output=True)
                self.assertEqual(generated.returncode, 0, generated.stderr.decode())
                keys = subprocess.check_output(["gpg", "--with-colons", "--list-keys"], env=env, stderr=subprocess.DEVNULL).decode()
                env["ROOST_RELEASE_FINGERPRINT"] = next(line.split(":")[9] for line in keys.splitlines() if line.startswith("fpr:"))
                artifact = root / "artifact"
                artifact.write_bytes(b"abc")
                subprocess.run([str(ROOT / "scripts/release/sign-artifact.sh"), str(artifact)], env=env, capture_output=True, check=True)
                public_key = root / "key.asc"
                public_key.write_bytes(subprocess.check_output(["gpg", "--armor", "--export"], env=env))
                args = [str(ROOT / "scripts/release/verify-artifact.sh"), str(artifact), str(artifact) + ".asc",
                        str(artifact) + ".sha256", str(public_key), ABC_SHA256]
                self.assertEqual(subprocess.run(args, env=env, capture_output=True).returncode, 0)
                self.assertNotEqual(subprocess.run([*args[:-1], "0" * 64], env=env, capture_output=True).returncode, 0)
                self.assertNotEqual(subprocess.run(args, env={**env, "ROOST_RELEASE_FINGERPRINT": "A" * 40}, capture_output=True).returncode, 0)
                artifact.write_bytes(b"tampered")
                changed_hash = hashlib.sha256(b"tampered").hexdigest()
                (root / "artifact.sha256").write_text(f"{changed_hash}  artifact\n")
                self.assertNotEqual(subprocess.run([*args[:-1], changed_hash], env=env, capture_output=True).returncode, 0)
            finally:
                subprocess.run(["gpgconf", "--kill", "gpg-agent"], env=env, capture_output=True, check=False)


if __name__ == "__main__":
    unittest.main()
