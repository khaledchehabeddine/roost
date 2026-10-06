#!/usr/bin/env python3
"""Adapt Rust doc comments in a generated UniFFI binding for one host platform.

UniFFI copies Rust doc comments into Swift and Kotlin unchanged. For the given platform this:

- keeps only that platform's `swift` or `kotlin` example blocks;
- rewrites rustdoc links to the names the binding exposes: [`RoostError::InvalidData`] becomes
  `RoostError.InvalidData` in Swift and [RoostException.InvalidData] in Kotlin, and
  [`Self::reserve_operation`] becomes `reserveOperation`;
- turns a `# Errors` section into Swift's `- Throws:` field or Kotlin's `@throws` tags at the end of
  the comment.
"""

import argparse
from pathlib import Path
import re


PLATFORMS = ("swift", "kotlin")
DOC_LINE = re.compile(r"^(\s*\*)(\s|$)")
FENCE = re.compile(r"^\s*\*\s?```(\w*)\s*$")
BLANK_DOC_LINE = re.compile(r"^\s*\*\s*$")
COMMENT_END = re.compile(r"^\s*\*/")
ERRORS_HEADING = re.compile(r"^(\s*\*)\s?# Errors\s*$")
BULLET = re.compile(r"^\s*\*\s?- (.*)$")
# UniFFI strips indentation, so a wrapped bullet continues on any following non-blank line that
# doesn't start a new bullet, heading, or fence (Markdown's lazy continuation).
CONTINUATION = re.compile(r"^\s*\*\s+(?!- |#|```)(\S.*)$")
LINK = re.compile(r"\[`([^`]+)`\](?:\([^)\s]*\))?")
HOST_NAME = r"(?:\[[\w.]+\]|`[\w.]+`)"
ERROR_NAMES = re.compile(rf"^({HOST_NAME}(?:\s*(?:\||,|or)\s*{HOST_NAME})*)\s*(.*)$", re.DOTALL)
PATH_PREFIXES = ("crate", "self", "super", "Self")


def lower_camel(name):
    first, *rest = name.split("_")
    return first + "".join(word[:1].upper() + word[1:] for word in rest)


def host_type(name, platform, binding):
    # UniFFI names Kotlin error types and variants `*Exception`.
    if platform == "kotlin" and name.endswith("Error"):
        exception = name.removesuffix("Error") + "Exception"
        if f"class {exception}" in binding:
            return exception
    return name


def host_name(path, platform, binding):
    segments = [segment for segment in path.split("::") if segment not in PATH_PREFIXES]
    name = segments[-1]
    if name[:1].islower():
        name = lower_camel(name)
    else:
        name = host_type(name, platform, binding)
    if len(segments) > 1 and segments[-2][:1].isupper():
        name = f"{host_type(segments[-2], platform, binding)}.{name}"
    # KDoc resolves [Name] links; Swift symbol links need full DocC signatures, so use code voice.
    return f"[{name}]" if platform == "kotlin" else f"`{name}`"


def filter_examples_and_links(lines, platform, binding):
    kept = []
    skipping = False
    in_block = False
    skipped_block = False
    for line in lines:
        fence = FENCE.match(line)
        if skipping:
            skipping = not fence
            continue
        if fence and fence.group(1) in PLATFORMS and fence.group(1) != platform:
            skipping = True
            skipped_block = True
            continue
        # Removing a block between two blank doc lines would leave them adjacent.
        if skipped_block and BLANK_DOC_LINE.match(line) and kept and BLANK_DOC_LINE.match(kept[-1]):
            skipped_block = False
            continue
        skipped_block = False
        if fence:
            in_block = not in_block
        elif DOC_LINE.match(line) and not in_block:
            line = LINK.sub(lambda link: host_name(link.group(1), platform, binding), line)
        kept.append(line)
    if skipping or in_block:
        raise ValueError("unterminated doc example block")
    return kept


def throws_lines(prefix, errors, platform):
    newline = "\n"
    if platform == "swift":
        lines = [f"{prefix} - Throws:{newline}"]
        for first, rest in errors:
            lines.append(f"{prefix}   - {first}{newline}")
            lines.extend(f"{prefix}     {text}{newline}" for text in rest)
        return lines
    lines = []
    for first, rest in errors:
        # A bullet's list of errors can wrap, so parse the whole bullet as one line.
        text = " ".join([first, *rest])
        names = ERROR_NAMES.match(text)
        if names:
            condition = names.group(2)
            exceptions = [name.strip("[]`") for name in re.findall(HOST_NAME, names.group(1))]
        else:
            condition, exceptions = text, ["RoostException"]
        lines.extend(f"{prefix} @throws {exception} {condition}".rstrip() + newline for exception in exceptions)
    return lines


def move_errors_to_throws(lines, platform):
    out = []
    pending = None
    i = 0
    while i < len(lines):
        line = lines[i]
        heading = ERRORS_HEADING.match(line)
        if heading:
            prefix = heading.group(1)
            errors = []
            i += 1
            # Rustdoc style often puts a blank line between the heading and its bullets.
            while i < len(lines) and BLANK_DOC_LINE.match(lines[i]):
                i += 1
            while i < len(lines) and (bullet := BULLET.match(lines[i])):
                rest = []
                i += 1
                while i < len(lines) and (continuation := CONTINUATION.match(lines[i])):
                    rest.append(continuation.group(1))
                    i += 1
                errors.append((bullet.group(1), rest))
            if not errors:
                raise ValueError("# Errors section without bullets")
            # Drop the blank line that separated the section, keeping one between neighbors.
            if out and BLANK_DOC_LINE.match(out[-1]) and (i >= len(lines) or BLANK_DOC_LINE.match(lines[i]) or COMMENT_END.match(lines[i])):
                out.pop()
            pending = (prefix, errors)
            continue
        if pending and COMMENT_END.match(line):
            prefix, errors = pending
            if out and not BLANK_DOC_LINE.match(out[-1]):
                out.append(f"{prefix}\n")
            out.extend(throws_lines(prefix, errors, platform))
            pending = None
        out.append(line)
        i += 1
    if pending:
        raise ValueError("# Errors section outside a doc comment")
    return out


def adapt(binding, platform):
    lines = filter_examples_and_links(binding.splitlines(keepends=True), platform, binding)
    return "".join(move_errors_to_throws(lines, platform))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("platform", choices=PLATFORMS)
    parser.add_argument("binding", type=Path)
    args = parser.parse_args()
    args.binding.write_text(adapt(args.binding.read_text(), args.platform))


if __name__ == "__main__":
    main()
