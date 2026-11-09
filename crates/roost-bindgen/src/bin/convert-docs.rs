//! Converts the Rust doc comments in a generated UniFFI binding to Swift or Kotlin conventions.

use heck::{ToLowerCamelCase, ToShoutySnakeCase};
use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

const SOURCES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../roost-client/src");

#[derive(Clone, Copy, PartialEq)]
enum Language {
    Swift,
    Kotlin,
}

impl Language {
    fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "swift" => Some(Self::Swift),
            "kotlin" => Some(Self::Kotlin),
            _ => None,
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let [tag, path] = args.as_slice() else {
        return usage();
    };
    let Some(language) = Language::from_tag(tag) else {
        return usage();
    };
    let result = read_sources(Path::new(SOURCES)).and_then(|sources| {
        let binding = fs::read_to_string(path).map_err(|error| error.to_string())?;
        let converted = convert(&binding, language, &sources)?;
        fs::write(path, converted).map_err(|error| error.to_string())
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("convert-docs: {path}: {error}");
            ExitCode::FAILURE
        }
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: convert-docs <swift|kotlin> <binding>");
    ExitCode::FAILURE
}

fn read_sources(dir: &Path) -> Result<String, String> {
    let read_error = |path: &Path, error| format!("{}: {error}", path.display());
    let mut sources = String::new();
    for entry in fs::read_dir(dir).map_err(|error| read_error(dir, error))? {
        let path = entry.map_err(|error| read_error(dir, error))?.path();
        if path.is_dir() {
            sources.push_str(&read_sources(&path)?);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push_str(&fs::read_to_string(&path).map_err(|error| read_error(&path, error))?);
            sources.push('\n');
        }
    }
    Ok(sources)
}

fn convert(binding: &str, language: Language, sources: &str) -> Result<String, String> {
    let examples = doc_blocks(sources);
    let lines = filter_examples_and_links(binding, language, &examples)?;
    let lines = move_errors_to_throws(&lines, language)?;
    let mut converted = drop_extra_blank_lines(lines).join("\n");
    if binding.ends_with('\n') {
        converted.push('\n');
    }
    Ok(converted)
}

fn doc_blocks(sources: &str) -> Vec<Vec<&str>> {
    let mut blocks = Vec::new();
    let mut block: Option<Vec<&str>> = None;
    for line in sources.lines() {
        let Some(text) = line.trim_start().strip_prefix("///") else {
            continue;
        };
        let text = skip_space(text);
        match block.take() {
            Some(lines) if text.starts_with("```") => blocks.push(lines),
            Some(mut lines) => {
                lines.push(text);
                block = Some(lines);
            }
            None if text.starts_with("```") => block = Some(Vec::new()),
            None => {}
        }
    }
    blocks
}

fn filter_examples_and_links(
    binding: &str,
    language: Language,
    examples: &[Vec<&str>],
) -> Result<Vec<String>, String> {
    let mut kept = Vec::new();
    let mut open: Option<bool> = None;
    let mut block: Vec<&str> = Vec::new();
    for line in binding.lines() {
        match (open, fence_tag(line)) {
            (Some(keep), Some(_)) => {
                if keep {
                    let restored = restore_indentation(&block, examples).ok_or_else(|| {
                        let first = block.first().and_then(|line| after_star(line));
                        format!(
                            "doc example not found in the Rust sources: {}",
                            first.unwrap_or_default().trim()
                        )
                    })?;
                    kept.extend(restored);
                    kept.push(line.to_owned());
                }
                open = None;
            }
            (Some(_), None) => block.push(line),
            (None, Some(tag)) => {
                let keep = Language::from_tag(tag).is_none_or(|tag| tag == language);
                if keep {
                    kept.push(line.to_owned());
                }
                open = Some(keep);
                block.clear();
            }
            (None, None) if is_doc_text(line) => {
                kept.push(rewrite_links(&rewrite_code_spans(line), language, binding)?);
            }
            (None, None) => kept.push(line.to_owned()),
        }
    }
    if open.is_some() {
        return Err("unterminated doc example block".to_owned());
    }
    Ok(kept)
}

fn restore_indentation(block: &[&str], examples: &[Vec<&str>]) -> Option<Vec<String>> {
    let matches = |example: &&Vec<&str>| {
        example.len() == block.len()
            && example.iter().zip(block).all(|(source, line)| {
                after_star(line).is_some_and(|text| text.trim() == source.trim())
            })
    };
    let example = examples.iter().find(matches)?;
    let restored = block.iter().zip(example).map(|(line, source)| {
        let prefix = &line[..line.len() - after_star(line).unwrap_or_default().len()];
        let source = source.trim_end();
        if source.is_empty() {
            prefix.to_owned()
        } else {
            format!("{prefix} {source}")
        }
    });
    Some(restored.collect())
}

fn rewrite_code_spans(line: &str) -> String {
    let parts: Vec<&str> = line.split('`').collect();
    let spans = parts.iter().enumerate().map(|(index, part)| {
        let closed = index % 2 == 1 && index + 1 < parts.len();
        if closed && part.split('.').all(is_snake_case) {
            part.split('.')
                .map(ToLowerCamelCase::to_lower_camel_case)
                .collect::<Vec<_>>()
                .join(".")
        } else {
            (*part).to_owned()
        }
    });
    spans.collect::<Vec<_>>().join("`")
}

fn is_snake_case(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn rewrite_links(line: &str, language: Language, binding: &str) -> Result<String, String> {
    let mut rewritten = String::new();
    let mut rest = line;
    while let Some(start) = rest.find("[`") {
        let link = &rest[start + 2..];
        let Some(end) = link
            .find('`')
            .filter(|&end| end > 0 && link[end + 1..].starts_with(']'))
        else {
            rewritten.push_str(&rest[..=start]);
            rest = &rest[start + 1..];
            continue;
        };
        rewritten.push_str(&rest[..start]);
        let mut path = &link[..end];
        rest = &link[end + 2..];
        // A Rust path target, such as `(crate::IdentityContext)`, names the item in place of the
        // text. A URL or other target leaves the text as the name.
        if let Some(target) = rest.strip_prefix('(')
            && let Some(close) = target.find(|c: char| c == ')' || c.is_whitespace())
            && target[close..].starts_with(')')
        {
            let item = &target[..close];
            if item.chars().all(|c| is_word(c) || c == ':') {
                path = item;
            }
            rest = &target[close + 1..];
        }
        rewritten.push_str(&host_name(path, language, binding)?);
    }
    rewritten.push_str(rest);
    Ok(rewritten)
}

fn host_name(path: &str, language: Language, binding: &str) -> Result<String, String> {
    let segments: Vec<&str> = path
        .split("::")
        .filter(|segment| !matches!(*segment, "crate" | "self" | "super" | "Self"))
        .collect();
    let Some((last, parents)) = segments.split_last() else {
        return Err(format!("rustdoc link without an item: {path}"));
    };
    let parent = parents
        .last()
        .filter(|parent| parent.starts_with(char::is_uppercase));
    let member = if last.starts_with(char::is_lowercase) {
        last.to_lower_camel_case()
    } else if let Some(parent) = parent {
        host_variant(parent, last, language, binding)
    } else {
        host_type(last, language, binding)
    };
    let name = match parent {
        Some(parent) => format!("{}.{member}", host_type(parent, language, binding)),
        None => member,
    };
    // KDoc resolves [Name] links. DocC needs full symbol signatures, so Swift gets code voice.
    Ok(match language {
        Language::Swift => format!("`{name}`"),
        Language::Kotlin => format!("[{name}]"),
    })
}

fn host_type(name: &str, language: Language, binding: &str) -> String {
    // UniFFI names Kotlin error types and variants `*Exception`.
    if language == Language::Kotlin
        && let Some(stem) = name.strip_suffix("Error")
    {
        let exception = format!("{stem}Exception");
        if binding.contains(&format!("class {exception}")) {
            return exception;
        }
    }
    name.to_owned()
}

fn host_variant(parent: &str, variant: &str, language: Language, binding: &str) -> String {
    match language {
        // UniFFI writes an error's Swift cases in upper camel case, as Rust names them, and every
        // other enum's in lower camel case.
        Language::Swift if binding.contains(&format!("enum {parent}: Swift.Error")) => {
            variant.to_owned()
        }
        Language::Swift => variant.to_lower_camel_case(),
        // UniFFI writes an enum without fields as a Kotlin enum class with upper snake case
        // entries.
        Language::Kotlin
            if binding.contains(&format!("enum class {parent} "))
                || binding.contains(&format!("enum class {parent}(")) =>
        {
            variant.to_shouty_snake_case()
        }
        Language::Kotlin => host_type(variant, language, binding),
    }
}

fn move_errors_to_throws(lines: &[String], language: Language) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    let mut pending = None;
    let mut i = 0;
    while i < lines.len() {
        let line = &lines[i];
        if let Some(prefix) = errors_heading(line) {
            i += 1;
            let mut bullets = Vec::new();
            while let Some(first) = lines.get(i).and_then(|line| bullet(line)) {
                let mut bullet = vec![first];
                i += 1;
                while let Some(text) = lines.get(i).and_then(|line| continuation(line)) {
                    bullet.push(text);
                    i += 1;
                }
                bullets.push(bullet);
            }
            pending = Some((prefix, bullets));
            continue;
        }
        if is_comment_end(line)
            && let Some((prefix, bullets)) = pending.take()
        {
            if out.last().is_some_and(|last| !is_blank(last)) {
                out.push(prefix.to_owned());
            }
            out.extend(throws_lines(prefix, &bullets, language)?);
        }
        out.push(line.clone());
        i += 1;
    }
    if pending.is_some() {
        return Err("# Errors section outside a doc comment".to_owned());
    }
    Ok(out)
}

fn throws_lines(
    prefix: &str,
    bullets: &[Vec<&str>],
    language: Language,
) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    match language {
        Language::Swift => {
            lines.push(format!("{prefix} - Throws:"));
            for bullet in bullets {
                for (index, text) in bullet.iter().enumerate() {
                    let marker = if index == 0 { "- " } else { "  " };
                    lines.push(format!("{prefix}   {marker}{text}"));
                }
            }
        }
        Language::Kotlin => {
            for bullet in bullets {
                // A bullet's list of errors can wrap, so parse the whole bullet as one line.
                let text = bullet.join(" ");
                let Some((names, condition)) = error_names(&text) else {
                    return Err(format!("# Errors bullet without an error name: {text}"));
                };
                for name in names {
                    lines.push(
                        format!("{prefix} @throws {name} {condition}")
                            .trim_end()
                            .to_owned(),
                    );
                }
            }
        }
    }
    Ok(lines)
}

fn error_names(text: &str) -> Option<(Vec<&str>, &str)> {
    let (first, mut rest) = leading_name(text)?;
    let mut names = vec![first];
    while let Some((name, after)) = rest
        .trim_start()
        .strip_prefix("or")
        .and_then(|rest| leading_name(rest.trim_start()))
    {
        names.push(name);
        rest = after;
    }
    Some((names, rest.trim_start()))
}

fn leading_name(text: &str) -> Option<(&str, &str)> {
    let (name, rest) = text.strip_prefix('[')?.split_once(']')?;
    let valid = !name.is_empty() && name.chars().all(|c| is_word(c) || c == '.');
    valid.then_some((name, rest))
}

fn drop_extra_blank_lines(lines: Vec<String>) -> Vec<String> {
    let mut kept: Vec<String> = Vec::new();
    for line in lines {
        if (is_blank(&line) || is_comment_end(&line))
            && kept.last().is_some_and(|last| is_blank(last))
        {
            kept.pop();
        }
        kept.push(line);
    }
    kept
}

fn after_star(line: &str) -> Option<&str> {
    line.trim_start().strip_prefix('*')
}

fn skip_space(text: &str) -> &str {
    text.strip_prefix(char::is_whitespace).unwrap_or(text)
}

fn is_doc_text(line: &str) -> bool {
    after_star(line).is_some_and(|text| text.is_empty() || text.starts_with(char::is_whitespace))
}

fn is_blank(line: &str) -> bool {
    after_star(line).is_some_and(|text| text.trim().is_empty())
}

fn is_comment_end(line: &str) -> bool {
    after_star(line).is_some_and(|text| text.starts_with('/'))
}

fn fence_tag(line: &str) -> Option<&str> {
    skip_space(after_star(line)?).strip_prefix("```")
}

fn errors_heading(line: &str) -> Option<&str> {
    let text = after_star(line)?;
    (skip_space(text).trim_end() == "# Errors").then(|| &line[..line.len() - text.len()])
}

fn bullet(line: &str) -> Option<&str> {
    skip_space(after_star(line)?).strip_prefix("- ")
}

// UniFFI strips indentation, so a wrapped bullet continues on any following non-blank line that
// doesn't start a new bullet, heading, or code fence.
fn continuation(line: &str) -> Option<&str> {
    let after = after_star(line)?;
    let text = after.trim_start();
    let continues = text.len() < after.len()
        && !text.is_empty()
        && !text.starts_with("- ")
        && !text.starts_with('#')
        && !text.starts_with("```");
    continues.then_some(text)
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(lines: &[&str]) -> String {
        lines.join("\n") + "\n"
    }

    fn rust_docs(lines: &[&str]) -> String {
        lines.iter().map(|line| format!("/// {line}\n")).collect()
    }

    #[test]
    fn keeps_only_the_host_languages_examples() {
        let sources = rust_docs(&[
            "```swift",
            "let operations = try context.unfinishedOperations()",
            "```",
            "```kotlin",
            "val operations = context.unfinishedOperations()",
            "```",
        ]);
        let binding = text(&[
            "/**",
            " * Lists unfinished operations.",
            " *",
            " * ```swift",
            " * let operations = try context.unfinishedOperations()",
            " * ```",
            " *",
            " * ```kotlin",
            " * val operations = context.unfinishedOperations()",
            " * ```",
            " */",
        ]);
        let swift = text(&[
            "/**",
            " * Lists unfinished operations.",
            " *",
            " * ```swift",
            " * let operations = try context.unfinishedOperations()",
            " * ```",
            " */",
        ]);
        let kotlin = text(&[
            "/**",
            " * Lists unfinished operations.",
            " *",
            " * ```kotlin",
            " * val operations = context.unfinishedOperations()",
            " * ```",
            " */",
        ]);
        assert_eq!(convert(&binding, Language::Swift, &sources).unwrap(), swift);
        assert_eq!(
            convert(&binding, Language::Kotlin, &sources).unwrap(),
            kotlin
        );
    }

    #[test]
    fn restores_example_indentation_from_the_sources() {
        let sources = text(&[
            "    /// ```swift",
            "    /// if done {",
            "    ///     stop()",
            "    ///",
            "    ///     log()",
            "    /// }",
            "    /// ```",
            "    /// Sends when ready.",
            "    ///",
            "    /// ```swift",
            "    /// if ready {",
            "    ///     send()",
            "    ///",
            "    ///     log()",
            "    /// }",
            "    /// ```",
        ]);
        let binding = text(&[
            "/**",
            " * ```swift",
            " * if ready {",
            " * send()",
            " *",
            " * log()",
            " * }",
            " * ```",
            " */",
        ]);
        let swift = text(&[
            "/**",
            " * ```swift",
            " * if ready {",
            " *     send()",
            " *",
            " *     log()",
            " * }",
            " * ```",
            " */",
        ]);
        assert_eq!(convert(&binding, Language::Swift, &sources).unwrap(), swift);
    }

    #[test]
    fn rewrites_links_to_swift_names() {
        let binding = text(&[
            "    /**",
            "     * Fails with [`RoostError::InvalidData`] after [`Self::reserve_operation`] in an",
            "     * [`IdentityContext`](crate::IdentityContext) that returned",
            "     * [`MessageEncryptionStep::NeedsState`] or",
            "     * [`NeedsPreKeyBundle`](crate::MessageEncryptionStep::NeedsPreKeyBundle), as in",
            "     * [`RFC 9180`](https://www.rfc-editor.org/rfc/rfc9180).",
            "     */",
            "enum RoostError: Swift.Error {",
        ]);
        let swift = text(&[
            "    /**",
            "     * Fails with `RoostError.InvalidData` after `reserveOperation` in an",
            "     * `IdentityContext` that returned",
            "     * `MessageEncryptionStep.needsState` or",
            "     * `MessageEncryptionStep.needsPreKeyBundle`, as in",
            "     * `RFC 9180`.",
            "     */",
            "enum RoostError: Swift.Error {",
        ]);
        assert_eq!(convert(&binding, Language::Swift, "").unwrap(), swift);
    }

    #[test]
    fn rewrites_links_to_kotlin_names_outside_code() {
        let sources = rust_docs(&["```kotlin", "// [`RoostError::InvalidData`]", "```"]);
        let binding = text(&[
            "/**",
            " * Fails with [`RoostError::InvalidData`] after [`Self::reserve_operation`].",
            " * Returns [`ProtocolStateKind::ContactState`] or [`MessageEncryptionStep::NeedsState`].",
            " * Reads [`PayloadKind::ContentWithGrant`].",
            " *",
            " * ```kotlin",
            " * // [`RoostError::InvalidData`]",
            " * ```",
            " */",
            "sealed class RoostException",
            "enum class ProtocolStateKind {",
            "enum class PayloadKind(val value: UByte) {",
        ]);
        let kotlin = text(&[
            "/**",
            " * Fails with [RoostException.InvalidData] after [reserveOperation].",
            " * Returns [ProtocolStateKind.CONTACT_STATE] or [MessageEncryptionStep.NeedsState].",
            " * Reads [PayloadKind.CONTENT_WITH_GRANT].",
            " *",
            " * ```kotlin",
            " * // [`RoostError::InvalidData`]",
            " * ```",
            " */",
            "sealed class RoostException",
            "enum class ProtocolStateKind {",
            "enum class PayloadKind(val value: UByte) {",
        ]);
        assert_eq!(
            convert(&binding, Language::Kotlin, &sources).unwrap(),
            kotlin
        );
    }

    #[test]
    fn rewrites_snake_case_code_spans_outside_examples() {
        let sources = rust_docs(&["```swift", "// `identity_key`", "```"]);
        let binding = text(&[
            "/**",
            " * Pass `identity_key` and `admission.signed_prekey_id`, not `Self`, `ID_KEY`, or `30_000`.",
            " * A span that wraps, such as `stored_key",
            " * name`, stays.",
            " *",
            " * ```swift",
            " * // `identity_key`",
            " * ```",
            " */",
            "// Passes the bytes to `ffi_bytebuffer_from_bytes`.",
        ]);
        let swift = text(&[
            "/**",
            " * Pass `identityKey` and `admission.signedPrekeyId`, not `Self`, `ID_KEY`, or `30_000`.",
            " * A span that wraps, such as `stored_key",
            " * name`, stays.",
            " *",
            " * ```swift",
            " * // `identity_key`",
            " * ```",
            " */",
            "// Passes the bytes to `ffi_bytebuffer_from_bytes`.",
        ]);
        assert_eq!(convert(&binding, Language::Swift, &sources).unwrap(), swift);
    }

    #[test]
    fn turns_errors_into_swift_throws_with_wrapped_bullets() {
        let binding = text(&[
            "    /**",
            "     * Validates a sender certificate.",
            "     *",
            "     * # Errors",
            "     * - [`RoostError::CertificateRejected`] if the certificate is expired, revoked, untrusted, or",
            "     * signed for another relay domain.",
            "     * - [`RoostError::InvalidData`] if a key or the reference time is malformed.",
            "     */",
            "enum RoostError: Swift.Error {",
        ]);
        let swift = text(&[
            "    /**",
            "     * Validates a sender certificate.",
            "     *",
            "     * - Throws:",
            "     *   - `RoostError.CertificateRejected` if the certificate is expired, revoked, untrusted, or",
            "     *     signed for another relay domain.",
            "     *   - `RoostError.InvalidData` if a key or the reference time is malformed.",
            "     */",
            "enum RoostError: Swift.Error {",
        ]);
        assert_eq!(convert(&binding, Language::Swift, "").unwrap(), swift);
    }

    #[test]
    fn turns_errors_into_kotlin_throws_per_error_name() {
        let binding = text(&[
            "    /**",
            "     * Restores a backup.",
            "     *",
            "     * # Errors",
            "     * - [`RoostError::DecryptionFailed`] if the passphrase is wrong or the backup was altered.",
            "     * - [`RoostError::InvalidData`] or [`RoostError::UnsupportedVersion`] if the backup is",
            "     * malformed.",
            "     */",
            "sealed class RoostException",
        ]);
        let kotlin = text(&[
            "    /**",
            "     * Restores a backup.",
            "     *",
            "     * @throws RoostException.DecryptionFailed if the passphrase is wrong or the backup was altered.",
            "     * @throws RoostException.InvalidData if the backup is malformed.",
            "     * @throws RoostException.UnsupportedVersion if the backup is malformed.",
            "     */",
            "sealed class RoostException",
        ]);
        assert_eq!(convert(&binding, Language::Kotlin, "").unwrap(), kotlin);
    }

    #[test]
    fn moves_errors_to_the_end_of_the_comment() {
        let binding = text(&[
            "/**",
            " * Accepts a contact.",
            " *",
            " * # Errors",
            " * - [`RoostError::InvalidData`] if the key is malformed.",
            " *",
            " * Call it once per contact.",
            " */",
            "enum RoostError: Swift.Error {",
        ]);
        let swift = text(&[
            "/**",
            " * Accepts a contact.",
            " *",
            " * Call it once per contact.",
            " *",
            " * - Throws:",
            " *   - `RoostError.InvalidData` if the key is malformed.",
            " */",
            "enum RoostError: Swift.Error {",
        ]);
        assert_eq!(convert(&binding, Language::Swift, "").unwrap(), swift);
    }

    #[test]
    fn rejects_an_unterminated_example_block() {
        let binding = text(&["/**", " * ```swift", " * let a = 1", " */"]);
        let unterminated = Err("unterminated doc example block".to_owned());
        assert_eq!(convert(&binding, Language::Swift, ""), unterminated);
        assert_eq!(convert(&binding, Language::Kotlin, ""), unterminated);
    }

    #[test]
    fn rejects_a_kotlin_errors_bullet_without_an_error_name() {
        let binding = text(&["/**", " * # Errors", " * - When storage fails.", " */"]);
        assert_eq!(
            convert(&binding, Language::Kotlin, ""),
            Err("# Errors bullet without an error name: When storage fails.".to_owned())
        );
    }
}
