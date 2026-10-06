//! Adapts the Rust doc comments in a generated UniFFI binding to its host language.
//!
//! UniFFI copies Rust doc comments into Swift and Kotlin unchanged. For the given language this:
//!
//! - keeps only that language's `swift` or `kotlin` example blocks;
//! - rewrites rustdoc links to the names the binding exposes: ``[`RoostError::InvalidData`]``
//!   becomes `` `RoostError.InvalidData` `` in Swift and `[RoostException.InvalidData]` in Kotlin,
//!   and ``[`Self::reserve_operation`]`` becomes `reserveOperation`;
//! - turns a `# Errors` section into Swift's `- Throws:` field or Kotlin's `@throws` tags at the end
//!   of the comment.
//!
//! Usage: `host-docs <swift|kotlin> <binding>` rewrites the binding in place.

use std::env;
use std::fs;
use std::process::ExitCode;

/// A binding's host language, tagged as in a doc example's code fence.
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
    let result = fs::read_to_string(path)
        .map_err(|error| error.to_string())
        .and_then(|binding| adapt(&binding, language))
        .and_then(|adapted| fs::write(path, adapted).map_err(|error| error.to_string()));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("host-docs: {path}: {error}");
            ExitCode::FAILURE
        }
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: host-docs <swift|kotlin> <binding>");
    ExitCode::FAILURE
}

fn adapt(binding: &str, language: Language) -> Result<String, String> {
    let lines = filter_examples_and_links(binding, language)?;
    let mut adapted = move_errors_to_throws(&lines, language)?.join("\n");
    if binding.ends_with('\n') {
        adapted.push('\n');
    }
    Ok(adapted)
}

fn filter_examples_and_links(binding: &str, language: Language) -> Result<Vec<String>, String> {
    let mut kept: Vec<String> = Vec::new();
    let mut skipping = false;
    let mut in_block = false;
    let mut skipped_block = false;
    for line in binding.lines() {
        let fence = fence_tag(line);
        if skipping {
            skipping = fence.is_none();
            continue;
        }
        if fence
            .and_then(Language::from_tag)
            .is_some_and(|tag| tag != language)
        {
            skipping = true;
            skipped_block = true;
            continue;
        }
        // Removing a block between two blank doc lines would leave them adjacent.
        if skipped_block && is_blank(line) && kept.last().is_some_and(|last| is_blank(last)) {
            skipped_block = false;
            continue;
        }
        skipped_block = false;
        if fence.is_some() {
            in_block = !in_block;
        } else if is_doc_text(line) && !in_block {
            kept.push(rewrite_links(line, language, binding)?);
            continue;
        }
        kept.push(line.to_owned());
    }
    if skipping || in_block {
        return Err("unterminated doc example block".to_owned());
    }
    Ok(kept)
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
        rewritten.push_str(&host_name(&link[..end], language, binding)?);
        rest = &link[end + 2..];
        // Drop a link target, such as `(crate::IdentityContext)`.
        if let Some(target) = rest.strip_prefix('(')
            && let Some(close) = target.find(|c: char| c == ')' || c.is_whitespace())
            && target[close..].starts_with(')')
        {
            rest = &target[close + 1..];
        }
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
    let mut name = if last.starts_with(char::is_lowercase) {
        lower_camel(last)
    } else {
        host_type(last, language, binding)
    };
    if let Some(parent) = parents
        .last()
        .filter(|parent| parent.starts_with(char::is_uppercase))
    {
        name = format!("{}.{name}", host_type(parent, language, binding));
    }
    // KDoc resolves [Name] links; Swift symbol links need full DocC signatures, so use code voice.
    Ok(match language {
        Language::Swift => format!("`{name}`"),
        Language::Kotlin => format!("[{name}]"),
    })
}

fn lower_camel(name: &str) -> String {
    let mut words = name.split('_');
    let mut camel = words.next().unwrap_or_default().to_owned();
    for word in words {
        let mut chars = word.chars();
        if let Some(first) = chars.next() {
            camel.extend(first.to_uppercase());
            camel.push_str(chars.as_str());
        }
    }
    camel
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

fn move_errors_to_throws(lines: &[String], language: Language) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    let mut pending = None;
    let mut i = 0;
    while i < lines.len() {
        let line = &lines[i];
        if let Some(prefix) = errors_heading(line) {
            i += 1;
            // Rustdoc style often puts a blank line between the heading and its bullets.
            while lines.get(i).is_some_and(|line| is_blank(line)) {
                i += 1;
            }
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
            if bullets.is_empty() {
                return Err("# Errors section without bullets".to_owned());
            }
            // Drop the blank line that separated the section, keeping one between neighbors.
            let section_ends = lines
                .get(i)
                .is_none_or(|next| is_blank(next) || is_comment_end(next));
            if section_ends && out.last().is_some_and(|last| is_blank(last)) {
                out.pop();
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

/// Splits a Kotlin bullet such as `[A] or [B] if …` into its error names and its condition.
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

// A comment line looks like `     * text`. These helpers read the text after its `*`.

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

/// Returns a code fence's language tag, which is empty for a closing fence.
fn fence_tag(line: &str) -> Option<&str> {
    let fence = skip_space(after_star(line)?).strip_prefix("```")?;
    let end = fence.find(|c: char| !is_word(c)).unwrap_or(fence.len());
    fence[end..].trim().is_empty().then(|| &fence[..end])
}

/// Returns the `     *` that starts an `# Errors` heading.
fn errors_heading(line: &str) -> Option<&str> {
    let text = after_star(line)?;
    (skip_space(text).trim_end() == "# Errors").then(|| &line[..line.len() - text.len()])
}

fn bullet(line: &str) -> Option<&str> {
    skip_space(after_star(line)?).strip_prefix("- ")
}

/// Returns the text of a line that continues the bullet above it.
///
/// UniFFI strips indentation, so a wrapped bullet continues on any following non-blank line that
/// doesn't start a new bullet, heading, or code fence.
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

    #[test]
    fn keeps_only_the_host_languages_examples() {
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
            " *",
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
        assert_eq!(adapt(&binding, Language::Swift).unwrap(), swift);
        assert_eq!(adapt(&binding, Language::Kotlin).unwrap(), kotlin);
    }

    #[test]
    fn rewrites_links_to_swift_names() {
        let binding = text(&[
            "    /**",
            "     * Fails with [`RoostError::InvalidData`] after [`Self::reserve_operation`] in an",
            "     * [`IdentityContext`](crate::IdentityContext).",
            "     */",
        ]);
        let swift = text(&[
            "    /**",
            "     * Fails with `RoostError.InvalidData` after `reserveOperation` in an",
            "     * `IdentityContext`.",
            "     */",
        ]);
        assert_eq!(adapt(&binding, Language::Swift).unwrap(), swift);
    }

    #[test]
    fn rewrites_links_to_kotlin_names_outside_code() {
        let binding = text(&[
            "/**",
            " * Fails with [`RoostError::InvalidData`] after [`Self::reserve_operation`].",
            " *",
            " * ```kotlin",
            " * // [`RoostError::InvalidData`]",
            " * ```",
            " */",
            "sealed class RoostException",
        ]);
        let kotlin = text(&[
            "/**",
            " * Fails with [RoostException.InvalidData] after [reserveOperation].",
            " *",
            " * ```kotlin",
            " * // [`RoostError::InvalidData`]",
            " * ```",
            " */",
            "sealed class RoostException",
        ]);
        assert_eq!(adapt(&binding, Language::Kotlin).unwrap(), kotlin);
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
        ]);
        assert_eq!(adapt(&binding, Language::Swift).unwrap(), swift);
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
        assert_eq!(adapt(&binding, Language::Kotlin).unwrap(), kotlin);
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
        ]);
        assert_eq!(adapt(&binding, Language::Swift).unwrap(), swift);
    }

    #[test]
    fn rejects_an_unterminated_example_block() {
        let binding = text(&["/**", " * ```swift", " * let a = 1", " */"]);
        assert!(adapt(&binding, Language::Swift).is_err());
        assert!(adapt(&binding, Language::Kotlin).is_err());
    }

    #[test]
    fn rejects_an_errors_section_without_bullets() {
        let binding = text(&[
            "/**",
            " * # Errors",
            " *",
            " * Fails when storage fails.",
            " */",
        ]);
        assert!(adapt(&binding, Language::Swift).is_err());
    }

    #[test]
    fn rejects_a_kotlin_errors_bullet_without_an_error_name() {
        let binding = text(&["/**", " * # Errors", " * - When storage fails.", " */"]);
        assert!(adapt(&binding, Language::Kotlin).is_err());
    }
}
