# Writing

These rules don't apply to names or string literals in code. Where another skill or document sets a format or a length, follow it.

## Content

- Cut any point the reader doesn't need, such as "This change follows best practices" or a closing "ensuring security".
- Say exactly what happens, such as "a failed update leaves the earlier updates applied", not "updates are handled safely".
- State a point directly, such as "it also authenticates Messages", not "it doesn't just encrypt Messages, it authenticates them".
- Give a reason in agent instructions only when it changes what the agent does.
- Comment only to prevent a reader's mistake, except for the documentation comments that `missing_docs` or the Rust skill asks for.

## Sentences

- Put one idea in each sentence.
- Keep the articles and verbs a sentence needs, such as "the test is failing", not "test failing".
- Prefer the active voice, such as "the Relay rejects the Message", not "the Message is rejected".
- Use the plain word, such as "is", not "serves as".
- Connect ideas with words, not symbols, such as "then" in place of "→".
- Spell out abbreviations, except standard terms such as "AEAD".
- Use American spelling.

## Punctuation and Formatting

- Separate thoughts with a period or a comma, not a dash or a semicolon.
- Use parentheses only for a citation, such as "(ADR 0050)", or to define an abbreviation, such as "Identity Key (IK)".
- Use a colon to introduce a list or an example, not to join two clauses.
- Write headings in Title Case, such as "Punctuation and Formatting".
- Bold only what a skimming reader must not miss.
