# Writing

Host developers, contributors, and their agents act on this repo's text without the writer there to ask, so a sentence they have to decode leads to wrong code.

These rules cover prose, not names or strings in code. Reread each draft against every section before finishing.

## Content

- Name the mechanism, value, or number, such as "a failed update leaves the earlier updates applied", not "updates are handled safely".
- Cut a sentence that could appear unchanged in another project's docs.
- End a sentence at its claim, not on an "-ing" phrase that adds a second, unsupported one, such as ", ensuring the key stays secret".
- State the point directly, not as "not just X, but Y".
- List items in their real number, not in threes for rhythm.

## Sentences

- Put one idea in each sentence, and split any sentence a reader has to read twice.
- Keep the articles and verbs a sentence needs, and spell out arrows and any abbreviation a reader would have to look up.
- Name the actor, such as "the relay rejects the message", not "the message is rejected", unless the actor is unknown or doesn't matter.
- Hedge once, where the doubt is, such as "may", not "could potentially".

## Words

- Use the plain word, such as "use" for "leverage", "is" for "serves as", "also" for "additionally", and "to" for "in order to".
- Replace an adverb with a stronger verb or a number, such as "takes 4 ms", not "runs quickly".
- Call each thing by one name and repeat it.
- Use the literal word, such as "base" for "substrate" and "returns the key" for "the key rides along", but keep a term with an exact meaning in the field, such as "cryptographic primitive" or "Double Ratchet".

## Punctuation and Formatting

- Separate thoughts with a period or a comma, never an em dash, and give an aside its own sentence instead of parentheses.
- Use a colon to introduce a list or an example, not to join two clauses.
- Bold only what a skimming reader must not miss.
- Start a list item with its content, not a bold label and colon that the rest of the line repeats.
- Leave out decorative emojis.

## Replies

- Start with the answer or the result, then give the reasoning a reader needs to trust it.
- Name the source of a claim, or say how sure you are and what would settle it.
- End when the information ends, without a recap, praise, or an offer to help.

## Example

### ❌ Bad

```rust
/// Serves as the core entry point for decryption, ensuring that messages are robustly validated — the ratchet state is carefully updated.
```

### ✅ Good

```rust
/// Decrypts a message and advances the ratchet.
///
/// A message that fails to authenticate leaves the ratchet unchanged.
```
