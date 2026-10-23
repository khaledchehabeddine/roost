# Writing

Host developers read Roost's doc comments in Swift and Kotlin without the Rust code, and agents read the repo's docs as context, so neither can ask the writer what a sentence meant.

Follow these rules in everything a person reads, including replies, and reread the draft against each section before finishing.

## Say What It Does

- Name the mechanism, value, or number, such as "a failed update leaves the earlier updates applied", not "updates are handled safely".
- Cut a sentence that could appear unchanged in another project's docs.
- End a sentence at its claim, not on an "-ing" phrase that adds a second, unsupported one, such as ", ensuring the key stays secret".
- Name what supports a claim, such as a spec or a measurement, instead of "experts say" or "it's generally recommended".
- State the point directly, not as "not just X, but Y".
- List items in their real number, not in threes for rhythm.

## Sentences

- Put one idea in each sentence, and split any sentence a reader has to read twice.
- Write whole sentences with their articles and verbs, and spell out arrows and any abbreviation a reader would have to look up.
- Name the actor, such as "the relay rejects the message", not "the message is rejected", unless the actor is unknown or doesn't matter.
- Replace an adverb with a stronger verb or a number, such as "takes 4 ms", not "runs quickly".
- Hedge once, where the doubt is, such as "may", not "could potentially".

## Words

- Use the plain word, such as "use" for "leverage", "is" for "serves as", "also" for "additionally", "important" for "crucial", and "to" for "in order to".
- Call each thing by one name and repeat it, using the [glossary](../../../../GLOSSARY.md) term for a domain concept.
- Use the literal word for a metaphor, such as "base" for "substrate", "add" for "wedge in", and "way" for "vector", but keep a term with an exact meaning in the field, such as "cryptographic primitive", "Double Ratchet", or "test harness".
- Describe code literally, such as "the function returns the key", not "the key rides along".

## Punctuation and Formatting

- Separate thoughts with a period or a comma, never an em dash, and give an aside its own sentence instead of parentheses.
- Use a colon only before a list or an example.
- Bold only what a skimming reader must not miss.
- Start a list item with its content, not a bold label and colon that the rest of the line repeats.
- Leave out decorative emojis, but keep ✅ and ❌ as labels on good and bad examples.

## Replies

- Start with the answer or the result, then give the reasoning a reader needs to trust it.
- Say how sure you are of a claim you didn't check, and what would settle it.
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
