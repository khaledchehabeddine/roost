# Documentation

## Host API

UniFFI-exported items in `roost-client`. UniFFI copies their doc comments into the generated Swift and Kotlin, so write for a mobile developer who knows neither Rust nor the protocol. Docs are extra help for using Roost well; keep them short.

- Make each item's doc self-contained; readers hover one symbol at a time.
- Start with one plain-text sentence, without links, saying what the item does for the host: a third-person verb for functions ("Returns", "Prepares"), a noun phrase for types. Swift shows it as the summary.
- Then state what the signature can't show: what to persist, in what order, what to call next, and which checks stay the host's job. Skip this when there is nothing.
- Under `# Errors`, list the errors a host can act on and when they happen. Document failures a host can only report, like `InternalError`, once on that `ClientError` variant. [`host_docs.py`](../../../../../scripts/build/host_docs.py) turns the section into Swift's `- Throws:` and Kotlin's `@throws`.
- Leave out requirement IDs, protocol shorthand, wire formats, and Rust-only types.
- Refer to items with rustdoc links, such as [`ClientError::InvalidData`] or [`Self::commit_operation`]. `host_docs.py` rewrites them to each platform's names.
- Add an example only when usage isn't clear without one, usually a multi-step flow. Write one `swift` and one `kotlin` block, never Rust; `host_docs.py` keeps the matching block in each binding.
- Put the orientation on `Client`: what Roost does versus what the host owns, where each flow starts, and one example of the prepared-operation sequence. Each `prepare…` method still states the steps in one sentence.

## Rust Internals

Everything else, written for Roost contributors.

- Start with one sentence: a third-person verb for functions ("Returns", "Derives"), a noun phrase for types.
- Then state what the signature and types can't show: invariants, ordering, security assumptions, and why a surprising choice was made. Skip this when there is nothing.
- Keep claims about atomicity, rollback, and partial failure exactly true, and state limitations rather than leaving them out.
- Don't write `# Errors` sections. A function's error type lists only the failures it can return, and each variant documents when it happens.
- Add an example only when usage isn't clear without one, usually a multi-step flow. Document a flow shared by several methods once, on their type.
- Give a source module `//!` docs only when its file name doesn't explain its purpose.
- Open each crate's `//!` docs with a one-sentence summary and a short scope paragraph: what the crate is responsible for, and what it leaves to other crates where a contributor might expect otherwise. List feature flags. Don't add a quick-start example unless the crate is published.
- Keep `compile_fail` blocks that stop secret types from gaining `Debug` or `Clone`.
