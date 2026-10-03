# Domain Modeling

The glossary sets one name per concept and ADRs record why a decision was made.

## Glossary

Follow the [template](templates/glossary.md) when editing `GLOSSARY.md`.

- Check a new or changed term against the glossary and the code, and ask when its meaning is unclear.
- Add a term only when this project gives it a meaning of its own.
- Define it by what it is, in one or two sentences.
- List other words people use for it, if any, as words to avoid.
- Keep terms in alphabetical order.
- Remove a term when this project stops using it.
- Leave out code details, such as limits, encodings, type names, and file paths.

## ADRs

Follow the [template](templates/adr.md) when writing an ADR in `docs/adr/`.

- Write an ADR only when a decision is costly to reverse, surprising without context, and the result of a real trade-off.
- List an alternative only when a reader might ask why it wasn't chosen.
- Leave out code details, such as caller duties, limits, test coverage, and encodings.
- Update an ADR in place when its decision changes.
- Delete an ADR when its decision no longer applies, renumber the ADRs after it, and update every reference.
