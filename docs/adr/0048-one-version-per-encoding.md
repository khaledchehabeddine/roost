# One Version per Encoding

A sealed sender frame or protocol state blob nests several layers, and one version at its start covers every layer inside it, so readers never combine versions. The one exception is a sender certificate, which its domain signs with its own version. Relays forward frames without reading the version.

## Alternatives

- A version on each layer: readers would have to handle combinations of versions.
- Separate versions for the visible frame and its sealed contents: this only helps if relays read the version.
