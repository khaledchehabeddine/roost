# Cryptographic test vectors

**Status:** Accepted

Use published vectors where available and independent implementations for primitive known answers
without published vectors. Record inputs and derivation provenance beside the constants so an
intentional change can be checked independently. An implementation-generated expected value alone
cannot detect both sides making the same cryptographic mistake.

Current protocol tests create their inputs locally. Small fixed examples belong beside assertions
when they check a known result or avoid expensive setup. We do not maintain a separate format-freeze
suite or regeneration tool for prerelease compatibility.
