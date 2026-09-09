# Protocol DoS Hardening Limits

**Status:** Accepted

Protocol denial-of-service hardening is configured through one public Rust limits value consumed
by Core protocol-state operations. A single value keeps defaults, supported ceilings, and
constrained-environment trade-offs reviewable as one API surface, while preserving fixed defaults
for existing callers and avoiding transport-specific policy in the cryptographic core.

## Considered Options

- Expose constants only. Rejected because callers could not lower limits for constrained hosts.
- Add one builder method per limit. Rejected because related ceilings would be reviewed and
  documented across many entry points instead of one cohesive API.

## Verification Evidence

- `docs/security.md` records default resource ceilings and caller responsibilities for constrained
  hosts.
- `docs/release.md` records constrained-decryption budget evidence for the release-gated receive
  path.
- The v1 MVP removes the platform-dependent allocation/latency gate. Input caps and explicit
  rejection tests remain; current releases make no measured device performance guarantee.
