# Versionless Identity Keystore Encoding

**Status:** Accepted

Identity secrets persist to platform secure storage as raw fixed-length 32-byte values, one entry per key role, with no version byte or envelope. Secure-storage entries sit outside the versioned-artifact set (message encoding, Protocol State Blobs, identity backup) because each entry is a single primitive whose length is fixed by the algorithm choice: a version byte buys nothing until the primitive itself changes, and a primitive change forces re-keying through code that must know both layouts anyway. Raw entries also keep the unlock path free of any parser and keep keychain payloads minimal.

## Considered Options

- Versioned envelope per entry. Rejected. Adds a decode step and a corruptible byte to every load with no migration it could express today; the storage key already names the role and fixes the layout.
- One combined, versioned identity blob. Rejected. Couples unrelated key roles into a single read-modify-write and makes partially restored states ambiguous.
