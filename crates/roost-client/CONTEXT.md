# Client

The mobile UniFFI declarations and adapters for Core operations and Protocol verification.

## Language

**SecureStorage**:
The foreign-implementable interface through which the host supplies platform secret storage at
runtime. Rust adapts it to Core's storage trait; Core does not access Keychain or Keystore directly.
_Avoid_: protocol database, SDK-owned keychain

**Prepared KeyStore Operation**:
The host-visible identifier, preconditions, and provisional output of Core's secure mutation.
Staged secrets stay in SecureStorage; the host coordinates its database commit with finalization.
_Avoid_: eager KeyStore call, platform transaction

**Host State Transaction**:
The atomic commit of Core's conditional blob updates and their associated effects. The host owns
persistence and serialization across processes; a Rust callback cannot supply that transaction.
_Avoid_: Rust storage callback, SDK database

**Binding Surface**:
The Rust UniFFI objects, records, enums, and foreign traits from which Swift and Kotlin APIs are
generated. Generated files are build outputs; Rust declarations remain their maintained source.
_Avoid_: handwritten FFI, checked-in SDK source
