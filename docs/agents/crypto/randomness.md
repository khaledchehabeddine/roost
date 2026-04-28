# Randomness for Cryptographic Use

## Pattern

Production cryptographic randomness comes from `rand::rngs::OsRng` — the OS-provided cryptographically secure RNG. No other source is acceptable outside `#[cfg(test)]` modules.

In Hermes: every key-generation site uses `OsRng` directly (no thread-local wrappers, no seed-derived RNGs).

## Why it matters

Cryptographic security collapses without unpredictable randomness:

- Predictable seeds → predictable keys. An attacker who guesses the seed reproduces every secret derived from it.
- Statistical weakness → distinguishability. Even RNGs that "look random" but have low entropy let an attacker bias the keyspace search.
- Single-source-of-truth simplifies audit. Reviewers can grep for `OsRng` and confirm every production key path uses it.

`OsRng` reads from the OS entropy pool (`/dev/urandom` on Linux/macOS, `BCryptGenRandom` on Windows, `getrandom(2)` syscall when available). The OS pool is continuously seeded from hardware sources and is the platform's strongest entropy guarantee.

## Implementation

```rust
use rand::rngs::OsRng;
use x25519_dalek::StaticSecret;
use ed25519_dalek::SigningKey;

pub fn generate_x25519_secret() -> StaticSecret {
    StaticSecret::random_from_rng(OsRng)
}

pub fn generate_ed25519_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}
```

Both dalek crates accept `OsRng` directly via their `random_from_rng` / `generate` constructors. No intermediate buffer, no seed derivation.

## Test exception

`#[cfg(test)]` modules may use seeded RNGs for reproducibility:

```rust
#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn known_answer_test() {
        let mut rng = ChaCha20Rng::seed_from_u64(0xC0FFEE);
        let key = StaticSecret::random_from_rng(&mut rng);
        assert_eq!(key.to_bytes(), EXPECTED_KEY);
    }
}
```

This is the *only* acceptable use of a non-OS RNG. The `#[cfg(test)]` gate ensures it never compiles into the production binary.

## Anti-patterns

```rust
// BAD: seed derived from time (or any low-entropy source) — guessable
let mut rng = StdRng::seed_from_u64(timestamp);
let key = derive_from_rng(&mut rng);

// BAD: hardcoded seed outside #[cfg(test)] — vulnerability
const TEST_SEED: [u8; 32] = [0; 32];
let mut rng = ChaCha20Rng::from_seed(TEST_SEED);
```

## Apply when

- Generating any long-lived key (identity key, signed prekey, one-time prekey)
- Generating ephemeral key pairs (ratchet step DH keys)
- Creating any value that must be unpredictable to an attacker

## Don't apply when

- Generating non-secret values like timestamps, counters, or message IDs (unless those values must be unpredictable for a security reason)
- In `#[cfg(test)]` code where reproducibility outweighs unpredictability

## Verification

Audit RNG sources:

```bash
grep -rn "rand::\|RngCore\|rng\b" crates/hermes-crypto/src/ | grep -v "//"
```

For each match, confirm:
1. `OsRng` (production) or seeded RNG inside `#[cfg(test)]` (tests)
2. No `thread_rng`, no `StdRng::seed_from_u64`, no hand-rolled seeds
3. No randomness derived from time, process ID, or other low-entropy sources

## See also

- `rand` crate documentation: <https://docs.rs/rand/>
- `getrandom` crate (the OS interface): <https://docs.rs/getrandom/>
- AGENTS.md `## Coding Guidelines > Crypto` — the enforceable rule
- [zeroization.md](zeroization.md) — secrets you generate from `OsRng` need scrubbing on drop
