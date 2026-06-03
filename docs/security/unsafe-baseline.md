# Unsafe Baseline

Generated with `cargo geiger --manifest-path <crate>/Cargo.toml --all-targets --all-dependencies --no-indent --output-format GitHubMarkdown --locked`.

The generator sorts dependency rows to avoid cargo-geiger tree-order churn.
It tolerates cargo-geiger's known source-match warning after a report body is produced.

## aether-crypto


Metric output format: x/y
    x = unsafe code used by the build
    y = total unsafe code found in the crate

Symbols:
    🔒  = No `unsafe` usage found, declares #![forbid(unsafe_code)]
    ❓  = No `unsafe` usage found, missing #![forbid(unsafe_code)]
    ☢️  = `unsafe` usage found

Functions  Expressions  Impls  Traits  Methods  Dependency

0/0        0/0          0/0    0/0     0/0      ❓  aether-crypto 0.4.0
0/0        0/0          0/0    0/0     0/0      ❓  autocfg 1.5.0
0/0        0/0          0/0    0/0     0/0      ❓  bitflags 2.11.0
0/0        0/0          0/0    0/0     0/0      ❓  cfg-if 1.0.4
0/0        0/0          0/0    0/0     0/0      ❓  chacha20poly1305 0.10.1
0/0        0/0          0/0    0/0     0/0      ❓  cobs 0.3.0
0/0        0/0          0/0    0/0     0/0      ❓  curve25519-dalek-derive 0.1.1
0/0        0/0          0/0    0/0     0/0      ❓  ed25519-dalek 2.2.0
0/0        0/0          0/0    0/0     0/0      ❓  fiat-crypto 0.2.9
0/0        0/0          0/0    0/0     0/0      ❓  hex 0.4.3
0/0        0/0          0/0    0/0     0/0      ❓  num-traits 0.2.19
0/0        0/0          0/0    0/0     0/0      ❓  opaque-debug 0.3.1
0/0        0/0          0/0    0/0     0/0      ❓  quote 1.0.45
0/0        0/0          0/0    0/0     0/0      ❓  rand_chacha 0.3.1
0/0        0/0          0/0    0/0     0/0      ❓  rand_xorshift 0.3.0
0/0        0/0          0/0    0/0     0/0      ❓  rustc_version 0.4.1
0/0        0/0          0/0    0/0     0/0      ❓  serde_derive 1.0.228
0/0        0/0          0/0    0/0     0/0      ❓  thiserror 2.0.18
0/0        0/0          0/0    0/0     0/0      ❓  thiserror-impl 2.0.18
0/0        0/0          0/0    0/0     0/0      ❓  version_check 0.9.5
0/0        0/0          0/0    0/0     0/0      ❓  x25519-dalek 2.0.1
0/0        0/0          0/0    0/0     0/0      🔒  aead 0.5.2
0/0        0/0          0/0    0/0     0/0      🔒  crypto-common 0.1.7
0/0        0/0          0/0    0/0     0/0      🔒  digest 0.10.7
0/0        0/0          0/0    0/0     0/0      🔒  ed25519 2.2.3
0/0        0/0          0/0    0/0     0/0      🔒  hkdf 0.12.4
0/0        0/0          0/0    0/0     0/0      🔒  hmac 0.12.1
0/0        0/0          0/0    0/0     0/0      🔒  regex-syntax 0.8.10
0/0        0/0          0/0    0/0     0/0      🔒  signature 2.2.0
0/0        0/0          0/0    0/0     0/0      🔒  typenum 1.19.0
0/0        0/0          0/0    0/0     0/0      🔒  zeroize_derive 1.4.3
0/0        0/5          0/0    0/0     0/0      ❓  serde 1.0.228
0/0        0/6          0/0    0/0     0/0      ❓  proptest 1.5.0
0/0        0/7          0/1    0/0     0/0      ❓  lazy_static 1.5.0
0/0        0/78         0/0    0/0     0/0      ❓  serde_json 1.0.149
0/0        1/1          0/0    0/0     0/0      ☢️  universal-hash 0.5.1
0/0        126/126      0/0    0/0     3/3      ☢️  inout 0.1.4
0/0        14/14        0/0    0/0     3/3      ☢️  proc-macro2 1.0.106
0/0        16/16        0/0    0/0     0/0      ☢️  block-buffer 0.10.4
0/0        2/2          0/0    0/0     0/0      ☢️  rand_core 0.6.4
0/0        32/32        1/1    0/0     0/0      ☢️  rand 0.8.6
0/0        4/4          0/0    0/0     0/0      ☢️  unicode-ident 1.0.24
0/0        5/5          0/0    0/0     0/0      ☢️  serde_core 1.0.228
0/0        51/51        0/0    0/0     0/0      ☢️  postcard 1.1.3
0/0        7/7          0/0    0/0     0/0      ☢️  cipher 0.4.4
0/0        8/8          0/0    0/0     0/0      ☢️  subtle 2.6.1
0/0        87/87        3/3    0/0     2/2      ☢️  syn 2.0.117
0/1        0/11         0/0    0/0     0/0      ❓  unarray 0.1.4
0/1        0/145        0/0    0/0     0/0      ❓  itoa 1.0.18
0/13       0/842        0/0    0/0     0/0      ❓  chacha20 0.9.1
0/18       4/707        0/0    0/0     0/0      ☢️  sha2 0.10.9
0/2        137/680      0/0    0/0     16/25    ☢️  ppv-lite86 0.2.21
0/2        7/806        0/0    0/0     0/0      ☢️  curve25519-dalek 4.1.3
0/41       0/2421       0/2    0/0     0/147    ❓  memchr 2.8.0
0/46       0/652        0/0    0/0     0/0      ❓  wasi 0.11.1+wasi-snapshot-preview1
0/5        0/69         0/0    0/0     0/0      ❓  libm 0.2.16
0/5        0/975        0/0    0/0     0/12     ❓  poly1305 0.8.0
0/6        0/646        0/0    0/0     0/3      ❓  zmij 1.0.21
1/1        11/12        0/0    0/0     0/0      ☢️  cpufeatures 0.2.17
1/1        285/285      20/20  8/8     5/5      ☢️  generic-array 0.14.7
1/92       10/725       0/2    0/0     5/101    ☢️  libc 0.2.183
12/12      475/475      74/74  29/29   37/37    ☢️  zerocopy 0.8.47
2/2        26/26        0/0    0/0     0/0      ☢️  zeroize 1.8.2
3/6        51/192       0/1    0/0     1/3      ☢️  getrandom 0.2.17
5/5        120/120      2/2    0/0     1/1      ☢️  semver 1.0.27

Totals
25/259     1479/10238   100/106 37/37   73/342

## aether-core


Metric output format: x/y
    x = unsafe code used by the build
    y = total unsafe code found in the crate

Symbols:
    🔒  = No `unsafe` usage found, declares #![forbid(unsafe_code)]
    ❓  = No `unsafe` usage found, missing #![forbid(unsafe_code)]
    ☢️  = `unsafe` usage found

Functions  Expressions  Impls  Traits  Methods  Dependency

0/0        0/0          0/0    0/0     0/0      ❓  aether-core 0.4.0
0/0        0/0          0/0    0/0     0/0      ❓  aether-crypto 0.4.0
0/0        0/0          0/0    0/0     0/0      ❓  cfg-if 1.0.4
0/0        0/0          0/0    0/0     0/0      ❓  chacha20poly1305 0.10.1
0/0        0/0          0/0    0/0     0/0      ❓  cobs 0.3.0
0/0        0/0          0/0    0/0     0/0      ❓  curve25519-dalek-derive 0.1.1
0/0        0/0          0/0    0/0     0/0      ❓  ed25519-dalek 2.2.0
0/0        0/0          0/0    0/0     0/0      ❓  fiat-crypto 0.2.9
0/0        0/0          0/0    0/0     0/0      ❓  opaque-debug 0.3.1
0/0        0/0          0/0    0/0     0/0      ❓  quote 1.0.45
0/0        0/0          0/0    0/0     0/0      ❓  rand_chacha 0.3.1
0/0        0/0          0/0    0/0     0/0      ❓  rustc_version 0.4.1
0/0        0/0          0/0    0/0     0/0      ❓  serde_derive 1.0.228
0/0        0/0          0/0    0/0     0/0      ❓  thiserror 2.0.18
0/0        0/0          0/0    0/0     0/0      ❓  thiserror-impl 2.0.18
0/0        0/0          0/0    0/0     0/0      ❓  version_check 0.9.5
0/0        0/0          0/0    0/0     0/0      ❓  x25519-dalek 2.0.1
0/0        0/0          0/0    0/0     0/0      🔒  aead 0.5.2
0/0        0/0          0/0    0/0     0/0      🔒  crypto-common 0.1.7
0/0        0/0          0/0    0/0     0/0      🔒  digest 0.10.7
0/0        0/0          0/0    0/0     0/0      🔒  ed25519 2.2.3
0/0        0/0          0/0    0/0     0/0      🔒  hkdf 0.12.4
0/0        0/0          0/0    0/0     0/0      🔒  hmac 0.12.1
0/0        0/0          0/0    0/0     0/0      🔒  password-hash 0.5.0
0/0        0/0          0/0    0/0     0/0      🔒  signature 2.2.0
0/0        0/0          0/0    0/0     0/0      🔒  typenum 1.19.0
0/0        0/0          0/0    0/0     0/0      🔒  zeroize_derive 1.4.3
0/0        0/5          0/0    0/0     0/0      ❓  serde 1.0.228
0/0        1/1          0/0    0/0     0/0      ☢️  universal-hash 0.5.1
0/0        12/20        13/13  1/1     0/0      ☢️  blake2 0.10.6
0/0        126/126      0/0    0/0     3/3      ☢️  inout 0.1.4
0/0        14/14        0/0    0/0     3/3      ☢️  proc-macro2 1.0.106
0/0        16/16        0/0    0/0     0/0      ☢️  block-buffer 0.10.4
0/0        2/2          0/0    0/0     0/0      ☢️  rand_core 0.6.4
0/0        25/25        0/0    0/0     0/0      ☢️  base64ct 1.8.3
0/0        32/32        1/1    0/0     0/0      ☢️  rand 0.8.6
0/0        4/4          0/0    0/0     0/0      ☢️  unicode-ident 1.0.24
0/0        5/5          0/0    0/0     0/0      ☢️  serde_core 1.0.228
0/0        51/51        0/0    0/0     0/0      ☢️  postcard 1.1.3
0/0        7/7          0/0    0/0     0/0      ☢️  cipher 0.4.4
0/0        8/8          0/0    0/0     0/0      ☢️  subtle 2.6.1
0/0        87/87        3/3    0/0     2/2      ☢️  syn 2.0.117
0/13       0/842        0/0    0/0     0/0      ❓  chacha20 0.9.1
0/18       4/707        0/0    0/0     0/0      ☢️  sha2 0.10.9
0/2        137/680      0/0    0/0     16/25    ☢️  ppv-lite86 0.2.21
0/2        7/806        0/0    0/0     0/0      ☢️  curve25519-dalek 4.1.3
0/46       0/652        0/0    0/0     0/0      ❓  wasi 0.11.1+wasi-snapshot-preview1
0/5        0/975        0/0    0/0     0/12     ❓  poly1305 0.8.0
1/1        11/12        0/0    0/0     0/0      ☢️  cpufeatures 0.2.17
1/1        2/2          0/0    0/0     0/0      ☢️  argon2 0.5.3
1/1        285/285      20/20  8/8     5/5      ☢️  generic-array 0.14.7
1/92       10/725       0/2    0/0     5/101    ☢️  libc 0.2.183
12/12      475/475      74/74  29/29   37/37    ☢️  zerocopy 0.8.47
2/2        26/26        0/0    0/0     0/0      ☢️  zeroize 1.8.2
3/6        51/192       0/1    0/0     1/3      ☢️  getrandom 0.2.17
5/5        120/120      2/2    0/0     1/1      ☢️  semver 1.0.27

Totals
26/206     1518/6902    113/116 38/38   73/192

## aether-uniffi


Metric output format: x/y
    x = unsafe code used by the build
    y = total unsafe code found in the crate

Symbols:
    🔒  = No `unsafe` usage found, declares #![forbid(unsafe_code)]
    ❓  = No `unsafe` usage found, missing #![forbid(unsafe_code)]
    ☢️  = `unsafe` usage found

Functions  Expressions  Impls  Traits  Methods  Dependency

0/0        0/0          0/0    0/0     0/0      ❓  aether-core 0.4.0
0/0        0/0          0/0    0/0     0/0      ❓  aether-crypto 0.4.0
0/0        0/0          0/0    0/0     0/0      ❓  aether-uniffi 0.4.0
0/0        0/0          0/0    0/0     0/0      ❓  autocfg 1.5.0
0/0        0/0          0/0    0/0     0/0      ❓  basic-toml 0.1.10
0/0        0/0          0/0    0/0     0/0      ❓  bitflags 2.11.0
0/0        0/0          0/0    0/0     0/0      ❓  cargo-platform 0.1.9
0/0        0/0          0/0    0/0     0/0      ❓  cargo_metadata 0.19.2
0/0        0/0          0/0    0/0     0/0      ❓  cfg-if 1.0.4
0/0        0/0          0/0    0/0     0/0      ❓  chacha20poly1305 0.10.1
0/0        0/0          0/0    0/0     0/0      ❓  clap 4.6.0
0/0        0/0          0/0    0/0     0/0      ❓  cobs 0.3.0
0/0        0/0          0/0    0/0     0/0      ❓  curve25519-dalek-derive 0.1.1
0/0        0/0          0/0    0/0     0/0      ❓  ed25519-dalek 2.2.0
0/0        0/0          0/0    0/0     0/0      ❓  equivalent 1.0.2
0/0        0/0          0/0    0/0     0/0      ❓  fiat-crypto 0.2.9
0/0        0/0          0/0    0/0     0/0      ❓  fs-err 2.11.0
0/0        0/0          0/0    0/0     0/0      ❓  glob 0.3.3
0/0        0/0          0/0    0/0     0/0      ❓  num-traits 0.2.19
0/0        0/0          0/0    0/0     0/0      ❓  opaque-debug 0.3.1
0/0        0/0          0/0    0/0     0/0      ❓  quote 1.0.45
0/0        0/0          0/0    0/0     0/0      ❓  rand_chacha 0.3.1
0/0        0/0          0/0    0/0     0/0      ❓  rand_xorshift 0.3.0
0/0        0/0          0/0    0/0     0/0      ❓  rustc-hash 2.1.2
0/0        0/0          0/0    0/0     0/0      ❓  rustc_version 0.4.1
0/0        0/0          0/0    0/0     0/0      ❓  scroll_derive 0.12.1
0/0        0/0          0/0    0/0     0/0      ❓  serde_derive 1.0.228
0/0        0/0          0/0    0/0     0/0      ❓  smawk 0.3.2
0/0        0/0          0/0    0/0     0/0      ❓  static_assertions 1.1.0
0/0        0/0          0/0    0/0     0/0      ❓  thiserror 2.0.18
0/0        0/0          0/0    0/0     0/0      ❓  thiserror-impl 2.0.18
0/0        0/0          0/0    0/0     0/0      ❓  uniffi 0.31.1
0/0        0/0          0/0    0/0     0/0      ❓  uniffi_bindgen 0.31.1
0/0        0/0          0/0    0/0     0/0      ❓  uniffi_internal_macros 0.31.1
0/0        0/0          0/0    0/0     0/0      ❓  uniffi_macros 0.31.1
0/0        0/0          0/0    0/0     0/0      ❓  uniffi_meta 0.31.1
0/0        0/0          0/0    0/0     0/0      ❓  uniffi_pipeline 0.31.1
0/0        0/0          0/0    0/0     0/0      ❓  uniffi_udl 0.31.1
0/0        0/0          0/0    0/0     0/0      ❓  version_check 0.9.5
0/0        0/0          0/0    0/0     0/0      ❓  weedle2 5.0.0
0/0        0/0          0/0    0/0     0/0      ❓  windows-link 0.2.1
0/0        0/0          0/0    0/0     0/0      ❓  x25519-dalek 2.0.1
0/0        0/0          0/0    0/0     0/0      🔒  aead 0.5.2
0/0        0/0          0/0    0/0     0/0      🔒  clap_builder 4.6.0
0/0        0/0          0/0    0/0     0/0      🔒  clap_derive 4.6.0
0/0        0/0          0/0    0/0     0/0      🔒  crypto-common 0.1.7
0/0        0/0          0/0    0/0     0/0      🔒  digest 0.10.7
0/0        0/0          0/0    0/0     0/0      🔒  ed25519 2.2.3
0/0        0/0          0/0    0/0     0/0      🔒  fastrand 2.3.0
0/0        0/0          0/0    0/0     0/0      🔒  heck 0.5.0
0/0        0/0          0/0    0/0     0/0      🔒  hkdf 0.12.4
0/0        0/0          0/0    0/0     0/0      🔒  hmac 0.12.1
0/0        0/0          0/0    0/0     0/0      🔒  password-hash 0.5.0
0/0        0/0          0/0    0/0     0/0      🔒  regex-syntax 0.8.10
0/0        0/0          0/0    0/0     0/0      🔒  serde_spanned 1.1.0
0/0        0/0          0/0    0/0     0/0      🔒  signature 2.2.0
0/0        0/0          0/0    0/0     0/0      🔒  strsim 0.11.1
0/0        0/0          0/0    0/0     0/0      🔒  textwrap 0.16.2
0/0        0/0          0/0    0/0     0/0      🔒  toml 0.9.12+spec-1.1.0
0/0        0/0          0/0    0/0     0/0      🔒  toml_datetime 0.7.5+spec-1.1.0
0/0        0/0          0/0    0/0     0/0      🔒  toml_writer 1.1.0+spec-1.1.0
0/0        0/0          0/0    0/0     0/0      🔒  typenum 1.19.0
0/0        0/0          0/0    0/0     0/0      🔒  zeroize_derive 1.4.3
0/0        0/46         0/0    0/0     0/0      ❓  tempfile 3.27.0
0/0        0/5          0/0    0/0     0/0      ❓  serde 1.0.228
0/0        0/6          0/0    0/0     0/0      ❓  proptest 1.5.0
0/0        0/7          0/1    0/0     0/0      ❓  lazy_static 1.5.0
0/0        0/8925       0/0    0/0     0/0      ❓  windows-sys 0.61.2
0/0        1/1          0/0    0/0     0/0      ☢️  askama_derive 0.14.0
0/0        1/1          0/0    0/0     0/0      ☢️  universal-hash 0.5.1
0/0        109/109      0/0    0/0     9/9      ☢️  minimal-lexical 0.2.1
0/0        12/20        13/13  1/1     0/0      ☢️  blake2 0.10.6
0/0        126/126      0/0    0/0     3/3      ☢️  inout 0.1.4
0/0        14/14        0/0    0/0     0/0      ☢️  scroll 0.12.0
0/0        14/14        0/0    0/0     3/3      ☢️  proc-macro2 1.0.106
0/0        16/16        0/0    0/0     0/0      ☢️  block-buffer 0.10.4
0/0        2/2          0/0    0/0     0/0      ☢️  rand_core 0.6.4
0/0        2/2          8/8    0/0     1/1      ☢️  goblin 0.8.2
0/0        25/25        0/0    0/0     0/0      ☢️  base64ct 1.8.3
0/0        32/32        1/1    0/0     0/0      ☢️  rand 0.8.6
0/0        35/103       0/0    0/0     0/0      ☢️  errno 0.3.14
0/0        4/4          0/0    0/0     0/0      ☢️  unicode-ident 1.0.24
0/0        4/5          0/0    0/0     0/0      ☢️  askama 0.14.0
0/0        40/40        0/0    0/0     0/0      ☢️  nom 7.1.3
0/0        5/5          0/0    0/0     0/0      ☢️  serde_core 1.0.228
0/0        51/51        0/0    0/0     0/0      ☢️  postcard 1.1.3
0/0        6/6          0/0    0/0     0/0      ☢️  anstyle 1.0.14
0/0        66/72        0/0    0/0     16/18    ☢️  winnow 1.0.1
0/0        68/72        0/0    0/0     16/18    ☢️  winnow 0.7.15
0/0        7/7          0/0    0/0     0/0      ☢️  cipher 0.4.4
0/0        72/72        0/0    0/0     8/8      ☢️  toml_parser 1.1.0+spec-1.1.0
0/0        75/78        0/0    0/0     0/0      ☢️  serde_json 1.0.149
0/0        78/83        0/0    0/0     0/0      ☢️  indexmap 2.13.0
0/0        8/8          0/0    0/0     0/0      ☢️  subtle 2.6.1
0/0        81/128       5/9    0/0     3/5      ☢️  once_cell 1.21.4
0/0        87/87        3/3    0/0     2/2      ☢️  syn 2.0.117
0/0        9/9          0/0    0/0     0/0      ☢️  askama_parser 0.14.0
0/1        0/11         0/0    0/0     0/0      ❓  unarray 0.1.4
0/10       0/17551      0/0    0/0     0/2286   ❓  linux-raw-sys 0.12.1
0/11       0/507        0/11   0/3     0/31     ❓  wit-bindgen 0.51.0
0/13       0/842        0/0    0/0     0/0      ❓  chacha20 0.9.1
0/18       4/707        0/0    0/0     0/0      ☢️  sha2 0.10.9
0/2        137/680      0/0    0/0     16/25    ☢️  ppv-lite86 0.2.21
0/2        7/806        0/0    0/0     0/0      ☢️  curve25519-dalek 4.1.3
0/209      0/9078       0/25   0/2     0/58     ❓  wasip2 1.0.2+wasi-0.2.9
0/231      0/10231      0/77   0/2     0/197    ❓  wasip3 0.4.0+wasi-0.3.0-rc-2026-01-06
0/3        0/157        0/0    0/0     0/0      ❓  r-efi 6.0.0
0/46       0/652        0/0    0/0     0/0      ❓  wasi 0.11.1+wasi-snapshot-preview1
0/5        0/69         0/0    0/0     0/0      ❓  libm 0.2.16
0/5        0/975        0/0    0/0     0/12     ❓  poly1305 0.8.0
1/1        11/12        0/0    0/0     0/0      ☢️  cpufeatures 0.2.17
1/1        1337/1601    18/23  1/1     83/96    ☢️  hashbrown 0.16.1
1/1        145/145      0/0    0/0     0/0      ☢️  itoa 1.0.18
1/1        15/15        0/0    0/0     0/0      ☢️  clap_lex 1.1.0
1/1        2/2          0/0    0/0     0/0      ☢️  argon2 0.5.3
1/1        285/285      20/20  8/8     5/5      ☢️  generic-array 0.14.7
1/1        41/41        0/0    0/0     0/0      ☢️  siphasher 1.0.2
1/1        63/63        0/0    0/0     3/3      ☢️  camino 1.2.2
1/92       10/725       0/2    0/0     5/101    ☢️  libc 0.2.183
12/12      475/475      74/74  29/29   37/37    ☢️  zerocopy 0.8.47
12/15      356/362      2/2    0/0     12/12    ☢️  anyhow 1.0.102
2/2        18/18        1/1    0/0     0/0      ☢️  log 0.4.29
2/2        26/26        0/0    0/0     0/0      ☢️  zeroize 1.8.2
2/2        29/31        11/13  1/1     0/0      ☢️  plain 0.2.3
2/7        34/249       0/0    0/0     0/0      ☢️  getrandom 0.4.2
3/6        51/192       0/1    0/0     1/3      ☢️  getrandom 0.2.17
34/41      1700/2421    2/2    0/0     82/147   ☢️  memchr 2.8.0
38/436     1353/7539    7/22   1/2     20/62    ☢️  rustix 1.1.4
4/4        68/97        25/25  10/10   14/14    ☢️  uniffi_core 0.31.1
40/40      799/853      12/14  1/1     16/20    ☢️  bytes 1.11.1
5/5        120/120      2/2    0/0     1/1      ☢️  semver 1.0.27
6/6        638/646      0/0    0/0     3/3      ☢️  zmij 1.0.21

Totals
171/1234   8774/68365   204/349 52/60   359/3180

