sharpie
=======

[<img alt="github" src="https://img.shields.io/badge/github-jondot/sharpie-8dagcb?style=for-the-badge&labelColor=555555&logo=github" height="20">](https://github.com/jondot/sharpie)
[<img alt="crates.io" src="https://img.shields.io/crates/v/sharpie.svg?style=for-the-badge&color=fc8d62&logo=rust" height="20">](https://crates.io/crates/sharpie)
[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-sharpie-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs" height="20">](https://docs.rs/sharpie)
[<img alt="build status" src="https://img.shields.io/github/actions/workflow/status/jondot/sharpie/build.yml?branch=master&style=for-the-badge" height="20">](https://github.com/jondot/sharpie/actions?query=branch%3Amaster)

This is a Rust library for signing and verifying digital signatures using _RSA_ or _ED25519_.

## Dependency

```toml
[dependencies]
sharpie = "0.1.0"
```

For most recent version see [crates.io](https://crates.io/crates/sharpie)


## Usage

Run the example:

```rust
$ cargo run -p sharpie --example sign
```

For `Ed25519`, use the `sharpie::ed` module.

```rust
use sharpie::ed::{sign, verify, PrivateKey, PublicKey};
```

Optionally, generate your keys with `OpenSSL`:

```
$ openssl genpkey -algorithm ED25519 -out ed.private.pem
$ openssl pkey -in private-key-ed.pem -pubout -out ed.public.pem
```

And then sign:

```rust
let privkey = PrivateKey::PEM(fs::read_to_string("fixtures/ed.private.pem")?);
let sig = sign(b"hello world", &privkey)?;
```

Or, verify:

```rust
let pubkey =
    PublicKey::PEM(fs::read_to_string("fixtures/ed.public.pem")?);

// sig is Vec<u8>
verify(b"hello world", &sig, pubkey)?;
```

# Copyright

Copyright (c) 2022 [@jondot](http://twitter.com/jondot). See [LICENSE](LICENSE.txt) for further details.
