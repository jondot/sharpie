//! Sign and verify using _RSA_ or _ED25519_ with a focus on simplicity.
//!
//! Use a simple interface: `sign` or `verify`,
//! from either the [ed] or [rsa] modules supporting multiple key formats.
//!
//! To sign:
//!
//! 1. Get the key bytes using `PrivateKey::<type>(..source..).read()`
//! 2. Optionally, cache these bytes for reuse
//! 3. Use `sign`
//!
//! To verify:
//!
//! 1. Get the key bytes using `PublicKey::<type>(..source..).read()`
//! 2. Optionally, cache these bytes for reuse
//! 3. Use `verify`
//!
//! Here's a full sign-verify cycle using `ED25519`, with keys generated using OpenSSL in this way:
//!
//! ```ignore
//! $ openssl genpkey -algorithm ED25519 -out ed.private.pem
//! $ openssl pkey -in private-key-ed.pem -pubout -out ed.public.pem
//! ```
//! Sign and verify using [sharpie::ed](ed):
//!
//! ```ignore
#![doc = include_str!("../examples/sign.rs")]
//! ```
//!
//!
//!
///ED25519 signing and verification
pub mod ed;

/// RSA signing and verification
pub mod rsa;

use snafu::prelude::*;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Unable to parse PEM: {}", source))]
    InvalidPem { source: pem::PemError },
    #[snafu(display("Signature operation failed"))]
    SignatureFailed { source: ring::error::Unspecified },
    #[snafu(display("Cannot read key: {}", source))]
    InvalidKey { source: ring::error::KeyRejected },
}
type Result<T, E = Error> = std::result::Result<T, E>;
