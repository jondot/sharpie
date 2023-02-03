use std::fs;

use base64::{prelude::BASE64_STANDARD, Engine};
use sharpie::ed::{sign, verify, PrivateKey, PublicKey};

fn main() -> anyhow::Result<()> {
    let privkey = PrivateKey::PEM(fs::read_to_string("sharpie/fixtures/ed.private.pem")?).read()?;
    let sig = sign(b"hello world", &privkey)?;
    let pubkey = PublicKey::PEM(fs::read_to_string("sharpie/fixtures/ed.public.pem")?);
    verify(b"hello world", &sig, &pubkey)?;
    println!(
        "Verified ed25519 signature, base64 encoded:\n{}",
        BASE64_STANDARD.encode(sig)
    );
    Ok(())
}
