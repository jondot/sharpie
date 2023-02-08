use ring::signature;
use snafu::ResultExt;

/// A private key source for `ED25519`
pub enum PrivateKey {
    ///  openssl genpkey -algorithm ED25519 -out private-key-ed.pem
    PEM(String),
    ///  openssl genpkey -algorithm ED25519 -outform DER -out private-key-ed.pem
    DER(Vec<u8>),
    ///  raw key bytes created with `ring` to be loaded with PKCS8v2 only
    Raw(Vec<u8>),
}

impl PrivateKey {
    /// Reads a [`PrivateKey`].
    ///
    /// # Errors
    ///
    /// This function will return an error if IO fails
    pub fn read(&self) -> crate::Result<PrivateKeyBytes> {
        Ok(match self {
            Self::PEM(s) => {
                let p = pem::parse(s).context(crate::InvalidPemSnafu)?;
                PrivateKeyBytes::PKCS8v1v2(p.contents)
            }
            Self::DER(b) => PrivateKeyBytes::PKCS8v1v2(b.clone()),
            Self::Raw(b) => PrivateKeyBytes::PKCS8v2(b.clone()),
        })
    }
}

/// Binary form of a raw ED25519 key
pub enum PrivateKeyBytes {
    /// represents the encoding used normally by openssl generated keys
    PKCS8v1v2(Vec<u8>),
    /// represents the encoding used by ring or more modern tools
    PKCS8v2(Vec<u8>),
}

/// A public key source for `ED25519`
pub enum PublicKey {
    /// openssl pkey -in private-key-ed.pem -pubout -out public-key-ed.pem
    PEM(String),
    /// openssl pkey -in private-key-ed.pem -pubout -outform DER -out public-key-ed.pem
    DER(Vec<u8>),
    ///  raw key bytes created with `ring`
    Raw(Vec<u8>),
}

impl PublicKey {
    /// Reads a [`PublicKey`].
    ///
    /// # Errors
    ///
    /// This function will return an error if decoding fails
    pub fn read(&self) -> crate::Result<PublicKeyBytes> {
        Ok(PublicKeyBytes::Raw(match self {
            Self::PEM(s) => {
                let p = pem::parse(s).context(crate::InvalidPemSnafu)?;
                p.contents.iter().skip(12).copied().collect::<Vec<_>>()
            }
            Self::DER(bs) => bs.iter().skip(12).copied().collect::<Vec<_>>(),
            Self::Raw(bs) => bs.clone(),
        }))
    }
}

/// Binary form of a raw ED25519 public key
pub enum PublicKeyBytes {
    /// the precise key bytes without header or encoding
    Raw(Vec<u8>),
}

/// Verify an ED25519 signature
///
/// # Errors
///
/// This function will return an error if verify failed
pub fn verify(msg: &[u8], sig: &[u8], pubkey: &PublicKeyBytes) -> crate::Result<()> {
    // ASN.1 encoding for ed25519 always has a 12 byte header which we cut off to get
    // to the raw key
    // see https://mta.openssl.org/pipermail/openssl-users/2018-March/007777.html
    let PublicKeyBytes::Raw(key_bytes) = pubkey;

    let peer_public_key = signature::UnparsedPublicKey::new(&signature::ED25519, &key_bytes);
    peer_public_key
        .verify(msg, sig)
        .context(crate::SignatureFailedSnafu)?;

    Ok(())
}

/// Sign a message using ED25519
///
/// # Errors
///
/// This function will return an error if signing failed
pub fn sign(msg: &[u8], prkey: &PrivateKeyBytes) -> crate::Result<Vec<u8>> {
    let key_pair = match prkey {
        PrivateKeyBytes::PKCS8v1v2(b) => {
            signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(b).context(crate::InvalidKeySnafu)
        }
        PrivateKeyBytes::PKCS8v2(b) => {
            signature::Ed25519KeyPair::from_pkcs8(b).context(crate::InvalidKeySnafu)
        }
    }?;

    let sig = key_pair.sign(msg);
    Ok(sig.as_ref().to_vec())
}

/// Sign a message using ED25519 and encode as base64
///
/// # Errors
///
/// This function will return an error if signing failed
#[cfg(feature = "base64")]
pub fn sign_base64(msg: &[u8], privkey: &PrivateKeyBytes) -> crate::Result<String> {
    use base64::{prelude::BASE64_STANDARD, Engine};
    let sig = sign(msg, privkey)?;
    Ok(BASE64_STANDARD.encode(sig))
}

/// Verify an ED25519 signature, where the signature is base64 encoded
///
/// # Errors
///
/// This function will return an error if verify failed
#[cfg(feature = "base64")]
pub fn verify_base64(msg: &[u8], sig: &str, pubkey: &PublicKeyBytes) -> crate::Result<()> {
    use base64::{prelude::BASE64_STANDARD, Engine};
    let sig = BASE64_STANDARD
        .decode(sig)
        .context(crate::DecodeFailedSnafu)?;
    verify(msg, &sig, pubkey)
}

#[cfg(test)]
mod tests {
    use ring::{rand, signature::KeyPair};

    use super::*;
    use std::{fs, path::Path, process::Command};

    #[test]
    fn test_negatives() {
        let privkey = PrivateKey::PEM(
            String::from_utf8_lossy(&fs::read("fixtures/ed.private.pem").unwrap()).to_string(),
        )
        .read()
        .unwrap();
        let sig = sign(b"hello world", &privkey).expect("should sign");
        let pubkey = PublicKey::PEM(
            String::from_utf8_lossy(&fs::read("fixtures/ed.public.pem").unwrap()).to_string(),
        );

        verify(b"hello world_", &sig, &pubkey.read().unwrap()).expect_err("should fail");

        // wrong key
        let pubkey = PublicKey::PEM(
            String::from_utf8_lossy(&fs::read("fixtures/rsa.public.pem").unwrap()).to_string(),
        );
        verify(b"hello world", &sig, &pubkey.read().unwrap()).expect_err("should fail");

        // wrong format
        let pubkey = PublicKey::DER(fs::read("fixtures/ed.public.pem").unwrap());
        verify(b"hello world", &sig, &pubkey.read().unwrap()).expect_err("should fail");
    }

    #[test]
    fn test_pem() {
        let privkey = PrivateKey::PEM(
            String::from_utf8_lossy(&fs::read("fixtures/ed.private.pem").unwrap()).to_string(),
        )
        .read()
        .unwrap();
        let sig = sign(b"hello world", &privkey).expect("should sign");
        let pubkey = PublicKey::PEM(
            String::from_utf8_lossy(&fs::read("fixtures/ed.public.pem").unwrap()).to_string(),
        );
        verify(b"hello world", &sig, &pubkey.read().unwrap()).expect("should verify");
    }

    #[cfg(feature = "base64")]
    #[test]
    fn test_base64() {
        let privkey = PrivateKey::PEM(
            String::from_utf8_lossy(&fs::read("fixtures/ed.private.pem").unwrap()).to_string(),
        )
        .read()
        .unwrap();
        let sig = sign_base64(b"hello world", &privkey).expect("should sign");
        let pubkey = PublicKey::PEM(
            String::from_utf8_lossy(&fs::read("fixtures/ed.public.pem").unwrap()).to_string(),
        );
        verify_base64(b"hello world", &sig, &pubkey.read().unwrap()).expect("should verify");
    }

    #[test]
    fn test_pkcs8v2() {
        // Generate a key pair in PKCS#8 (v2) format.
        let rng = rand::SystemRandom::new();
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .unwrap()
            .as_ref()
            .to_vec();
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

        let sig = sign(
            b"hello world",
            &PrivateKey::Raw(pkcs8_bytes).read().unwrap(),
        )
        .expect("should sign");
        let pubkey = PublicKey::Raw(key_pair.public_key().as_ref().to_vec());
        verify(b"hello world", &sig, &pubkey.read().unwrap()).expect("should verify");
    }

    #[test]
    fn test_nodejs_signed() {
        let sig = fs::read("fixtures/ed.sign-me.txt.nodejs-sig").expect("file should exist");
        let pubkey = PublicKey::PEM(
            String::from_utf8_lossy(&fs::read("fixtures/ed.public.pem").unwrap()).to_string(),
        );
        let msg = fs::read("fixtures/sign-me.txt").expect("file should exist");
        verify(&msg, &sig, &pubkey.read().unwrap()).expect("should verify");
    }

    #[test]
    fn test_nodejs_verified() {
        let privkey = PrivateKey::PEM(
            String::from_utf8_lossy(&fs::read("fixtures/ed.private.pem").unwrap()).to_string(),
        )
        .read()
        .unwrap();
        let msg = fs::read("fixtures/sign-me.txt").expect("file should exist");
        let sig = sign(&msg, &privkey).expect("should sign");

        let sigfile = "fixtures/ed.sign-me.txt.ring-sig";
        if Path::new(sigfile).exists() {
            fs::remove_file(sigfile).expect("should remove");
        }
        fs::write(sigfile, sig).expect("should write sig file");

        // uses a generic wrapped public key `ed.public-wrap.pem` (SubjectPublicKeyInfo)
        let out = Command::new("node")
            .args(["fixtures/verify.js"])
            .output()
            .expect("failed to execute process");
        let ok = String::from_utf8_lossy(&out.stdout);

        println!("ok: {ok}");
        assert!(ok.contains("OK"));
    }
}
