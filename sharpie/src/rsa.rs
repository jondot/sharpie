use ring::{rand, signature};
use snafu::ResultExt;

/// RSA private key source
pub enum PrivateKey {
    /// openssl genrsa -out private-key.pem 3072
    /// * Unwrapped pkcs8
    PEM(String),
    /// openssl genrsa -outform DER -out private-key.der 3072
    /// * Unwrapped pkcs8
    DER(Vec<u8>),
    ///    openssl genpkey -algorithm RSA \
    ///        -pkeyopt rsa_keygen_bits:3072 \
    ///        -pkeyopt rsa_keygen_pubexp:65537 | \
    ///      openssl pkcs8 -topk8 -nocrypt -outform pem > rsa-3072-private-key.pk8
    /// * Wrapped pkcs8
    PK8PEM(String),
    ///    openssl genpkey -algorithm RSA \
    ///        -pkeyopt rsa_keygen_bits:3072 \
    ///        -pkeyopt rsa_keygen_pubexp:65537 | \
    ///      openssl pkcs8 -topk8 -nocrypt -outform de > rsa-3072-private-key.pk8
    /// * Wrapped pkcs8
    PK8DER(Vec<u8>),
}

impl PrivateKey {
    /// Reads a [`PrivateKey`].
    ///
    /// # Errors
    ///
    /// This function will return an error if reading failed
    pub fn read(&self) -> crate::Result<PrivateKeyBytes> {
        Ok(match self {
            Self::PEM(s) => {
                let p = pem::parse(s).context(crate::InvalidPemSnafu)?;
                PrivateKeyBytes::DER(p.contents)
            }
            Self::DER(b) => PrivateKeyBytes::DER(b.clone()),

            Self::PK8PEM(s) => {
                let p = pem::parse(s).context(crate::InvalidPemSnafu)?;
                PrivateKeyBytes::PK8(p.contents)
            }
            Self::PK8DER(b) => PrivateKeyBytes::PK8(b.clone()),
        })
    }
}

/// Binary form of a raw RSA key
pub enum PrivateKeyBytes {
    DER(Vec<u8>),
    PK8(Vec<u8>),
}

/// A public key source for RSA
pub enum PublicKey {
    //// `openssl rsa -in private-key.pem -RSAPublicKey_out -out public-key.pem`
    ///  or with pk8 `openssl rsa -in fixtures/rsa.private.pem.pk8 -outform pem -RSAPublicKey_out -out fixtures/rsa.public.pem.pk8`
    PEM(String),
    //// `openssl rsa -in private-key.pem -outform DER -RSAPublicKey_out -out public-key.der`
    DER(Vec<u8>),
}

impl PublicKey {
    /// Reads a [`PublicKey`].
    ///
    /// # Errors
    ///
    /// This function will return an error if reading failed
    pub fn read(&self) -> crate::Result<PublicKeyBytes> {
        Ok(PublicKeyBytes::Raw(match self {
            Self::PEM(s) => {
                let p = pem::parse(s).context(crate::InvalidPemSnafu)?;
                p.contents
            }
            Self::DER(bs) => bs.clone(),
        }))
    }
}

/// Binary form of a raw RSA public key
pub enum PublicKeyBytes {
    Raw(Vec<u8>),
}

/// Verify
///
/// # Errors
///
/// This function will return an error if verification failed
pub fn verify(msg: &[u8], sig: &[u8], pubkey: &PublicKeyBytes) -> crate::Result<()> {
    let PublicKeyBytes::Raw(key_bytes) = pubkey;
    // Verify the signature.
    let public_key =
        signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, key_bytes);
    public_key
        .verify(msg, sig)
        .context(crate::SignatureFailedSnafu)?;
    Ok(())
}

/// Sign
///
/// # Errors
///
/// This function will return an error if signing failed
pub fn sign(msg: &[u8], privkey: &PrivateKeyBytes) -> crate::Result<Vec<u8>> {
    let key_pair = match privkey {
        PrivateKeyBytes::DER(b) => {
            signature::RsaKeyPair::from_der(b).context(crate::InvalidKeySnafu)
        }
        PrivateKeyBytes::PK8(b) => {
            signature::RsaKeyPair::from_pkcs8(b).context(crate::InvalidKeySnafu)
        }
    }?;
    let rng = rand::SystemRandom::new();
    let mut sig = vec![0; key_pair.public_modulus_len()];
    key_pair
        .sign(&signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig)
        .context(crate::SignatureFailedSnafu)?;

    Ok(sig)
}

/// Sign and return a base64 encoded signature
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

/// Verify where the signature is base64 encoded
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
    use super::*;
    use std::{fs, path::Path, process::Command};

    #[test]
    fn test_negatives() {
        let privkey = PrivateKey::PEM(
            String::from_utf8_lossy(&fs::read("fixtures/rsa.private.pem").unwrap()).to_string(),
        )
        .read()
        .unwrap();
        let sig = sign(b"hello world", &privkey).expect("should sign");
        let pubkey = PublicKey::PEM(
            String::from_utf8_lossy(&fs::read("fixtures/rsa.public.pem").unwrap()).to_string(),
        )
        .read()
        .unwrap();
        verify(b"hello world_", &sig, &pubkey).expect_err("should fail");

        // wrong key
        let pubkey = PublicKey::PEM(
            String::from_utf8_lossy(&fs::read("fixtures/ed.public.pem").unwrap()).to_string(),
        )
        .read()
        .unwrap();
        verify(b"hello world", &sig, &pubkey).expect_err("should fail");

        // wrong format
        let pubkey = PublicKey::DER(fs::read("fixtures/rsa.public.pem").unwrap())
            .read()
            .unwrap();
        verify(b"hello world", &sig, &pubkey).expect_err("should fail");
    }

    #[test]
    fn test_pem() {
        let privkey = PrivateKey::PEM(
            String::from_utf8_lossy(&fs::read("fixtures/rsa.private.pem").unwrap()).to_string(),
        )
        .read()
        .unwrap();
        let sig = sign(b"hello world", &privkey).expect("should sign");
        let pubkey = PublicKey::PEM(
            String::from_utf8_lossy(&fs::read("fixtures/rsa.public.pem").unwrap()).to_string(),
        )
        .read()
        .unwrap();
        verify(b"hello world", &sig, &pubkey).expect("should verify");
    }

    #[cfg(feature = "base64")]
    #[test]
    fn test_base64() {
        let privkey = PrivateKey::PEM(
            String::from_utf8_lossy(&fs::read("fixtures/rsa.private.pem").unwrap()).to_string(),
        )
        .read()
        .unwrap();
        let sig = sign_base64(b"hello world", &privkey).expect("should sign");
        let pubkey = PublicKey::PEM(
            String::from_utf8_lossy(&fs::read("fixtures/rsa.public.pem").unwrap()).to_string(),
        )
        .read()
        .unwrap();
        verify_base64(b"hello world", &sig, &pubkey).expect("should verify");
    }

    #[test]
    fn test_pk8pem() {
        let privkey = PrivateKey::PK8PEM(
            String::from_utf8_lossy(&fs::read("fixtures/rsa.private.pem.pk8").unwrap()).to_string(),
        )
        .read()
        .unwrap();
        let sig = sign(b"hello world", &privkey).expect("should sign");
        let pubkey = PublicKey::PEM(
            String::from_utf8_lossy(&fs::read("fixtures/rsa.public.pem.pk8").unwrap()).to_string(),
        )
        .read()
        .unwrap();
        verify(b"hello world", &sig, &pubkey).expect("should verify");
    }

    #[test]
    fn test_pk8der() {
        let privkey = PrivateKey::PK8DER(fs::read("fixtures/rsa.private.der.pk8").unwrap())
            .read()
            .unwrap();
        let sig = sign(b"hello world", &privkey).expect("should sign");
        let pubkey = PublicKey::DER(fs::read("fixtures/rsa.public.der.pk8").unwrap())
            .read()
            .unwrap();
        verify(b"hello world", &sig, &pubkey).expect("should verify");
    }

    #[test]
    fn test_ossl_signed() {
        let sig = fs::read("fixtures/rsa.sign-me.txt.ossl-sig").expect("file should exist");
        let pubkey = PublicKey::PEM(
            String::from_utf8_lossy(&fs::read("fixtures/rsa.public.pem").unwrap()).to_string(),
        )
        .read()
        .unwrap();
        let msg = fs::read("fixtures/sign-me.txt").expect("file should exist");
        verify(&msg, &sig, &pubkey).expect("should verify");
    }

    #[test]
    fn test_ossl_verified() {
        let privkey = PrivateKey::PEM(
            String::from_utf8_lossy(&fs::read("fixtures/rsa.private.pem").unwrap()).to_string(),
        )
        .read()
        .unwrap();
        let msg = fs::read("fixtures/sign-me.txt").expect("file should exist");
        let sig = sign(&msg, &privkey).expect("should sign");

        let sigfile = "fixtures/rsa.sign-me.txt.ring-sig";
        if Path::new(sigfile).exists() {
            fs::remove_file(sigfile).expect("should remove");
        }
        fs::write(sigfile, sig).expect("should write sig file");

        // uses a generic wrapped public key `rsa.public-wrap.pem` (SubjectPublicKeyInfo)
        let out = Command::new("openssl")
        .args(&"dgst -sha256 -verify fixtures/rsa.public-wrap.pem -signature fixtures/rsa.sign-me.txt.ring-sig fixtures/sign-me.txt".split(' ').collect::<Vec<_>>())
        .output()
        .expect("failed to execute process");
        let ok = String::from_utf8_lossy(&out.stdout);

        assert!(ok.contains("OK"));
    }
}
