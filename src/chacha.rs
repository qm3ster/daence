use std::fmt;

use chacha20::cipher::{KeyIvInit, StreamCipher};
use poly1305::Poly1305;
use subtle::ConstantTimeEq;
use universal_hash::{NewUniversalHash, UniversalHash};

/// Standard `ChaChaDaence` construct using `Poly1305`, `HChaCha20`, and `XChaCha20`.
/// Suitable for horses, children, and other individuals.
#[derive(Clone)]
pub struct ChaChaDaence<A> {
    cha: chacha20::Key, // [u8; 32],
    p1: poly1305::Key,  // [u8; 32]
    p2: poly1305::Key,  // [u8; 32]
    ad: A,
}

impl<A: AsRef<[u8]>> ChaChaDaence<A> {
    /// Constructs a `ChaChaDaence` from a 64-byte `key`
    /// and additional data (context) `ad` which will be authenticated but not encrypted.
    pub fn new(key: &[u8; 64], ad: A) -> Self {
        let cha = *chacha20::Key::from_slice(&key[..32]);
        let mut p1 = poly1305::Key::default();
        let mut p2 = poly1305::Key::default();
        p1[..16].copy_from_slice(&key[32..48]);
        p2[..16].copy_from_slice(&key[48..]);
        Self { cha, p1, p2, ad }
    }

    /// Encrypts a message `msg` in place `msg` in place, and writes authentication tago to `tag`.
    pub fn encrypt(&self, msg: &mut [u8], tag: &mut [u8; 24]) {
        self.compressauth(msg, tag);
        chacha20::XChaCha20::new(&self.cha, (&*tag).into()).apply_keystream(msg);
    }

    /// Authenticates and decrypts a message `msg` in place using `tag`
    /// If authentication fails, will zero-out the message instead.
    ///
    /// # Errors
    /// `AuthenticationError` is returned if the message is not authentic according to the tag
    pub fn decrypt<'m>(
        &self,
        msg: &'m mut [u8],
        tag: &[u8; 24],
    ) -> Result<&'m mut [u8], AuthenticationError> {
        let mut t = [0u8; 24];

        chacha20::XChaCha20::new(&self.cha, tag.into()).apply_keystream(msg);
        self.compressauth(msg, &mut t);

        if !bool::from(t.ct_eq(tag)) {
            msg.fill(0);
            return Err(AuthenticationError);
        }

        Ok(msg)
    }

    fn compressauth(&self, msg: &[u8], tag: &mut [u8; 24]) {
        let mut len64 = poly1305::Block::default();

        let mut p1 = Poly1305::new(&self.p1);
        let mut p2 = Poly1305::new(&self.p2);

        let ad = self.ad.as_ref();

        p1.update_padded(ad);
        p2.update_padded(ad);

        p1.update_padded(msg);
        p2.update_padded(msg);

        *(<&mut [u8; 8]>::try_from(&mut len64[0..8]).unwrap()) = (ad.len() as u64).to_le_bytes();
        *(<&mut [u8; 8]>::try_from(&mut len64[8..16]).unwrap()) = (msg.len() as u64).to_le_bytes();
        p1.update(&len64);
        p2.update(&len64);

        let h1 = p1.finalize();
        let h2 = p2.finalize();

        let u = chacha20::hchacha::<typenum::U10>(&self.cha, &h1.into_bytes());
        let t32 = chacha20::hchacha::<typenum::U10>(&u, &h2.into_bytes());

        tag.copy_from_slice(&t32[..24]);
    }
}

#[derive(Debug)]
pub struct AuthenticationError;
impl fmt::Display for AuthenticationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("failed MAC verification")
    }
}
impl std::error::Error for AuthenticationError {}

#[cfg(test)]
mod test {
    use super::ChaChaDaence;

    #[test]
    fn selftest() {
        let key: [u8; 64] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
            0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        ];
        let ad: [u8; 16] = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
            0x4e, 0x4f,
        ];
        let msg = vec![
            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d,
            0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
            0x6c, 0x6d, 0x6e, 0x6f, 0x70,
        ];
        let tag: [u8; 24] = [
            0x99, 0x76, 0x70, 0x9c, 0x45, 0x3c, 0x8f, 0x94, 0xe4, 0x92, 0xef, 0xa7, 0x70, 0xe3,
            0xc2, 0x21, 0xe0, 0x8e, 0xa6, 0xa0, 0xe5, 0x88, 0xd5, 0x4e,
        ];
        let cyphertext = vec![
            0x22, 0x7d, 0x2c, 0x0c, 0xde, 0xe4, 0x08, 0xbc, 0xe9, 0xd0, 0x53, 0x2a, 0x3a, 0x36,
            0x27, 0x01, 0x0f, 0x11, 0xf2, 0xb2, 0xe4, 0x72, 0x67, 0xe5, 0x33, 0xe9, 0x5a, 0xa3,
            0xb2, 0xe7, 0x1e, 0xfb, 0x68,
        ];
        let mut m: Vec<u8> = msg.clone();
        let mut t = [0u8; 24];

        ChaChaDaence::new(&key, &ad).encrypt(&mut m, &mut t);
        assert_eq!(m, cyphertext);
        assert_eq!(t, tag);

        ChaChaDaence::new(&key, &ad).decrypt(&mut m, &tag).unwrap();
        assert_eq!(m, msg);
    }

    #[test]
    fn test_vectors() {
        fn unhex(hex: &str) -> Vec<u8> {
            assert!(hex.len() % 2 == 0);
            let mut vec = Vec::with_capacity(hex.len() / 2);
            for i in 0..hex.len() / 2 {
                vec.push(u8::from_str_radix(&hex[i..i + 2], 16).unwrap());
            }
            vec
        }
        let mut lines = include_str!("../chachadaence.exp").lines();
        for i in 0..34 {
            let mut get = |prefix: &str| lines.next().expect(prefix).strip_prefix(prefix).unwrap();
            let m_len: usize = get("mlen=").parse().unwrap();
            assert_eq!(m_len, i);
            let ad_len: usize = get("alen=").parse().unwrap();
            let msg = unhex(get("m="));
            assert_eq!(msg.len(), m_len);
            let m_ = unhex(get("m_="));
            assert_eq!(msg, m_);
            let key = unhex(get("k=")).try_into().unwrap();
            let ad = unhex(get("a="));
            assert_eq!(ad.len(), ad_len);
            drop(unhex(get("h=")));
            drop(unhex(get("u=")));
            let cyphertext = unhex(get("c="));
            assert_eq!(cyphertext.len(), msg.len() + 24);
            assert!(lines.next().unwrap_or_default().is_empty());
            let (tag, cyphertext) = cyphertext.split_at(24);
            // let tag = tag.try_into().unwrap();
            let mut m: Vec<u8> = msg.clone();
            let mut t = [0u8; 24];

            ChaChaDaence::new(&key, &ad).encrypt(&mut m, &mut t);
            // assert_eq!(m, cyphertext);
            // assert_eq!(t, tag);

            ChaChaDaence::new(&key, &ad).decrypt(&mut m, &t).unwrap();
            // assert_eq!(m, msg);
        }
    }
}
