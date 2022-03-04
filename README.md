# Daence

[![Crates.io][crates-badge]][crates-url]
[![Docs.rs][docs-badge]][docs-url]
[![MIT licensed][mit-badge]][mit-url]

[crates-badge]: https://img.shields.io/crates/v/daence.svg
[crates-url]: https://crates.io/crates/daence
[docs-badge]: https://docs.rs/daence/badge.svg
[docs-url]: https://docs.rs/daence/
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/qm3ster/daence/blob/master/LICENSE

Here lies an implementation of ["Deterministic Authenticated Encryption with no noNCEnse" by Taylor ‘Riastradh’ Campbell](https://github.com/riastradh/daence).

## Security Warning
**No** security audits of this crate have ever been performed, and it has not been thoroughly assessed to ensure its operation is constant-time on common CPU architectures.

**USE AT YOUR OWN RISK!**

## Description

Rumor has it that this [`AEAD`](https://en.wikipedia.org/wiki/Authenticated_encryption) construct thrives in abscence of nonces.

That property, combined with a tag size of only 12 bytes, allows using it for extremely size-constrained messages.

It seems like it works, I am going to use it, and so can you.

Notably, at the time of writing, it is probably as constant-time as the underlying `poly1305::Poly1305`, `chacha20::hchacha`, `chacha20::XChaCha20` and `<[u8] as subtle::ConstantTimeEq>::ct_eq`.</br>
There is no flow control, and all of these get called on the entire relevant portions of the data for any and all keys, additional data, cyphertext, and tag.

⚠ That said, **neither this implementation, nor the original specification have been sufficiently peer reviewed**, and using this today may be unreasonable for many usecases. ⚠</br>
I personally have several questions for the specification...</br>
If you have the space for it, you may want to use [`AES-GCM-SIV`](https://github.com/RustCrypto/AEADs/tree/master/aes-gcm-siv).
If you additionaly have a source of nonces, and are confident they will not be reused, you may use [`ChaCha20Poly1305`](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305).

Currently, only the later XChaCha20 (as opposed to the Salsa20) variant is implemented.

Contributions are welcome, including documentation, benchmarks, and *especially* implementing the [`aead` traits](https://docs.rs/aead/latest/aead/#traits).

## License
This project is licensed under the [MIT license][mit-url].


## Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in Daencezs by you, shall be licensed as MIT, without any additional terms or conditions.