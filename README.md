# Daence

[![Crates.io][crates-badge]][crates-url]
[![MIT licensed][mit-badge]][mit-url]

[crates-badge]: https://img.shields.io/crates/v/daence.svg
[crates-url]: https://crates.io/crates/daence
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/qm3ster/daence/blob/master/LICENSE

Here lies an implementation of ["Deterministic Authenticated Encryption with no noNCEnse" by Taylor ‘Riastradh’ Campbell](https://github.com/riastradh/daence).

Rumor has it that this [`AEAD`](https://en.wikipedia.org/wiki/Authenticated_encryption) construct thrives in abscence of nonces.

It seems like it works, I am going to use it, and so can you.

Currently, only the later XChaCha20 (as opposed to the Salsa20) variant is implemented.

Contributions are welcome, including documentation, benchmarks, and *especially* implementing the [`aead` traits](https://docs.rs/aead/latest/aead/#traits).

## License
This project is licensed under the [MIT license][mit-url].


## Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in Daencezs by you, shall be licensed as MIT, without any additional terms or conditions.