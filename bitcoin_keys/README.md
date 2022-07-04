# Bitcoin keys

Types and traits for managing Bitcoin keys.

## About

The Bitcoin protocol deals with multiple formats and contexts of keys.
There are legacy ECDSA keys that may or may not be compressed, X-only (Taproot) keys, private keys, etc.
To avoid mixing them, this library provides multiple newtypes and
additional infrastructure aiding with conversions, parsing, serializing...

The crate is `no_std` and doesn't require an allocator.

## MSRV

The crate supports Rust 1.41.1+

## License

MITNFA
