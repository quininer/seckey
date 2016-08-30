//! Use [memset](https://github.com/quininer/memsec) protected secret memory.

extern crate memsec;

mod key;
mod bytes;
mod seckey;

pub use key::Key;
pub use bytes::Bytes;
pub use seckey::SecKey;
