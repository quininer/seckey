//! Use [memset](https://github.com/quininer/memsec) protected secret memory.

extern crate memsec;

mod key;
mod seckey;

pub use key::Key;
pub use seckey::SecKey;
