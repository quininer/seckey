//! Use [memsec](https://github.com/quininer/memsec) protected secret memory.

extern crate memsec;

mod key;
mod bytes;
mod seckey;

pub use key::*;
pub use bytes::*;
pub use seckey::*;
