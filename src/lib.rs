//! Use [memsec](https://github.com/quininer/memsec) protected secret memory.

extern crate memsec;

mod tempkey;
mod bytes;
mod seckey;

pub use bytes::*;
pub use tempkey::*;
pub use seckey::*;
