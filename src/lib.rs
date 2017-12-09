//! Use [memsec](https://github.com/quininer/memsec) protected secret memory.

extern crate memsec;
#[cfg(feature = "nodrop")] extern crate nodrop;

mod tempkey;
mod bytes;
mod seckey;

pub use bytes::*;
pub use tempkey::*;
pub use seckey::*;
