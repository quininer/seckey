//! Use [memsec](https://github.com/quininer/memsec) protected secret memory.

#![cfg_attr(not(feature = "nodrop"), feature(manually_drop))]

extern crate memsec;
#[cfg(feature = "nodrop")] extern crate nodrop;

mod key;
mod bytes;
mod seckey;

pub use key::*;
pub use bytes::*;
pub use seckey::*;
