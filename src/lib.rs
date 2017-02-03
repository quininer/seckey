//! Use [memsec](https://github.com/quininer/memsec) protected secret memory.

#![cfg_attr(feature = "place", feature(placement_new_protocol))]

extern crate memsec;

mod key;
mod bytes;
mod seckey;

pub use key::*;
pub use bytes::*;
pub use seckey::*;
