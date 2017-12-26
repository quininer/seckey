//! Use [memsec](https://github.com/quininer/memsec) protected secret memory.

#![cfg_attr(not(feature = "use_std"), no_std)]

#[cfg(feature = "use_std")] extern crate core;
extern crate memsec;

mod tempkey;
#[cfg(feature = "use_std")] mod bytes;
#[cfg(feature = "use_std")] mod seckey;

use core::mem;
use memsec::memzero;

pub use tempkey::*;
#[cfg(feature = "use_std")] pub use bytes::*;
#[cfg(feature = "use_std")] pub use seckey::*;


/// Zero a value
///
/// ```
/// use seckey::zero;
///
/// let mut v = [1, 2, 3];
/// zero(&mut v);
/// assert_eq!(v, [0, 0, 0]);
/// ```
pub fn zero<T: Copy>(t: &mut T) {
    unsafe { memzero(t, mem::size_of::<T>()) };
}

/// Zero a slice
///
/// ```
/// use seckey::zero_slice;
///
/// let v = &mut [1, 2, 3][..];
/// zero_slice(v);
/// assert_eq!(v, [0, 0, 0]);
/// ```
pub fn zero_slice<T: Copy>(t: &mut [T]) {
    unsafe { memzero(t.as_mut_ptr(), t.len() * mem::size_of::<T>()) };
}
