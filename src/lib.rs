//! Use [memsec](https://github.com/quininer/memsec) protected secret memory.

#![no_std]

extern crate memsec;

mod cmpkey;
mod tempkey;
#[cfg(feature = "use_std")] mod seckey;

use core::{ mem, ptr };
use memsec::memzero;

pub use cmpkey::CmpKey;
pub use tempkey::*;
#[cfg(feature = "use_std")] pub use seckey::*;


/// Zero a value
///
/// ```
/// use seckey::zero;
///
/// let mut v = [1, 2, 3];
/// unsafe { zero(&mut v) };
/// assert_eq!(v, [0, 0, 0]);
///
/// let mut v = &mut [1, 2, 3][..];
/// unsafe { zero(v) };
/// assert_eq!(v, [0, 0, 0]);
/// ```
pub unsafe fn zero<T: ?Sized>(t: &mut T) {
    memzero(t as *mut T as *mut u8, mem::size_of_val(t));
}

/// Free a value
///
/// Note that this does not clean data outside of the stack.
///
/// ```
/// use seckey::free;
///
/// let v = [1, 2, 3];
/// free(v);
/// ```
pub fn free<T: Sized>(mut t: T) {
    unsafe {
        ptr::drop_in_place(&mut t);
        zero(&mut t);
        mem::forget(t);
    }
}
