//! Use [memsec](https://github.com/quininer/memsec) protected secret memory.

#![no_std]

#[cfg(feature = "use_std")]
extern crate std;

mod cmpkey;
mod tempkey;

#[cfg(feature = "use_std")]
mod bytes;

use core::{ mem, ptr };
pub use cmpkey::CmpKey;
pub use tempkey::TempKey;

#[cfg(feature = "use_std")]
pub use bytes::SecBytes;


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
        memsec::memzero(&mut t as *mut T as *mut u8, mem::size_of_val(&t));
        if mem::needs_drop::<T>() {
            mem::forget(t);
        }
    }
}

/// Zero bytes
///
/// ```
/// use seckey::zero;
///
/// let mut v = [1, 2, 3];
/// zero(&mut v);
/// assert_eq!(v, [0, 0, 0]);
///
/// let mut v = &mut [1u8, 2, 3][..];
/// zero(v);
/// assert_eq!(v, [0, 0, 0]);
/// ```
#[inline]
pub fn zero(t: &mut [u8]) {
    unsafe {
        memsec::memzero(t.as_mut_ptr(), t.len());
    }
}
