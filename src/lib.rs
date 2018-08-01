//! Use [memsec](https://github.com/quininer/memsec) protected secret memory.

#![no_std]

#[cfg(feature = "use_std")] extern crate std;
extern crate memsec;

mod cmpkey;
mod tempkey;
mod zerosafe;
#[cfg(feature = "use_std")] mod seckey;

use core::{ mem, ptr };

pub use zerosafe::{ ZeroSafe, zero, unsafe_zero };
pub use cmpkey::CmpKey;
pub use tempkey::*;
#[cfg(feature = "use_std")] pub use seckey::*;


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
        unsafe_zero(&mut t);
        mem::forget(t);
    }
}
