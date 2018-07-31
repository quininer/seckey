//! Use [memsec](https://github.com/quininer/memsec) protected secret memory.

#![no_std]

extern crate memsec;

mod cmpkey;
mod tempkey;
#[cfg(feature = "use_std")] mod seckey;

use core::{ mem, ptr };
use memsec::memzero;

pub use zerosafe::ZeroSafe;
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

mod zerosafe {
    pub unsafe trait ZeroSafe {}

    macro_rules! impl_zerosafe {
        ( Type : $( $t:ty ),* ) => {
            $(
                unsafe impl ZeroSafe for $t {}
            )*
        };
        ( Generic : $( $t:ty ),* ) => {
            $(
                unsafe impl<T> ZeroSafe for $t {}
            )*
        };
        ( Array : $( $n:expr ),* ) => {
            $(
                unsafe impl<T: ZeroSafe> ZeroSafe for [T; $n] {}
            )*
        }
    }

    impl_zerosafe!{ Type:
        usize, u8, u16, u32, u64, u128,
        isize, i8, i16, i32, i64, i128,

        char, str
    }

    impl_zerosafe!{ Generic: *const T, *mut T, [T] }

    impl_zerosafe!{ Array:
         0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
        64,

        128, 256, 384, 512, 1024, 2048
    }
}
