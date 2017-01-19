use std::fmt;
use std::ops::{ Deref, DerefMut };
use std::ptr::copy;
use std::mem::size_of;
use std::cell::Cell;
use memsec::{
    memzero,
    malloc, free,
    Prot, mprotect
};


/// Secure Key.
///
/// The use [memsec/malloc](../../memsec/fn.malloc.html) protection secret bytes.
/// When you need the password stored in the memory, you should use it.
///
/// More docs see [Secure memory · libsodium](https://download.libsodium.org/doc/helpers/memory_management.html).
pub struct SecKey<T: Sized> {
    ptr: *mut T,
    count: Cell<usize>
}

impl<T> SecKey<T> where T: Sized {
    pub fn new(t: &T) -> Option<SecKey<T>> {
        let memptr = match unsafe { malloc(size_of::<T>()) } {
            Some(memptr) => memptr,
            None => return None
        };
        unsafe {
            copy(t, memptr, 1);
            mprotect(memptr, Prot::NoAccess);
        }
        Some(SecKey {
            ptr: memptr,
            count: Cell::new(0)
        })
    }

    fn read_unlock(&self) {
        let count = self.count.get();
        self.count.set(count + 1);
        if count == 0 {
            unsafe { mprotect(self.ptr, Prot::ReadOnly) };
        }
    }

    fn write_unlock(&self) {
        let count = self.count.get();
        self.count.set(count + 1);
        if count == 0 {
            unsafe { mprotect(self.ptr, Prot::ReadWrite) };
        }
    }

    fn lock(&self) {
        let count = self.count.get();
        self.count.set(count - 1);
        if count == 1 {
            unsafe { mprotect(self.ptr, Prot::NoAccess) };
        }
    }

    /// Borrow Read.
    ///
    /// ```
    /// use seckey::SecKey;
    ///
    /// let mut pass: [u8; 8] = [8; 8];
    /// let secpass = SecKey::new(&pass).unwrap();
    /// assert_eq!(pass, *secpass.read());
    /// ```
    #[inline]
    pub fn read(&self) -> SecReadGuard<T> {
        self.read_unlock();
        SecReadGuard(self)
    }

    /// Borrow Write.
    ///
    /// ```
    /// # use seckey::SecKey;
    /// #
    /// # let mut pass: [u8; 8] = [8; 8];
    /// # let mut secpass = SecKey::new(&pass).unwrap();
    /// let mut wpass = secpass.write();
    /// wpass[0] = 0;
    /// assert_eq!([0, 8, 8, 8, 8, 8, 8, 8], *wpass);
    /// ```
    #[inline]
    pub fn write(&mut self) -> SecWriteGuard<T> {
        self.write_unlock();
        SecWriteGuard(self)
    }
}

impl<T> From<T> for SecKey<T> {
    fn from(mut t: T) -> SecKey<T> {
        let output = SecKey::new(&t).unwrap();
        unsafe { memzero(&mut t, size_of::<T>()) }; // XXX if `Drop` ?
        output
    }
}

impl<T> fmt::Debug for SecKey<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", "** sec key **")
    }
}

impl<T> Drop for SecKey<T> {
    fn drop(&mut self) {
        unsafe { free(self.ptr) }
    }
}


/// Read Guard.
pub struct SecReadGuard<'a, T: Sized + 'a>(&'a SecKey<T>);

impl<'a, T: Sized + 'a> Deref for SecReadGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.0.ptr }
    }
}

impl<'a, T: Sized + 'a> Drop for SecReadGuard<'a, T> {
    fn drop(&mut self) {
        self.0.lock();
    }
}


/// Write Guard.
pub struct SecWriteGuard<'a, T: Sized + 'a>(&'a mut SecKey<T>);

impl<'a, T: Sized + 'a> Deref for SecWriteGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.0.ptr }
    }
}

impl<'a, T: Sized + 'a> DerefMut for SecWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.0.ptr }
    }
}

impl<'a, T: Sized + 'a> Drop for SecWriteGuard<'a, T> {
    fn drop(&mut self) {
        self.0.lock();
    }
}
