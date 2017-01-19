use std::fmt;
use std::ops::{ Deref, DerefMut };
use std::ptr::copy;
use std::mem::size_of;
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
pub struct SecKey<T: Sized>(*mut T);

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
        Some(SecKey(memptr))
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
        SecReadGuard(unsafe { &*self.0 })
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
        SecWriteGuard(unsafe { &mut *self.0 })
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
        unsafe { free(self.0) }
    }
}


/// Read Guard.
pub struct SecReadGuard<'a, T: Sized + 'a>(&'a T);

impl<'a, T: Sized + 'a> Deref for SecReadGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { mprotect(self.0 as *const _ as *mut T, Prot::ReadOnly) };
        self.0
    }
}

impl<'a, T: Sized + 'a> Drop for SecReadGuard<'a, T> {
    fn drop(&mut self) {
        unsafe { mprotect(self.0 as *const _ as *mut T, Prot::NoAccess) };
    }
}


/// Write Guard.
pub struct SecWriteGuard<'a, T: Sized + 'a>(&'a mut T);

impl<'a, T: Sized + 'a> Deref for SecWriteGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { mprotect(self.0 as *const _ as *mut T, Prot::ReadOnly) };
        self.0
    }
}

impl<'a, T: Sized + 'a> DerefMut for SecWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { mprotect(self.0, Prot::ReadWrite) };
        self.0
    }
}

impl<'a, T: Sized + 'a> Drop for SecWriteGuard<'a, T> {
    fn drop(&mut self) {
        unsafe { mprotect(self.0, Prot::NoAccess) };
    }
}
