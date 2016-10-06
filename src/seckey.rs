use std::fmt;
use std::ptr::copy;
use std::mem::size_of;
use memsec::{
    memzero,
    malloc, free,
    Prot, unprotected_mprotect
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
            unprotected_mprotect(memptr, Prot::NoAccess);
        }
        Some(SecKey(memptr))
    }

    /// Map read. returns closure return value.
    ///
    /// ```
    /// use seckey::SecKey;
    ///
    /// let mut pass: [u8; 8] = [8; 8];
    /// let secpass = SecKey::new(&pass).unwrap();
    /// assert!(secpass.read_map(|b| b == &pass));
    /// ```
    pub fn read_map<U, F: FnOnce(&T) -> U>(&self, f: F) -> U {
        unsafe { unprotected_mprotect(self.0, Prot::ReadOnly) };
        let output = f(unsafe { &*self.0 });
        unsafe { unprotected_mprotect(self.0, Prot::NoAccess) };
        output
    }

    /// Map write. returns closure return value.
    ///
    /// ```
    /// # use seckey::SecKey;
    /// #
    /// # let mut pass: [u8; 8] = [8; 8];
    /// # let mut secpass = SecKey::new(&pass).unwrap();
    /// secpass.write_map(|bs| bs[0] = 0);
    /// let bs = secpass.read_map(|bs| {
    ///     let mut pass = [0; 8];
    ///     pass.clone_from_slice(bs);
    ///     pass
    /// });
    /// assert_eq!(bs, [0, 8, 8, 8, 8, 8, 8, 8]);
    /// ```
    pub fn write_map<U, F: FnOnce(&mut T) -> U>(&mut self, f: F) -> U {
        unsafe { unprotected_mprotect(self.0, Prot::ReadWrite) };
        let output = f(unsafe { &mut *self.0 });
        unsafe { unprotected_mprotect(self.0, Prot::NoAccess) };
        output
    }
}

impl<T> From<T> for SecKey<T> {
    fn from(mut t: T) -> SecKey<T> {
        let output = SecKey::new(&t).unwrap();
        unsafe { memzero(&mut t, size_of::<T>()) };
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
