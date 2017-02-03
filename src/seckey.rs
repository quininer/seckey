use std::{ fmt, mem };
use std::ops::{ Deref, DerefMut };
use std::cell::Cell;
use memsec::{ memzero, malloc, free, Prot, mprotect };
#[cfg(feature = "place")] use std::ops::{ Place, Placer, InPlace };


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

/// ```
/// #![feature(placement_in_syntax)]
/// # fn main() {
/// use seckey::SecHeap;
///
/// let k = SecHeap <- 1;
/// assert_eq!(1, *k.read());
/// # }
/// ```
#[cfg(feature = "place")]
pub struct SecHeap;
#[cfg(feature = "place")]
pub struct SecPtr<T: Sized>(*mut T);

#[cfg(feature = "place")]
impl<T> Placer<T> for SecHeap {
    type Place = SecPtr<T>;

    fn make_place(self) -> Self::Place {
        SecPtr(unsafe { malloc(mem::size_of::<T>()).expect("malloc fail.") })
    }
}

#[cfg(feature = "place")]
impl<T> Place<T> for SecPtr<T> {
    fn pointer(&mut self) -> *mut T {
        self.0
    }
}

#[cfg(feature = "place")]
impl<T> InPlace<T> for SecPtr<T> {
    type Owner = SecKey<T>;

    unsafe fn finalize(self) -> Self::Owner {
        SecKey {
            ptr: self.0,
            count: Cell::new(0)
        }
    }
}

impl<T> SecKey<T> where T: Sized + Clone {
    /// ```
    /// use seckey::SecKey;
    ///
    /// let v = 1;
    /// let k = SecKey::new(&v).unwrap();
    /// assert_eq!(1, *k.read());
    /// ```
    pub fn new(t: &T) -> Option<SecKey<T>> {
        unsafe {
            let memptr: *mut T = match malloc(mem::size_of::<T>()) {
                Some(memptr) => memptr,
                None => return None
            };
            (*memptr).clone_from(t);
            mprotect(memptr, Prot::NoAccess);

            Some(SecKey {
                ptr: memptr,
                count: Cell::new(0)
            })
        }
    }
}

impl<T> SecKey<T> where T: Sized {
    /// ```
    /// use seckey::SecKey;
    ///
    /// let mut v = 1;
    /// let k = unsafe { SecKey::from_ptr(&mut v).unwrap() };
    /// assert_eq!(0, v);
    /// assert_eq!(1, *k.read());
    /// ```
    pub unsafe fn from_ptr(t: *mut T) -> Option<SecKey<T>> {
        let memptr: *mut T = match malloc(mem::size_of::<T>()) {
            Some(memptr) => memptr,
            None => return None
        };
        ::std::ptr::copy(t, memptr, 1);
        memzero(t, mem::size_of::<T>());
        mprotect(memptr, Prot::NoAccess);

        Some(SecKey {
            ptr: memptr,
            count: Cell::new(0)
        })
    }
}

impl<T> SecKey<T> where T: Sized {
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

impl<T> fmt::Debug for SecKey<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "** sec key ({}) **", self.count.get())
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
