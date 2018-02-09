use core::{ fmt, mem };
use core::ptr::{ self, NonNull };
use core::ops::{ Deref, DerefMut };
use core::cell::Cell;
use memsec::{ memzero, malloc, free, mprotect, Prot };


/// Secure Key
///
/// The use [memsec/malloc](../../memsec/fn.malloc.html) protection secret bytes.
///
/// More docs see [Secure memory · libsodium](https://download.libsodium.org/doc/helpers/memory_management.html).
pub struct SecKey<T> {
    ptr: NonNull<T>,
    count: Cell<usize>
}

impl<T> SecKey<T> {
    /// ```
    /// use seckey::{ zero, SecKey };
    ///
    /// let k = SecKey::new([1, 2, 3])
    ///     .unwrap_or_else(|mut val| {
    ///         // NOTE should zero it
    ///         zero(&mut val);
    ///         panic!()
    ///     });
    /// assert_eq!([1, 2, 3], *k.read());
    /// ```
    pub fn new(mut t: T) -> Result<SecKey<T>, T> {
        unsafe {
            match Self::from_ptr(&t) {
                Some(output) => {
                    memzero(&mut t as *mut T as *mut u8, mem::size_of::<T>());
                    mem::forget(t);
                    Ok(output)
                },
                None => Err(t)
            }
        }
    }

    /// ```
    /// use seckey::SecKey;
    ///
    /// let mut v = [1, 2, 3];
    /// let k = unsafe { SecKey::from_ptr(&v).unwrap() };
    /// assert_eq!([1, 2, 3], v);
    /// assert_eq!([1, 2, 3], *k.read());
    /// ```
    #[inline]
    pub unsafe fn from_ptr(t: *const T) -> Option<SecKey<T>> {
        Self::with(move |memptr| ptr::copy_nonoverlapping(t, memptr, 1))
    }

    /// ```
    /// use seckey::SecKey;
    ///
    /// let k: SecKey<u32> = unsafe { SecKey::with(|ptr| *ptr = 1).unwrap() };
    /// assert_eq!(1, *k.read());
    /// ```
    pub unsafe fn with<F>(f: F) -> Option<SecKey<T>>
        where F: FnOnce(*mut T)
    {
        let memptr = match malloc(mem::size_of::<T>()) {
            Some(memptr) => memptr as *mut T,
            None => return None
        };

        f(memptr);
        mprotect(memptr as *mut u8, Prot::NoAccess);

        Some(SecKey {
            ptr: NonNull::new_unchecked(memptr),
            count: Cell::new(0)
        })
    }
}

impl<T: Copy> SecKey<T> {
    pub fn from_ref(t: &T) -> Option<SecKey<T>> {
        unsafe { Self::from_ptr(t) }
    }
}

impl<T: Default> SecKey<T> {
    /// ```
    /// use seckey::SecKey;
    ///
    /// let k: SecKey<u32> = SecKey::with_default(|ptr| *ptr += 1).unwrap();
    /// assert_eq!(1, *k.read());
    /// ```
    pub fn with_default<F>(f: F) -> Option<SecKey<T>>
        where F: FnOnce(&mut T)
    {
        unsafe {
            Self::with(|p| {
                ptr::write(p, T::default());
                f(&mut *p);
            })
        }
    }
}

impl<T> SecKey<T> {
    #[inline]
    unsafe fn lock(&self) {
        let count = self.count.get();
        self.count.set(count - 1);
        if count <= 1 {
            mprotect(self.ptr.as_ptr() as *mut u8, Prot::NoAccess);
        }
    }

    /// Borrow Read
    ///
    /// ```
    /// use seckey::SecKey;
    ///
    /// let secpass = SecKey::new([8u8; 8]).unwrap();
    /// assert_eq!([8u8; 8], *secpass.read());
    /// ```
    #[inline]
    pub fn read(&self) -> SecReadGuard<T> {
        let count = self.count.get();
        self.count.set(count + 1);
        if count == 0 {
            unsafe { mprotect(self.ptr.as_ptr() as *mut u8, Prot::ReadOnly) };
        }

        SecReadGuard(self)
    }

    /// Borrow Write
    ///
    /// ```
    /// # use seckey::SecKey;
    /// #
    /// # let mut secpass = SecKey::new([8u8; 8]).unwrap();
    /// let mut wpass = secpass.write();
    /// wpass[0] = 0;
    /// assert_eq!([0, 8, 8, 8, 8, 8, 8, 8], *wpass);
    /// ```
    #[inline]
    pub fn write(&mut self) -> SecWriteGuard<T> {
        let count = self.count.get();
        self.count.set(count + 1);
        if count == 0 {
            unsafe { mprotect(self.ptr.as_ptr() as *mut u8, Prot::ReadWrite) };
        }

        SecWriteGuard(self)
    }
}

impl<T> fmt::Debug for SecKey<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("SecKey")
            .field(&format_args!("{:p}", self.ptr))
            .field(&self.count)
            .finish()
    }
}

impl<T> fmt::Pointer for SecKey<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:p}", self.ptr)
    }
}

impl<T> Drop for SecKey<T> {
    fn drop(&mut self) {
        unsafe {
            mprotect(self.ptr.as_ptr() as *mut u8, Prot::ReadWrite);
            ptr::drop_in_place(self.ptr.as_ptr());
            free(self.ptr.as_ptr() as *mut u8);
        }
    }
}


/// Read Guard
pub struct SecReadGuard<'a, T: 'a>(&'a SecKey<T>);

impl<'a, T: 'a> Deref for SecReadGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { self.0.ptr.as_ref() }
    }
}

impl<'a, T: 'a> Drop for SecReadGuard<'a, T> {
    fn drop(&mut self) {
        unsafe { self.0.lock() }
    }
}


/// Write Guard
pub struct SecWriteGuard<'a, T: 'a>(&'a mut SecKey<T>);

impl<'a, T: 'a> Deref for SecWriteGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { self.0.ptr.as_ref() }
    }
}

impl<'a, T: 'a> DerefMut for SecWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { self.0.ptr.as_mut() }
    }
}

impl<'a, T: 'a> Drop for SecWriteGuard<'a, T> {
    fn drop(&mut self) {
        unsafe { self.0.lock() }
    }
}
