use std::fmt;
use std::ptr::copy;
use std::mem::{ uninitialized, size_of, size_of_val };
use std::ops::{ Deref, DerefMut };
use memsec::{ memzero, memcmp, mlock, munlock };


/// Temporary Key.
///
/// ```
/// use seckey::Key;
///
/// let key = Key::<[u8; 8]>::new(&[8; 8]);
/// assert_eq!(key, [8u8; 8]);
/// ```
pub struct Key<T: Sized>(T);

impl<T> Key<T> where T: Sized {
    pub fn new(t: &T) -> Key<T> {
        let mut memo = unsafe { uninitialized() };
        unsafe {
            mlock(&mut memo, size_of::<T>());
            copy(t, &mut memo, 1);
        }
        Key(memo)
    }
}

impl<T> From<T> for Key<T> {
    #[inline]
    fn from(mut t: T) -> Key<T> {
        let output = Key::new(&t);
        unsafe { memzero(&mut t, size_of_val(&t)) };
        output
    }
}

impl<T> Deref for Key<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> DerefMut for Key<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T> fmt::Debug for Key<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", "** tmp key **")
    }
}

impl<T: Sized, X: ?Sized> PartialEq<X> for Key<T> {
    fn eq(&self, rhs: &X) -> bool {
        if size_of::<T>() == size_of_val(rhs) {
            unsafe { memcmp(
                &self.0 as *const T as *const u8,
                rhs as *const X as *const u8,
                size_of::<T>()
            ) == 0 }
        } else {
            false
        }
    }
}

impl<T> Eq for Key<T> {}

impl<T> Drop for Key<T> where T: Sized {
    fn drop(&mut self) {
        unsafe { munlock(&mut self.0, size_of::<T>()) };
    }
}
