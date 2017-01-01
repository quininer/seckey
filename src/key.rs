use std::fmt;
use std::ptr::copy;
use std::mem::{ uninitialized, size_of };
use memsec::{ memeq, mlock, munlock };


/// Temporary Key.
///
/// ```
/// use seckey::Key;
///
/// let key = Key::<[u8; 8]>::new(&[8; 8]);
/// assert_eq!(key, [8u8; 8]);
/// assert!(key != [1u8; 8]);
/// assert_eq!(key, Key::new(&[8u8; 8]));
/// ```
pub struct Key<T: Sized>(pub T);

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
        unsafe { mlock(&mut t, size_of::<T>()) };
        Key(t)
    }
}

impl<T> fmt::Debug for Key<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", "** tmp key **")
    }
}

impl<T: Sized> PartialEq<T> for Key<T> {
    fn eq(&self, rhs: &T) -> bool {
        unsafe { memeq(&self.0, rhs, size_of::<T>()) }
    }
}

impl<T: Sized> PartialEq<Key<T>> for Key<T> {
    fn eq(&self, &Key(ref rhs): &Key<T>) -> bool {
        self == rhs
    }
}

impl<T: Sized> Eq for Key<T> {}

impl<T> Drop for Key<T> where T: Sized {
    fn drop(&mut self) {
        unsafe { munlock(&mut self.0, size_of::<T>()) };
    }
}
