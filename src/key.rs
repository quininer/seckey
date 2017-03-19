use std::{ fmt, mem };
use std::borrow::{ Borrow, BorrowMut };
use memsec::{ memeq, mlock, munlock };


/// Temporary Key.
///
/// ```
/// use seckey::Key;
///
/// let key = unsafe { Key::from([8; 8]) };
/// assert_eq!(key, [8u8; 8]);
/// assert!(key != [1u8; 8]);
/// assert_eq!(key, unsafe { Key::from([8u8; 8]) });
/// ```
pub struct Key<T: Sized>(pub T);

impl<T> Key<T> {
    #[inline]
    pub unsafe fn from(mut t: T) -> Key<T> {
        mlock(&mut t, mem::size_of::<T>());
        Key(t)
    }
}

impl<T> Borrow<T> for Key<T> {
    fn borrow(&self) -> &T {
        &self.0
    }
}

impl<T> BorrowMut<T> for Key<T> {
    fn borrow_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

/*
impl<T> Default for Key<T> where T: Default {
    #[inline]
    fn default() -> Key<T> {
        Key::from(T::default())
    }
}
*/

impl<T> Clone for Key<T> where T: Clone {
    fn clone(&self) -> Key<T> {
        unsafe { Key::from(self.0.clone()) }
    }
}

impl<T> fmt::Debug for Key<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "** tmp key **")
    }
}

impl<T: Sized> PartialEq<T> for Key<T> {
    fn eq(&self, rhs: &T) -> bool {
        unsafe { memeq(&self.0, rhs, mem::size_of::<T>()) }
    }
}

impl<T: Sized> PartialEq<Key<T>> for Key<T> {
    fn eq(&self, &Key(ref rhs): &Key<T>) -> bool {
        self.eq(rhs)
    }
}

impl<T: Sized> Eq for Key<T> {}

impl<T> Drop for Key<T> where T: Sized {
    fn drop(&mut self) {
        unsafe {
            munlock(&mut self.0, mem::size_of::<T>());
        }
    }
}
