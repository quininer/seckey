use std::{ fmt, mem, ptr };
use std::cmp::Ordering;
use std::ops::{ Deref, DerefMut };
use memsec::{ memeq, memcmp, mlock, munlock };


/// Temporary Key.
///
/// ```
/// use seckey::Key;
///
/// let key = Key::from([8u8; 8]);
/// assert_eq!(key, [8u8; 8]);
/// assert_ne!(key, [1u8; 8]);
/// assert_eq!(key, Key::from([8u8; 8]));
/// ```
pub struct Key<T: Sized>(*mut T);

impl<T> Key<T> {
    pub fn from(t: T) -> Key<T> {
        let box_ptr = Box::into_raw(Box::new(t));
        unsafe { mlock(box_ptr, mem::size_of::<T>()) };
        Key(box_ptr)
    }
}

impl<T> Deref for Key<T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*self.0 }
    }
}

impl<T> DerefMut for Key<T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.0 }
    }
}

impl<T> Default for Key<T> where T: Default {
    fn default() -> Key<T> {
        Key::from(T::default())
    }
}

impl<T> Clone for Key<T> where T: Clone {
    fn clone(&self) -> Key<T> {
        unsafe { Key::from((*self.0).clone()) }
    }
}

impl<T> fmt::Debug for Key<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "** tmp key **")
    }
}

impl<T: Sized> PartialEq<T> for Key<T> {
    /// Constant time eq.
    ///
    /// NOTE, it compare memory value.
    fn eq(&self, rhs: &T) -> bool {
        unsafe { memeq(self.0, rhs, mem::size_of::<T>()) }
    }
}

impl<T: Sized> PartialEq<Key<T>> for Key<T> {
    /// Constant time eq.
    ///
    /// NOTE, it compare memory value.
    fn eq(&self, rhs: &Key<T>) -> bool {
        self.eq(rhs as &T)
    }
}

impl<T: Sized> Eq for Key<T> {}

impl<T> PartialOrd<T> for Key<T> {
    /// Constant time cmp.
    ///
    /// NOTE, it compare memory value.
    fn partial_cmp(&self, rhs: &T) -> Option<Ordering> {
        let order = unsafe {
            memcmp(self.0, rhs, mem::size_of::<T>())
        };
        Some(order.cmp(&0))
    }
}

impl<T> PartialOrd<Key<T>> for Key<T> {
    fn partial_cmp(&self, rhs: &Key<T>) -> Option<Ordering> {
        self.partial_cmp(rhs as &T)
    }
}

impl<T> Ord for Key<T> {
    fn cmp(&self, rhs: &Key<T>) -> Ordering {
        self.partial_cmp(rhs).unwrap()
    }
}

impl<T> Drop for Key<T> where T: Sized {
    fn drop(&mut self) {
        unsafe {
            ptr::drop_in_place(self.0);
            munlock(self.0, mem::size_of::<T>());
        }
    }
}
