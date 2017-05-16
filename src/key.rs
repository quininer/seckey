use std::{ fmt, mem, ptr };
use std::cmp::Ordering;
use std::ops::{ Deref, DerefMut };
use memsec::{ memeq, memcmp, mlock, munlock };
#[cfg(feature = "nodrop")] use nodrop::NoDrop as ManuallyDrop;
#[cfg(not(feature = "nodrop"))] use std::mem::ManuallyDrop;


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
pub struct Key<T: Sized>(ManuallyDrop<T>);

impl<T> Key<T> {
    pub fn from(mut t: T) -> Key<T> {
        unsafe { mlock(&mut t, mem::size_of::<T>()) };
        Key(ManuallyDrop::new(t))
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

impl<T> Default for Key<T> where T: Default {
    fn default() -> Key<T> {
        Key::from(T::default())
    }
}

impl<T> Clone for Key<T> where T: Clone {
    fn clone(&self) -> Key<T> {
        Key::from(self.0.clone())
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
        unsafe { memeq(&self.0 as &T, rhs, mem::size_of::<T>()) }
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
            memcmp(&self.0 as &T, rhs, mem::size_of::<T>())
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
            ptr::drop_in_place(&mut self.0 as &mut T);
            munlock(&mut self.0 as &mut T, mem::size_of::<T>());
        }
    }
}
