use std::{ fmt, mem, ptr };
use std::cmp::Ordering;
use std::ops::{ Deref, DerefMut };
use memsec::{ memeq, memcmp, mlock, munlock };


/// Temporary Key.
///
/// ```
/// use seckey::TempKey;
///
/// let key = TempKey::from([8u8; 8]);
/// assert_eq!(key, [8u8; 8]);
/// assert_ne!(key, [1u8; 8]);
/// assert_eq!(key, TempKey::from([8u8; 8]));
/// ```
pub struct TempKey<T: Sized>(*mut T);

impl<T> TempKey<T> {
    pub fn from(t: T) -> TempKey<T> {
        let box_ptr = Box::into_raw(Box::new(t));
        unsafe { mlock(box_ptr, mem::size_of::<T>()) };
        TempKey(box_ptr)
    }
}

impl<T> Deref for TempKey<T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*self.0 }
    }
}

impl<T> DerefMut for TempKey<T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.0 }
    }
}

impl<T> Default for TempKey<T> where T: Default {
    fn default() -> TempKey<T> {
        TempKey::from(T::default())
    }
}

impl<T> Clone for TempKey<T> where T: Clone {
    fn clone(&self) -> TempKey<T> {
        unsafe { TempKey::from((*self.0).clone()) }
    }
}

impl<T> fmt::Debug for TempKey<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("TempKey")
            .field(&format_args!("{:p}", self.0))
            .finish()
    }
}

impl<T: Sized> PartialEq<T> for TempKey<T> {
    /// Constant time eq.
    ///
    /// NOTE, it compare memory value.
    fn eq(&self, rhs: &T) -> bool {
        unsafe { memeq(self.0, rhs, mem::size_of::<T>()) }
    }
}

impl<T: Sized> PartialEq<TempKey<T>> for TempKey<T> {
    /// Constant time eq.
    ///
    /// NOTE, it compare memory value.
    #[inline]
    fn eq(&self, rhs: &TempKey<T>) -> bool {
        self.eq(rhs as &T)
    }
}

impl<T: Sized> Eq for TempKey<T> {}

impl<T> PartialOrd<T> for TempKey<T> {
    /// Constant time cmp.
    ///
    /// NOTE, it compare memory value.
    fn partial_cmp(&self, rhs: &T) -> Option<Ordering> {
        let order =
            unsafe { memcmp(self.0, rhs, mem::size_of::<T>()) };
        Some(order.cmp(&0))
    }
}

impl<T> PartialOrd<TempKey<T>> for TempKey<T> {
    #[inline]
    fn partial_cmp(&self, rhs: &TempKey<T>) -> Option<Ordering> {
        self.partial_cmp(rhs as &T)
    }
}

impl<T> Ord for TempKey<T> {
    #[inline]
    fn cmp(&self, rhs: &TempKey<T>) -> Ordering {
        self.partial_cmp(rhs).unwrap()
    }
}

impl<T> Drop for TempKey<T> where T: Sized {
    fn drop(&mut self) {
        unsafe {
            ptr::drop_in_place(self.0);
            munlock(self.0, mem::size_of::<T>());
        }
    }
}
