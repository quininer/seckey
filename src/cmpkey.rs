use core::{ fmt, mem };
use core::cmp::{ self, Ordering };
use memsec::{ memeq, memcmp };


/// Constant Time Compare
///
/// # Note
///
/// it compare memory value.
pub struct CmpKey<T: ?Sized + 'static>(pub T);


impl<T: ?Sized> CmpKey<T> {
    pub fn from(t: &T) -> &CmpKey<T> {
        unsafe { mem::transmute(t) }
    }
}


impl<T: ?Sized> fmt::Debug for CmpKey<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("CmpKey")
            .field(&format_args!("{:p}", &self.0))
            .finish()
    }
}


impl<T: ?Sized> PartialEq<T> for CmpKey<T> {
    fn eq(&self, rhs: &T) -> bool {
        let len1 = mem::size_of_val(&self.0);
        let len2 = mem::size_of_val(rhs);

        let r = unsafe { memeq(
            &self.0 as *const T as *const u8,
            rhs as *const T as *const u8,
            cmp::min(len1, len2)
        ) };
        len1 == len2 && r
    }
}

impl<T: ?Sized> PartialEq<CmpKey<T>> for CmpKey<T> {
    fn eq(&self, &CmpKey(ref rhs): &CmpKey<T>) -> bool {
        self.eq(rhs)
    }
}

impl<T: ?Sized> Eq for CmpKey<T> {}

impl<T: ?Sized> PartialOrd<T> for CmpKey<T> {
    fn partial_cmp(&self, rhs: &T) -> Option<Ordering> {
        self.partial_cmp(CmpKey::from(rhs))
    }
}

impl<T: ?Sized> PartialOrd<CmpKey<T>> for CmpKey<T> {
    fn partial_cmp(&self, rhs: &CmpKey<T>) -> Option<Ordering> {
        Some(self.cmp(rhs))
    }
}

impl<T: ?Sized> Ord for CmpKey<T> {
    fn cmp(&self, &CmpKey(ref rhs): &CmpKey<T>) -> Ordering {
        let len1 = mem::size_of_val(&self.0);
        let len2 = mem::size_of_val(rhs);

        let order = unsafe { memcmp(
            &self.0 as *const T as *const u8,
            rhs as *const T as *const u8,
            cmp::min(len1, len2))
        };

        let r = len1.cmp(&len2);
        match order.cmp(&0) {
            Ordering::Equal => r,
            order => order
        }
    }
}
