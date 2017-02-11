use std::fmt;
use std::cmp::{ Ordering, min };
use std::iter::repeat;
use std::ops::{ Deref, DerefMut };
use memsec::{ memeq, memcmp, mlock, munlock };


/// Temporary Bytes.
///
/// ```
/// use seckey::Bytes;
///
/// let bytes = Bytes::new(&[8; 8]);
///
/// assert_eq!(bytes, [8; 8]);
/// ```
pub struct Bytes(Vec<u8>);

impl Bytes {
    /// Create a new Bytes.
    #[inline]
    pub fn new(input: &[u8]) -> Bytes {
        let input: Vec<u8> = input.into();
        Bytes::from(input)
    }

    /// Create a empty Bytes.
    #[inline]
    pub fn empty() -> Bytes {
        Self::default()
    }
}

impl Default for Bytes {
    fn default() -> Bytes {
        Bytes(Vec::new())
    }
}

impl From<Vec<u8>> for Bytes {
    #[inline]
    fn from(mut t: Vec<u8>) -> Bytes {
        unsafe { mlock(t.as_mut_ptr(), t.len()) };
        Bytes(t)
    }
}

impl<'a> From<&'a [u8]> for Bytes {
    #[inline]
    fn from(t: &'a [u8]) -> Bytes {
        Bytes::new(t)
    }
}

impl Deref for Bytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl DerefMut for Bytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

impl Clone for Bytes {
    fn clone(&self) -> Bytes {
        Bytes::from(self.0.clone())
    }
}

impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.len() {
            0 => write!(f, "** empty **"),
            len => write!(f, "{}", repeat('*').take(len).collect::<String>())
        }
    }
}

impl AsRef<[u8]> for Bytes {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.deref()
    }
}

impl<A: AsRef<[u8]>> PartialEq<A> for Bytes {
    fn eq(&self, rhs: &A) -> bool {
        self.eq(rhs.as_ref())
    }
}

impl PartialEq<[u8]> for Bytes {
    /// Constant time eq.
    fn eq(&self, rhs: &[u8]) -> bool {
        let output = unsafe { memeq(
            self.as_ptr(), rhs.as_ptr(),
            min(self.len(), rhs.len())
        ) };

        self.len() == rhs.len() && output
    }
}

impl Eq for Bytes {}

impl<A: AsRef<[u8]>> PartialOrd<A> for Bytes {
    fn partial_cmp(&self, rhs: &A) -> Option<Ordering> {
        self.partial_cmp(rhs.as_ref())
    }
}

impl PartialOrd<[u8]> for Bytes {
    /// Constant time cmp.
    fn partial_cmp(&self, rhs: &[u8]) -> Option<Ordering> {
        let order = unsafe { memcmp(
            self.as_ptr(), rhs.as_ptr(),
            min(self.len(), rhs.len())
        ) };
        if order == 0 {
            Some(self.len().cmp(&rhs.len()))
        } else if order < 0 {
            Some(Ordering::Less)
        } else {
            Some(Ordering::Greater)
        }
    }
}

impl Ord for Bytes {
    fn cmp(&self, rhs: &Bytes) -> Ordering {
        self.partial_cmp(rhs.as_ref()).expect("unreachable!")
    }
}

impl Drop for Bytes {
    /// When drop, it will call `munlock`.
    fn drop(&mut self) {
        unsafe { munlock(self.0.as_mut_ptr(), self.0.len()) };
    }
}
