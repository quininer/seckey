use core::ptr;
use core::alloc::{ GlobalAlloc, Layout };
use memsec::memzero;


#[derive(Debug, Clone, Copy, Default)]
pub struct ZeroAllocator<T>(pub T);

unsafe impl<T: GlobalAlloc> GlobalAlloc for ZeroAllocator<T> {
    #[inline(always)]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.0.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        memzero(ptr, layout.size());
        self.0.dealloc(ptr, layout)
    }

    #[inline(always)]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        self.0.alloc_zeroed(layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_layout = Layout::from_size_align(new_size, layout.align()).ok();

        let new_ptr = new_layout
            .map(|layout| self.alloc(layout))
            .unwrap_or_else(ptr::null_mut);

        if !new_ptr.is_null() {
            ptr::copy_nonoverlapping(ptr, new_ptr, layout.size());
            self.dealloc(ptr, layout);
        }

        new_ptr
    }
}
