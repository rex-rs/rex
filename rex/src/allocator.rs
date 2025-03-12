use crate::bindings::linux::kernel::{
    gfp_t, ___GFP_HIGH_BIT, ___GFP_KSWAPD_RECLAIM_BIT,
};
use crate::stub::{kfree, rex_kmalloc};
use core::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;

/// #define ___GFP_HIGH BIT(___GFP_HIGH_BIT)
const __GFP_HIGH: gfp_t = 1 << ___GFP_HIGH_BIT;

/// #define ___GFP_KSWAPD_RECLAIM BIT(___GFP_KSWAPD_RECLAIM_BIT)
const __GFP_KSWAPD_RECLAIM: gfp_t = 1 << ___GFP_KSWAPD_RECLAIM_BIT;

/// #define GFP_ATOMIC (__GFP_HIGH|__GFP_KSWAPD_RECLAIM)
const GFP_ATOMIC: gfp_t = __GFP_HIGH | __GFP_KSWAPD_RECLAIM;

pub struct RexAlloc;

unsafe impl GlobalAlloc for RexAlloc {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe {
            rex_kmalloc(layout.pad_to_align().size(), GFP_ATOMIC) as *mut u8
        }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        unsafe { kfree(ptr as *mut c_void) }
    }
}
