#![allow(dead_code)]

pub mod compute;

pub type BpfPtr = *const core::ffi::c_void;
pub type U32 = u32;

#[repr(C)]
pub struct BpfProg {
    _private: [u8; 0],
}

#[repr(C)]
pub union BpfAttr {
    pub _raw: u64,
}

pub fn bpf_check(
    _prog: *mut *mut BpfProg,
    _attr: *mut BpfAttr,
    _uattr: BpfPtr,
    _uattr_size: U32,
) -> i32 {
    0
}
