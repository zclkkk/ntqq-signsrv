use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::path::Path;

use crate::error::AppError;

type SignFunc = unsafe extern "C" fn(
    cmd: *const c_char,
    src: *const u8,
    src_len: u32,
    seq: i32,
    out: *mut u8,
) -> i64;

#[repr(C)]
struct DlPhdrInfo {
    dlpi_addr: usize,
    dlpi_name: *const c_char,
    dlpi_phdr: *const c_void,
    dlpi_phnum: u16,
}

type DlPhdrCallback =
    unsafe extern "C" fn(info: *mut DlPhdrInfo, size: usize, data: *mut c_void) -> i32;

unsafe extern "C" {
    fn dl_iterate_phdr(callback: DlPhdrCallback, data: *mut c_void) -> i32;
    fn dlopen(filename: *const c_char, flags: i32) -> *mut c_void;
    fn dlerror() -> *const c_char;
}

const RTLD_LAZY: i32 = 0x00001;
const RTLD_GLOBAL: i32 = 0x00100;

unsafe extern "C" fn find_wrapper_base(
    info: *mut DlPhdrInfo,
    _size: usize,
    data: *mut c_void,
) -> i32 {
    unsafe {
        let info = &*info;
        let name = CStr::from_ptr(info.dlpi_name).to_string_lossy();
        if name.contains("wrapper.node") {
            *(data as *mut usize) = info.dlpi_addr;
            return 1;
        }
        0
    }
}

pub struct Signer {
    func: SignFunc,
    _lib_handle: *mut c_void,
}

unsafe impl Send for Signer {}
unsafe impl Sync for Signer {}

impl Signer {
    pub fn load(runtime_app: &Path, sign_offset: usize) -> Result<Self, AppError> {
        let app_dir = runtime_app.to_str()
            .ok_or_else(|| AppError::Config("runtime/app path is not valid UTF-8".into()))?;

        // Load stub (qq_magic_napi_register)
        let stub_path = CString::new(format!("{}/../libsymbols.so", app_dir)).unwrap();
        let h = unsafe { dlopen(stub_path.as_ptr(), RTLD_LAZY | RTLD_GLOBAL) };
        if h.is_null() {
            return Err(AppError::DlOpen(format!("libsymbols.so: {}", dl_err())));
        }
        tracing::info!("loaded libsymbols.so stub");

        // Preload libgnutls (libbugly.so has bundled curl using GnuTLS)
        let gnutls = CString::new("libgnutls.so.30").unwrap();
        let h = unsafe { dlopen(gnutls.as_ptr(), RTLD_LAZY | RTLD_GLOBAL) };
        if h.is_null() {
            tracing::warn!("libgnutls.so.30 not found (may be unnecessary): {}", dl_err());
        }

        // Load wrapper.node
        let wrapper_path = CString::new(format!("{}/wrapper.node", app_dir)).unwrap();
        let lib_handle = unsafe { dlopen(wrapper_path.as_ptr(), RTLD_LAZY) };
        if lib_handle.is_null() {
            return Err(AppError::DlOpen(format!("wrapper.node: {}", dl_err())));
        }
        tracing::info!("loaded wrapper.node");

        // Find base address via dl_iterate_phdr
        let mut base: usize = 0;
        let ret = unsafe { dl_iterate_phdr(find_wrapper_base, &mut base as *mut _ as *mut c_void) };
        if ret == 0 || base == 0 {
            return Err(AppError::DlOpen("wrapper.node base address not found".into()));
        }
        tracing::info!("wrapper.node base: 0x{:x}", base);

        // Calculate sign function address
        let sign_addr = base + sign_offset;
        let func: SignFunc = unsafe { std::mem::transmute(sign_addr) };
        tracing::info!("sign function at 0x{:x}", sign_addr);

        Ok(Signer { func, _lib_handle: lib_handle })
    }

    pub fn sign(&self, cmd: &str, src: &[u8], seq: i32) -> ([u8; 768], i64) {
        let c_cmd = CString::new(cmd).unwrap();
        let mut out = [0u8; 768];
        let ret = unsafe {
            (self.func)(c_cmd.as_ptr(), src.as_ptr(), src.len() as u32, seq, out.as_mut_ptr())
        };
        (out, ret)
    }
}

fn dl_err() -> String {
    unsafe {
        let ptr = dlerror();
        if ptr.is_null() {
            "unknown error".to_string()
        } else {
            CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    }
}
