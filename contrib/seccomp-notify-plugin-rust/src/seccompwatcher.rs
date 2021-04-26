extern crate nc;

mod mknod;

use std::os::raw::c_char;

pub enum RunOciSeccompNotifyHandleRet {
    NotHandled,
    SendResponse,
    DelayedResponse,
    SendResponseAndContinue,
}


impl RunOciSeccompNotifyHandleRet {
    fn value(&self) -> i32 {
        match *self {
            RunOciSeccompNotifyHandleRet::NotHandled => 0,
            RunOciSeccompNotifyHandleRet::SendResponse => 1,
            RunOciSeccompNotifyHandleRet::DelayedResponse => 2,
            RunOciSeccompNotifyHandleRet::SendResponseAndContinue => 3,
        }
    }
}
type Errno = i32;

type SyscallHandler = fn(req: &mut nc::seccomp_notif_t) -> Result<bool, Errno>;

pub struct LibcrunLoadSeccompNotifyConf {
    _runtime_root_path: *const c_char,
    _name: *const c_char,
    _bundle_path: *const c_char,
    _oci_config_path: *const c_char,
}

#[no_mangle]
pub extern "C" fn run_oci_seccomp_notify_plugin_version() -> i32 {
    1
}

#[no_mangle]
pub extern "C" fn run_oci_seccomp_notify_stop(opaque: *mut core::ffi::c_void) -> i32 {
    let ptr: *mut std::collections::HashMap<usize, SyscallHandler> =
        opaque as *mut std::collections::HashMap<usize, SyscallHandler>;
    unsafe {
        Box::from_raw(ptr);
    }
    0
}

#[no_mangle]
pub extern "C" fn run_oci_seccomp_notify_start(
    opaque: *mut *mut core::ffi::c_void,
    _conf: *mut LibcrunLoadSeccompNotifyConf,
    size_configuration: usize,
) -> i32 {
    if std::mem::size_of::<LibcrunLoadSeccompNotifyConf>() != size_configuration {
        return -libc::EINVAL;
    }
    let mut handlers = Box::new(std::collections::HashMap::new());
    handlers.insert(nc::SYS_MKNOD, mknod::handle_mknod_request as SyscallHandler);
    handlers.insert(
        nc::SYS_MKNODAT,
        mknod::handle_mknodat_request as SyscallHandler,
    );

    let ptr: *mut std::collections::HashMap<usize, SyscallHandler> = Box::into_raw(handlers);

    unsafe {
        *opaque = ptr as *mut libc::c_void;
    }

    0
}

#[no_mangle]
pub extern "C" fn run_oci_seccomp_notify_handle_request(
    opaque: *mut *mut core::ffi::c_void,
    _sizes: *mut nc::seccomp_notif_sizes_t,
    sreq: *mut nc::seccomp_notif_t,
    sresp: *mut nc::seccomp_notif_resp_t,
    _seccomp_fd: i32,
    shandled: *mut i32,
) -> i32 {
    let ptr: *mut std::collections::HashMap<usize, SyscallHandler> =
        opaque as *mut std::collections::HashMap<usize, SyscallHandler>;
    let handlers = *&ptr;
    let req = unsafe { &mut *sreq };
    let resp = unsafe { &mut *sresp };
    let handled = unsafe { &mut *shandled };
    let handler_maybe = { unsafe { handlers.as_ref().unwrap().get(&(req.data.nr as usize)) } };

    *handled = RunOciSeccompNotifyHandleRet::NotHandled.value();

    if let Some(handler) = handler_maybe {
        *handled = RunOciSeccompNotifyHandleRet::SendResponse.value();
        match handler(req) {
            Ok(notify_continue) => {
                if notify_continue {
                    *handled = RunOciSeccompNotifyHandleRet::SendResponseAndContinue.value();
                }
                resp.error = 0;
            }
            Err(errno) => {
                resp.error = -errno;
            }
        }
        resp.id = req.id;
        resp.val = 0;
        return 0;
    }
    0
}
