use std::ffi::CStr;
use std::ffi::CString;
use std::fs::File;
use std::io::Error;
use std::os::unix::fs::FileExt;
use std::os::unix::io::AsRawFd;
type Errno = i32;

struct Device {
    from: &'static str,
    major: u32,
    minor: u32,
}

const ALLOWED_DEVICES: [Device; 5] = [
    Device {
        from: "/dev/null",
        major: 1,
        minor: 3,
    },
    Device {
        from: "/dev/zero",
        major: 1,
        minor: 5,
    },
    Device {
        from: "/dev/full",
        major: 1,
        minor: 7,
    },
    Device {
        from: "/dev/random",
        major: 1,
        minor: 8,
    },
    Device {
        from: "/dev/urandom",
        major: 1,
        minor: 9,
    },
];

pub fn handle_mknodat_request(req: &mut nc::seccomp_notif_t) -> Result<bool, Errno> {
    match handle_mknod_internal(0, 1, 2, 3, req) {
        Ok(_) => Ok(false),
        Err(errno) => {
            if errno == libc::EPERM {
                Ok(true)
            } else {
                Err(errno)
            }
        }
    }
}

pub fn handle_mknod_request(req: &mut nc::seccomp_notif_t) -> Result<bool, Errno> {
    match handle_mknod_internal(-1, 0, 1, 2, req) {
        Ok(_) => Ok(false),
        Err(errno) => {
            if errno == libc::EPERM {
                Ok(true)
            } else {
                Err(errno)
            }
        }
    }
}

fn handle_mknod_internal(
    dirfd: isize,
    path_arg: usize,
    mode_arg: usize,
    dev_arg: usize,
    req: &mut nc::seccomp_notif_t,
) -> Result<u32, Errno> {
    let mut fname_buffer = vec![0; libc::PATH_MAX as usize];

    let fd = File::open(format!("/proc/{}/mem", req.pid))
        .map_err(|e| e.raw_os_error().unwrap_or(libc::EINVAL))?;
    fd.read_at(&mut fname_buffer, req.data.args[path_arg])
        .map_err(|_| {
            Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EINVAL)
        })?;

    let len = match fname_buffer.iter().position(|&x| x == 0) {
        Some(s) => s,
        None => {
            return Err(libc::EINVAL);
        }
    };
    let filename = CString::new(&fname_buffer[0..len]).map_err(|_| libc::EINVAL)?;

    // Only char devices are allowed
    if (req.data.args[mode_arg] as u32 & libc::S_IFMT) != libc::S_IFCHR {
        return Err(libc::EPERM);
    }
    let mode = (req.data.args[mode_arg] & 01777) as u32;

    let major = ((req.data.args[dev_arg] >> 8) & 0xFF) as u32;
    let minor = (req.data.args[dev_arg] & 0xFF) as u32;
    let present: &Device = match ALLOWED_DEVICES
        .iter()
        .find(|&x| x.major == major && x.minor == minor)
    {
        Some(x) => x,
        None => {
            return Err(libc::EPERM);
        }
    };

    let mut hdr = nc::cap_user_header_t {
        version: nc::LINUX_CAPABILITY_VERSION_3 as u32,
        pid: req.pid as i32,
    };
    let mut udata = nc::cap_user_data_t {
        permitted: 0,
        effective: 0,
        inheritable: 0,
    };
    nc::capget(&mut hdr, &mut udata)?;

    // The process has no CAP_MKNOD
    let has_cap_mknod = udata.effective & (1 << nc::types::CAP_MKNOD) != 0;
    if !has_cap_mknod {
        return Err(libc::EPERM);
    }

    let from = CString::new(present.from).map_err(|_| libc::EINVAL)?;

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EINVAL));
    }
    if pid == 0 {
        let mut sigset: libc::sigset_t = unsafe { std::mem::zeroed() };
        if unsafe { libc::sigfillset(&mut sigset) } < 0 {
            unsafe {
                libc::exit(
                    Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(libc::EINVAL),
                )
            };
        }
        if unsafe { libc::sigprocmask(libc::SIG_BLOCK, &mut sigset, std::ptr::null_mut()) } < 0 {
            unsafe {
                libc::exit(
                    Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(libc::EINVAL),
                )
            };
        }

        let cwd_fd: File = if dirfd < 0 {
            File::open(format!("/proc/{}/cwd", req.pid))
        } else {
            File::open(format!(
                "/proc/{}/fd/{}",
                req.pid, req.data.args[dirfd as usize]
            ))
        }
        .unwrap_or_else(|err| unsafe { libc::exit(err.raw_os_error().unwrap_or(libc::EINVAL)) });
        match do_mount_in_mountns(cwd_fd.as_raw_fd(), &filename, mode, &from, req) {
            Ok(_) => {
                unsafe { libc::exit(0) };
            }
            Err(errno) => {
                unsafe { libc::exit(errno) };
            }
        }
    }

    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    let mut status: i32 = 0;
    if unsafe { libc::wait4(pid, &mut status, 0, &mut usage) } < 0 {
        return Err(Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EINVAL));
    }

    let retcode = ((status) & 0xff00) >> 8;
    if retcode != 0 {
        return Err(retcode);
    }

    Ok(0)
}

fn do_mount_in_mountns(
    cwd_fd: i32,
    to: &CStr,
    mode: u32,
    from: &CStr,
    req: &mut nc::seccomp_notif_t,
) -> Result<u32, Errno> {
    let fd = File::open(format!("/proc/{}/ns/user", req.pid))
        .map_err(|e| e.raw_os_error().unwrap_or(libc::EINVAL))?;
    if unsafe { libc::setns(fd.as_raw_fd(), 0) } < 0 {
        let err = Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EINVAL);
        if err != libc::EINVAL {
            return Err(err);
        }
    }

    let fd = File::open(format!("/proc/{}/ns/mnt", req.pid))
        .map_err(|e| e.raw_os_error().unwrap_or(libc::EINVAL))?;
    if unsafe { libc::setns(fd.as_raw_fd(), 0) } < 0 {
        let err = Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EINVAL);
        if err != libc::EINVAL {
            return Err(err);
        }
    }

    if unsafe { libc::fchdir(cwd_fd) } < 0 {
        return Err(Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EINVAL));
    }

    let fd = unsafe {
        libc::open(
            to.as_ptr(),
            libc::O_RDWR | libc::O_EXCL | libc::O_CREAT | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err(Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EINVAL));
    }
    if unsafe { libc::close(fd) } < 0 {
        return Err(Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EINVAL));
    }

    let flags = libc::MS_BIND | libc::MS_SLAVE;
    let ret = unsafe {
        libc::mount(
            from.as_ptr(),
            to.as_ptr(),
            std::ptr::null(),
            flags,
            std::ptr::null(),
        )
    };
    if ret < 0 {
        return Err(Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EINVAL));
    }

    Ok(0)
}
