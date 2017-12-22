use std;
extern crate libc;

pub fn trace_me() {
    unsafe {
        libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0);
    }
}

pub fn continue_until_next_syscall(target_pid: i32) {
    unsafe {
        libc::ptrace(libc::PTRACE_SYSCALL, target_pid, 0, 0);
    }
}

pub fn continue_and_wait_until_next_syscall(target_pid: i32) {
    continue_until_next_syscall(target_pid);
    unsafe {
        libc::wait(std::ptr::null_mut());
    }
}

pub fn cont(target_pid: i32) {
    unsafe {
        libc::ptrace(libc::PTRACE_CONT, target_pid, 0, 0);
    }
}

pub fn read_user(target_pid: i32, reg_id: i32) -> Result<i64, i32> {
    unsafe {
        /* clear errno */
        *libc::__errno_location() = 0;
        let ret = libc::ptrace(libc::PTRACE_PEEKUSER, target_pid, 8 * reg_id, 0);
        if ret == -1 && *libc::__errno_location() != 0 {
            return Err(*libc::__errno_location());
        } else {
            return Ok(ret);
        }
    }
}
