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

pub fn singlestep(target_pid: i32) {
    unsafe {
        libc::ptrace(libc::PTRACE_SINGLESTEP, target_pid, 0, 0);
    }
}

pub fn cont(target_pid: i32) {
    unsafe {
        libc::ptrace(libc::PTRACE_CONT, target_pid, 0, 0);
    }
}

pub fn peek_word(target_pid: i32, addr: u64) -> Result<u64, i32> {
    unsafe {
        *libc::__errno_location() = 0;
        let word: i64 = libc::ptrace(libc::PTRACE_PEEKTEXT, target_pid, addr, 0);
        if word == -1 && *libc::__errno_location() != 0 {
            return Err(*libc::__errno_location());
        } else {
            return Ok(word as u64);
        }
    }
}

pub fn poke_word(target_pid: i32, addr: u64, data: u64) {
    unsafe {
        libc::ptrace(libc::PTRACE_POKETEXT, target_pid, addr, data);
    }
}

pub fn get_user_struct(target_pid: i32, user_struct: *mut libc::user) {
    unsafe {
        libc::ptrace(libc::PTRACE_GETREGS, target_pid, 0, user_struct);
    }
}

pub fn write_user_struct(target_pid: i32, user_struct: *const libc::user) {
    unsafe {
        libc::ptrace(libc::PTRACE_SETREGS, target_pid, 0, user_struct);
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
