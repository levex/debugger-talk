extern crate libc;
use std;
use std::ffi::{CString};

use super::ptrace;

#[derive(PartialEq, Eq)]
pub enum ProgramState {
    Fresh,
    Running,
    Stopped,
    Failed,
    Exited,
}

pub const PRG_FLAG_IN_SYSCALL: u32 = (1 << 0);

pub struct TargetProgram {
    pub target_pid: i32,
    pub target_executable: String,
    pub state: ProgramState,
    pub flags: u32,
}

impl TargetProgram {

    pub fn new(target_pid: i32, target: &String) -> TargetProgram {
        return TargetProgram {
            target_pid: target_pid,
            target_executable: (*target).clone(),
            state: ProgramState::Fresh,
            flags: 0,
        }
    }

    pub fn run(&mut self) {
        unsafe {
            /* tell the kernel that we want to be traced */
            ptrace::trace_me();

            /* create a C String version of the target */
            let ctarget_m = CString::new((self.target_executable).clone()).unwrap();
            let ctarget = ctarget_m.as_ptr();

            /* prepare the argv */
            let mut vec_argv: Vec<*const i8> = Vec::new();
            vec_argv.push(ctarget);
            vec_argv.push(std::ptr::null());

            /* prepare the environment */
            let mut vec_envv: Vec<*const i8> = Vec::new();
            vec_envv.push(CString::new("HOME=/vagrant").unwrap().as_ptr());
            vec_envv.push(std::ptr::null());

            self.state = ProgramState::Running;

            /* start the application */
            let ret = libc::execve(ctarget, vec_argv.as_ptr(), vec_envv.as_ptr());

            self.state = ProgramState::Failed;

            /* oops, it failed to run */
            println!("TRG: failed to run, exited with err {} and errno {}", ret, *libc::__errno_location());
        }
    }

    pub fn wait(&self) {
        unsafe {
            /* wait for the next ptrace induced block */
            libc::wait(std::ptr::null_mut());
        }
    }

    pub fn read_user(&mut self, reg_id: i32) -> Result<i64, i32> {
        return ptrace::read_user(self.target_pid, reg_id);
    }

    pub fn cont(&mut self) {
        self.state = ProgramState::Running;
        ptrace::cont(self.target_pid);
    }

    pub fn continue_until_next_syscall(&mut self) {
        ptrace::continue_until_next_syscall(self.target_pid);
        self.state = ProgramState::Running;
    }

    pub fn continue_and_wait_until_next_syscall(&mut self) {
        ptrace::continue_and_wait_until_next_syscall(self.target_pid);
        self.state = ProgramState::Stopped;
    }
}
