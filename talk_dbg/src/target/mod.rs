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

#[derive(Clone)]
struct BreakpointData {
    addr: u64,
    orig_byte: u8,
}

pub struct TargetProgram {
    pub target_pid: i32,
    pub target_executable: String,
    pub state: ProgramState,
    pub flags: u32,
    breakpoints: Vec<BreakpointData>,
}

impl TargetProgram {

    pub fn new(target_pid: i32, target: &String) -> TargetProgram {
        TargetProgram {
            target_pid: target_pid,
            target_executable: (*target).clone(),
            state: ProgramState::Fresh,
            flags: 0,
            breakpoints: Vec::new(),
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

    pub fn kill(&mut self) {
        unsafe {
            libc::kill(self.target_pid, libc::SIGKILL);
        }
        self.state = ProgramState::Exited;
    }

    pub fn wait(&self) -> u32 {
        let mut status: i32 = 0;

        unsafe {
            /* wait for the next ptrace induced block */
            libc::waitpid(-1, &mut status, 0);
        }

        return status as u32;
    }

    pub fn read_user(&mut self, reg_id: i32) -> Result<i64, i32> {
        return ptrace::read_user(self.target_pid, reg_id);
    }

    pub fn singlestep(&mut self) {
        self.state = ProgramState::Running;
        ptrace::singlestep(self.target_pid);
    }

    pub fn cont(&mut self) {
        self.state = ProgramState::Running;
        ptrace::cont(self.target_pid);
    }

    pub fn continue_and_wait_until_next_syscall(&mut self) {
        ptrace::continue_and_wait_until_next_syscall(self.target_pid);
        self.state = ProgramState::Stopped;
    }

    pub fn peek_byte_at(&mut self, location: u64) -> u8 {
        /* align to 8 bytes */
        let loc = (location / 8) * 8;
        let offset = location % 8;
        let word: Result<u64, i32> = ptrace::peek_word(self.target_pid, loc);
        match word {
            Ok(w) => return ((w & (0xff << (8 * offset))) >> (8 * offset)) as u8,
            Err(err) =>
                panic!("failed to read byte at {:016x} errno: {}", loc, err),
        }
    }

    pub fn poke_byte_at(&mut self, location: u64, data: u8) {
        let loc = (location / 8) * 8;
        let offset = location % 8;
        let mut word: u64 = ptrace::peek_word(self.target_pid, loc)
            .ok()
            .expect("OOPS");
        word = (word & !(0xff << (8 * offset))) | ((data as u64) << (8 * offset));
        ptrace::poke_word(self.target_pid, loc, word);
    }

    pub fn get_user_struct(&mut self) -> libc::user {
        unsafe {
            let mut user_struct: libc::user = std::mem::uninitialized();
            ptrace::get_user_struct(self.target_pid, &mut user_struct);
            return user_struct;
        }
    }

    pub fn write_user_struct(&mut self, usr: libc::user) {
        ptrace::write_user_struct(self.target_pid, &usr);
    }

    pub fn list_breakpoints(&mut self) {
        if self.breakpoints.len() == 0 {
            println!("No breakpoints set yet");
            return;
        }
        for i in 0..self.breakpoints.len() {
            let bp: BreakpointData = self.breakpoints[i].clone();

            println!("Breakpoint {} at 0x{:016x}", i, bp.addr);
        }
    }

    pub fn set_breakpoint(&mut self, loc: u64) {
        let orig_byte: u8 = self.peek_byte_at(loc);

        /* 0xCC is the machine code int $3 */
        self.poke_byte_at(loc, 0xCC);

        self.breakpoints.push(BreakpointData {
                addr: loc,
                orig_byte: orig_byte,
        });
    }

    pub fn handle_breakpoint(&mut self) {
        let mut user: libc::user = self.get_user_struct();
        let rip: u64 = user.regs.rip - 1;

        for i in 0..self.breakpoints.len() {
            let bp = self.breakpoints[i].clone();

            if bp.addr == rip {
                self.poke_byte_at(bp.addr, bp.orig_byte);

                user.regs.rip = rip;
                self.write_user_struct(user);
                return;
            }
        }

        panic!("oops");
    }
}
