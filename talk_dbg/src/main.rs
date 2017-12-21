use std::env;
use std::ffi::{CString};
extern crate libc;

fn usage(name: &String) {
    println!("talkDbg -- a simple debugger written at linux.conf.au 2018");
    println!("                ... and some beforehand");
    println!("                Licensed under the MIT license");
    println!("                Author: Levente Kurusa <lkurusa@acm.org>");
    println!("");
    println!("Usage: {} EXEC - runs EXEC and attaches to it", name);
}

fn target_run(target: &String) {
    println!("TRG: running {}", target);

    unsafe {
        /* tell the kernel that we want to be traced */
        libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0);

        /* create a C String version of the target */
        let ctarget_m = CString::new((*target).clone()).unwrap();
        let ctarget = ctarget_m.as_ptr();

        /* prepare the argv */
        let mut vec_argv: Vec<*const i8> = Vec::new();
        vec_argv.push(ctarget);
        vec_argv.push(std::ptr::null());

        /* prepare the environment */
        let mut vec_envv: Vec<*const i8> = Vec::new();
        vec_envv.push(CString::new("HOME=/vagrant").unwrap().as_ptr());
        vec_envv.push(std::ptr::null());

        /* start the application */
        let ret = libc::execve(ctarget, vec_argv.as_ptr(), vec_envv.as_ptr());

        /* oops, it failed to run */
        println!("TRG: failed to run, exited with err {} and errno {}", ret, *libc::__errno_location());
    }
}

fn target_start(target: &String) {
    let target_pid: libc::pid_t;
    unsafe {
        target_pid = libc::fork();
    }

    /* FIXME: handle when the fork fails */
    if target_pid == 0 {
        /* this is the target process */
        target_run(target);
        return;
    } else {
        /* this is the debugger instance */
        println!("DBG: debugger attaching to pid {}", target_pid);

        unsafe {
            /* wait for the first ptrace induced block */
            libc::wait(std::ptr::null_mut());

            /* the child was blocked, time to read the first syscall # */
            let orig_eax = libc::ptrace(libc::PTRACE_PEEKUSER, target_pid, 8 * libc::ORIG_RAX, 0);

            println!("DBG: Register RAX had value {} before the target was blocked", orig_eax);

            /* let the program continue */
            libc::ptrace(libc::PTRACE_CONT, target_pid, 0, 0);

            /* wait for it to die... */
            libc::wait(std::ptr::null_mut());
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    /* if there are no arguments then show usage & exit */
    if args.len() < 2 {
        usage(&args[0]);
        return;
    }

    /* extract the target */
    let target: &String = &args[1];

    /* start the target */
    target_start(target);
}
