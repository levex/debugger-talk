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
