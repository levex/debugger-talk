use std::env;
use std::io;
mod ptrace;
mod target;
use target::*;
use std::io::Write;
extern crate libc;

fn usage(name: &String) {
    println!("talkDbg -- a simple debugger written at linux.conf.au 2018");
    println!("                ... and some beforehand");
    println!("                Licensed under the MIT license");
    println!("                Author: Levente Kurusa <lkurusa@acm.org>");
    println!("");
    println!("Usage: {} EXEC - runs EXEC and attaches to it", name);
}

fn input_loop(prg: &mut TargetProgram) {
    loop {
        println!("Target stopped, please enter a command, or 'h' for help");
        print!("(talkDbg) ");
        std::io::stdout().flush();
        let mut reader = io::stdin();
        let mut input = String::new();
        reader.read_line(&mut input).ok().expect("DBG: couldn't read from console");

        if input.trim() == "h" {
            println!("s - run & wait until next syscall");
            println!("c - continue until next breakpoint");
        } else if input.trim() == "c" {
            prg.cont();
        } else if input.trim() == "s" {
            /* continue and wait for next syscall */
            prg.continue_and_wait_until_next_syscall();

            /* the child was blocked, time to read the first syscall # */
            let orig_eax = prg.read_user(libc::ORIG_RAX)
                    .ok()
                    .expect("DBG: FATAL: ptrace failed to read the RAX register");

            println!("DBG: Target invoked system call {}", orig_eax);

            if orig_eax == -1 || orig_eax == 60 || orig_eax == 231 {
                println!("DBG: Target has exited");
                break;
            }
        }
    }
}

fn target_start(target: &String) {
    let target_pid: libc::pid_t;
    unsafe {
        target_pid = libc::fork();
    }

    let mut prg: TargetProgram = TargetProgram::new(target_pid, target);

    /* FIXME: handle when the fork fails */
    if target_pid == 0 {

        println!("TRG: running {}", target);
        prg.run();

        return;
    } else {
        /* this is the debugger instance */
        println!("DBG: debugger attaching to pid {}", target_pid);

        /* wait for the first stop... */
        prg.wait();

        /* then start the input loop */
        input_loop(&mut prg);
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
