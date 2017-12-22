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
    let mut last_input: String = String::new();
    let mut should_prompt: bool = true;

    loop {
        let reader = io::stdin();
        let mut input = String::new();
        if (should_prompt) {
            print!("(talkDbg) ");
            std::io::stdout().flush();
            reader.read_line(&mut input).ok().expect("DBG: couldn't read from console");
        }

        if input.trim().len() == 0 {
            input = last_input.clone();
        } else {
            last_input = String::from(input.trim().clone());
        }

        if input.trim() == "h" {
            println!("s - run & wait until next syscall");
            println!("c - continue until next breakpoint");
        } else if input.trim() == "c" {
            prg.cont();
            prg.wait();
            /* we don't support breakpoints, so this must mean it exited */
            prg.state = ProgramState::Exited;
            break;
        } else if input.trim() == "s" {
            /* continue and wait for next syscall */
            prg.continue_and_wait_until_next_syscall();

            /* check if we are in entry or exit */
            if (prg.flags & PRG_FLAG_IN_SYSCALL) == 0{
                /* entering a system call... */
                prg.flags |= PRG_FLAG_IN_SYSCALL;
                should_prompt = false;

                /* the child was blocked, time to read the syscall # */
                let orig_eax = prg.read_user(libc::ORIG_RAX)
                        .ok()
                        .expect("DBG: FATAL: ptrace failed to read the RAX register");

                print!("DBG: Target invoked system call {} ", orig_eax);

                if orig_eax == -1 || orig_eax == 60 || orig_eax == 231 {
                    println!("");
                    prg.state = ProgramState::Exited;
                    break;
                }
            } else {
                /* exiting a syscall */
                prg.flags &= !PRG_FLAG_IN_SYSCALL;

                /* read the result register */
                let result = prg.read_user(libc::RAX)
                    .ok()
                    .expect("DBG: FATAL: ptrace failed to read the RAX register");

                println!(" with result {}", result);
                should_prompt = true;
            }

        }
    }

    if prg.state == ProgramState::Exited {
        println!("DBG: Target has exited");
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
