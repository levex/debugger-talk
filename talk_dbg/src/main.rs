use std::env;
use std::io;
use std::mem::transmute;
mod ptrace;
mod target;
use target::*;
use std::io::Write;
extern crate libc;
extern crate capstone;
use capstone::*;
use capstone::arch::*;

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
        if should_prompt {
            print!("(talkDbg) ");
            std::io::stdout().flush().ok().expect("DBG: failed to flush stdout");
            reader.read_line(&mut input).ok().expect("DBG: couldn't read from console");
        }

        if input.trim().len() == 0 {
            input = last_input.clone();
        } else {
            last_input = String::from(input.trim().clone());
        }

        if input.trim() == "h" {
            println!("Welcome to talkDbg, below are the commands you can use:");
            println!("");
            println!("s - singlestep");
            println!("y - run & wait until next syscall");
            println!("r - dump registers");
            println!("c - continue until next breakpoint");
            println!("h - show this help");
            println!("q - quit");
        } else if input.trim() == "s" {
            prg.singlestep();
            prg.wait();
            let rip = prg.read_user(libc::RIP).ok().expect("DBG: FATAL: failed to read a register");
            let rsp = prg.read_user(libc::RSP).ok().expect("DBG: FATAL: failed to read a register");
            let rbp = prg.read_user(libc::RBP).ok().expect("DBG: FATAL: failed to read a register");

            /* TODO: disassemble instruction */
            let mut instruction: [u8; 16] = [0x90; 16];

            unsafe {
                let rawtop = libc::ptrace(libc::PTRACE_PEEKTEXT, prg.target_pid, rip, 0);
                let top: [u8; 8] = transmute(rawtop.to_le());

                let rawbot = libc::ptrace(libc::PTRACE_PEEKTEXT, prg.target_pid, rip + 8, 0);
                let bot: [u8; 8] = transmute(rawbot.to_le());

                instruction[0..8].copy_from_slice(&top);
                instruction[8..].copy_from_slice(&bot);
            }

            let cs = Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .syntax(arch::x86::ArchSyntax::Att)
                .detail(true)
                .build().ok().expect("Failed to construct capstone disassembler");
            let insns = cs.disasm_count(&instruction, rip as u64, 1).ok().expect("Unknown instruction");
            for i in insns.iter() {
                println!("{}", i);
            }

            println!("RIP: 0x{:016x} RSP: 0x{:016x} RBP: 0x{:016x}", rip, rsp, rbp);
        } else if input.trim() == "c" {
            prg.cont();
            prg.wait();
            /* we don't support breakpoints, so this must mean it exited */
            prg.state = ProgramState::Exited;
            break;
        } else if input.trim() == "r" {
            let (rax, rbx, rcx, rdx);
            let (r15, r14, r13, r12, r11, r10, r9, r8);
            let (rsp, rbp, rsi, rdi);
            let (rip, cs, eflags, ss, ds, es, fs, gs);

            /* generated with Vim, should use PTRACE_GETREGS */
            rax = prg.read_user(libc::RAX).ok().expect("DBG: FATAL: failed to read a register");
            rbx = prg.read_user(libc::RBX).ok().expect("DBG: FATAL: failed to read a register");
            rcx = prg.read_user(libc::RCX).ok().expect("DBG: FATAL: failed to read a register");
            rdx = prg.read_user(libc::RDX).ok().expect("DBG: FATAL: failed to read a register");

            r15 = prg.read_user(libc::R15).ok().expect("DBG: FATAL: failed to read a register");
            r14 = prg.read_user(libc::R14).ok().expect("DBG: FATAL: failed to read a register");
            r13 = prg.read_user(libc::R13).ok().expect("DBG: FATAL: failed to read a register");
            r12 = prg.read_user(libc::R12).ok().expect("DBG: FATAL: failed to read a register");
            r11 = prg.read_user(libc::R11).ok().expect("DBG: FATAL: failed to read a register");
            r10 = prg.read_user(libc::R10).ok().expect("DBG: FATAL: failed to read a register");
            r9 = prg.read_user(libc::R9).ok().expect("DBG: FATAL: failed to read a register");
            r8 = prg.read_user(libc::R8).ok().expect("DBG: FATAL: failed to read a register");

            rsp = prg.read_user(libc::RSP).ok().expect("DBG: FATAL: failed to read a register");
            rbp = prg.read_user(libc::RBP).ok().expect("DBG: FATAL: failed to read a register");
            rsi = prg.read_user(libc::RSI).ok().expect("DBG: FATAL: failed to read a register");
            rdi = prg.read_user(libc::RDI).ok().expect("DBG: FATAL: failed to read a register");

            rip = prg.read_user(libc::RIP).ok().expect("DBG: FATAL: failed to read a register");
            cs = prg.read_user(libc::CS).ok().expect("DBG: FATAL: failed to read a register");
            eflags = prg.read_user(libc::EFLAGS).ok().expect("DBG: FATAL: failed to read a register");
            ss = prg.read_user(libc::SS).ok().expect("DBG: FATAL: failed to read a register");
            ds = prg.read_user(libc::DS).ok().expect("DBG: FATAL: failed to read a register");
            es = prg.read_user(libc::ES).ok().expect("DBG: FATAL: failed to read a register");
            fs = prg.read_user(libc::FS).ok().expect("DBG: FATAL: failed to read a register");
            gs = prg.read_user(libc::GS).ok().expect("DBG: FATAL: failed to read a register");

            println!("RAX: 0x{:016x} RBX: 0x{:016x} RCX: 0x{:016x} RDX: 0x{:016x}", rax, rbx, rcx, rdx);
            println!("R15: 0x{:016x} R14: 0x{:016x} R13: 0x{:016x} R12: 0x{:016x}", r15, r14, r13, r12);
            println!("R11: 0x{:016x} R10: 0x{:016x} R9:  0x{:016x} R8:  0x{:016x}", r11, r10, r9, r8);
            println!("RSP: 0x{:016x} RBP: 0x{:016x} RSI: 0x{:016x} RDI: 0x{:016x}", rsp, rbp, rsi, rdi);
            println!("RIP: 0x{:016x} CS: 0x{:04x} EFLAGS: 0x{:08x}", rip, cs, eflags);
            println!("SS: 0x{:04x} DS: 0x{:04x} ES: 0x{:04x} FS: 0x{:04x} GS: 0x{:04x}", ss, ds, es, fs, gs);
        } else if input.trim() == "y" {
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

                print!("DBG: Target invoked system call {}", orig_eax);

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
        } else if input.trim() == "q" {
            prg.kill();
            break;
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
