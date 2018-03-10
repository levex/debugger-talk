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
    println!("talkDbg -- a simple debugger written at SCALE 16x");
    println!("                ... and some beforehand");
    println!("                Licensed under the MIT license");
    println!("                Author: Levente Kurusa <lkurusa@acm.org>");
    println!("");
    println!("Usage: {} EXEC - runs EXEC and attaches to it", name);
}

fn disassemble_at(target_pid: i32, rip: u64) -> String {
        let mut instruction: [u8; 16] = [0x90; 16];

        unsafe {
            let rawtop = libc::ptrace(libc::PTRACE_PEEKTEXT, target_pid, rip, 0);
            let top: [u8; 8] = transmute(rawtop.to_le());

            let rawbot = libc::ptrace(libc::PTRACE_PEEKTEXT, target_pid, rip + 8, 0);
            let bot: [u8; 8] = transmute(rawbot.to_le());

            instruction[0..8].copy_from_slice(&top);
            instruction[8..].copy_from_slice(&bot);
        }

        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Att)
            .detail(true)
            .build()
            .ok()
            .expect("Failed to construct capstone disassembler");

        //println!("disassembling: {:?}", instruction);

        let insns = cs.disasm_count(&instruction, rip, 1).ok().expect("Unknown instruction");
        return format!("{}", insns.iter().nth(0).expect("no instruction"));
}

fn print_short_state(prg: &mut TargetProgram) {
    let regs = prg.get_user_struct().regs;

    println!("{}", disassemble_at(prg.target_pid, regs.rip));
    println!("RIP: 0x{:016x} RSP: 0x{:016x} RBP: 0x{:016x}",
                regs.rip, regs.rsp, regs.rbp);
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
            println!("b $addr - set a breakpoint at $addr");
            println!("lsb - list breakpoints");
            println!("h - show this help");
            println!("q - quit");
        } else if input.trim() == "s" {
            prg.singlestep();
            prg.wait();

            print_short_state(prg);
        } else if input.trim() == "c" {
            prg.cont();
            let status: libc::c_int = prg.wait() as libc::c_int;

            unsafe {
                if libc::WIFEXITED(status) {
                    /* we don't support breakpoints, so this must mean it exited */
                    prg.state = ProgramState::Exited;
                    break;
                } else if libc::WIFSTOPPED(status) {
                    prg.handle_breakpoint();
                    print_short_state(prg);
                } else {
                    panic!("Something odd happened");
                }
            }
        } else if input.trim() == "r" {
            let regs = prg.get_user_struct().regs;

            println!("RAX: 0x{:016x} RBX: 0x{:016x} RCX: 0x{:016x} RDX: 0x{:016x}",
                        regs.rax, regs.rbx, regs.rcx, regs.rdx);
            println!("R15: 0x{:016x} R14: 0x{:016x} R13: 0x{:016x} R12: 0x{:016x}",
                        regs.r15, regs.r14, regs.r13, regs.r12);
            println!("R11: 0x{:016x} R10: 0x{:016x} R9:  0x{:016x} R8:  0x{:016x}",
                        regs.r11, regs.r10, regs.r9, regs.r8);
            println!("RSP: 0x{:016x} RBP: 0x{:016x} RSI: 0x{:016x} RDI: 0x{:016x}",
                        regs.rsp, regs.rbp, regs.rsi, regs.rdi);
            println!("RIP: 0x{:016x} CS: 0x{:04x} EFLAGS: 0x{:08x}",
                        regs.rip, regs.cs, regs.eflags);
            println!("SS: 0x{:04x} DS: 0x{:04x} ES: 0x{:04x} FS: 0x{:04x} GS: 0x{:04x}",
                        regs.ss, regs.ds, regs.es, regs.fs, regs.gs);
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
        } else if input.trim().starts_with("b ") {
            let address: String = input.trim().chars().skip(4).collect();
            let addr: u64 = u64::from_str_radix(&address, 16).unwrap();

            prg.set_breakpoint(addr);
            println!("Breakpoint set at 0x{:016x}!", addr);
        } else if input.trim() == "lsb" {
            prg.list_breakpoints();
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
