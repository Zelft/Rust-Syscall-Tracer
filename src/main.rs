use libc::{c_void, user_regs_struct, PT_NULL};
use nix::sys::ptrace;
use nix::sys::ptrace::*;
use nix::sys::wait::waitpid;
use std::collections::HashMap;
use std::mem;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::ptr;
use std::io;
use std::io::prelude::*;
use std::time::Instant;

mod system_calls;


fn main() {

    let argv: Vec<_> = std::env::args().collect();
    let mut progArguments : Vec<String > = vec![];
    let optionv = String::from("-v");
    let optionV = String::from("-V");
    let mut v_option : bool = false;
    let mut V_option : bool = false;
    let mut first : bool = false;

    let mut cmd = Command :: new(&argv[0]); //::new(&argv[0]);
    for i in argv {
        if i!="-v" && i!="-V" && i!="rastreador" && i!="./rastreador" && first==false{
            println!("Prog: {}",i);
            cmd = Command::new(i);
            first=true;
        }
        else if i!="-v" && i!="-V" && i!="rastreador" && i!="./rastreador" && first==true{
            println!("argumento {}",i);
            cmd.arg(i);
        }
        else if i=="-v"{
            println!("Opcion -v");
            v_option = true;
        }else if i=="-V"{
            println!("Opcion -V");
            V_option = true;
        } 
    }


    //Hashmap to store the count call, can compare to strace for numbers!
    let mut map = HashMap::new();

    //allow the child to be traced
    // let output = cmd.before_exec(traceme);

    // let mut child = cmd.spawn().expect("child process failed");

    // let pid = nix::unistd::Pid::from_raw(child.id() as libc::pid_t);
    let pid = getProcessId(cmd);

    //allow parent to be stopped everytime there is a SIGTRAP sent because a syscall happened.
    ptrace::setoptions(
        pid,
        Options::PTRACE_O_TRACESYSGOOD | Options::PTRACE_O_TRACEEXEC,
    )
    .unwrap();

    waitpid(pid, None);

    /// Whether we are exiting (rather than entering) a syscall.
    /// ptrace is stopped both times when exiting and entering a syscall, we only
    /// need to stop once.  
    let mut exit = true;

    if(V_option==true){
        loop {
            let start = Instant::now();
            //get the registers from the address where ptrace is stopped.
            let regs = match get_regs(pid) {
                Ok(x) => x,
                Err(err ) => {
                    eprintln!("End of ptrace {:?}", err);
                    break;
                }
            };
            // do stuff
            
            let elapsed = start.elapsed();
    
            // Debug format
            //println!("Init: {:?}", start.());
    
            // Format as milliseconds rounded down
            // Since Rust 1.33:
            //println!("Fin: {:?}", elapsed.as_secs_f64());
            //println!("{:?}", regs.eflags);
            //pause();
            if exit {
                /// syscall number is stored inside orig_rax register. Transalte from number
                /// to syscall name using an array that stores all syscalls.  
                let mut syscallName = system_calls::SYSTEM_CALL_NAMES[(regs.orig_rax) as usize];
    
                println!("{}", &syscallName);
                //println!("{} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} ",elapsed.as_secs_f64(),regs.r15, regs.r14,regs.r13, regs.r12,regs.r11, regs.r10,regs.r9,regs.r8,regs.rbp,regs.rbx,regs.rax,regs.rcx,regs.rdx,regs.rsi,regs.rdi);
                pause();
                match map.get(&syscallName) {
                    
                    Some(&number) => map.insert(syscallName, number + 1),
                    _ => map.insert(syscallName, 1),
                };
            }
    
            unsafe {
                ptrace(
                    Request::PTRACE_SYSCALL,
                    pid,
                    ptr::null_mut(),
                    ptr::null_mut(),
                );
            }
    
            waitpid(pid, None);
            exit = !exit;
        }
    }else if(v_option==true){
        loop {
            let start = Instant::now();
            //get the registers from the address where ptrace is stopped.
            let regs = match get_regs(pid) {
                Ok(x) => x,
                Err(err ) => {
                    eprintln!("End of ptrace {:?}", err);
                    break;
                }
            };
            // do stuff
            
            let elapsed = start.elapsed();
    
            // Debug format
            //println!("Init: {:?}", start.());
    
            // Format as milliseconds rounded down
            // Since Rust 1.33:
            //println!("Fin: {:?}", elapsed.as_secs_f64());
            //println!("{:?}", regs.eflags);
            //pause();
            if exit {
                /// syscall number is stored inside orig_rax register. Transalte from number
                /// to syscall name using an array that stores all syscalls.  
                let mut syscallName = system_calls::SYSTEM_CALL_NAMES[(regs.orig_rax) as usize];
    
                //println!("{}", &syscallName);
                //println!("{} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} ",elapsed.as_secs_f64(),regs.r15, regs.r14,regs.r13, regs.r12,regs.r11, regs.r10,regs.r9,regs.r8,regs.rbp,regs.rbx,regs.rax,regs.rcx,regs.rdx,regs.rsi,regs.rdi);
                println!("{}", &syscallName);
        
                match map.get(&syscallName) {
                    
                    Some(&number) => map.insert(syscallName, number + 1),
                    _ => map.insert(syscallName, 1),
                };
            }
    
            unsafe {
                ptrace(
                    Request::PTRACE_SYSCALL,
                    pid,
                    ptr::null_mut(),
                    ptr::null_mut(),
                );
            }
    
            waitpid(pid, None);
            exit = !exit;
        }

    }else{
        loop {
            let start = Instant::now();
            //get the registers from the address where ptrace is stopped.
            let regs = match get_regs(pid) {
                Ok(x) => x,
                Err(err ) => {
                    eprintln!("End of ptrace {:?}", err);
                    break;
                }
            };
            // do stuff
            
            let elapsed = start.elapsed();
    
            // Debug format
            //println!("Init: {:?}", start.());
    
            // Format as milliseconds rounded down
            // Since Rust 1.33:
            //println!("Fin: {:?}", elapsed.as_secs_f64());
            
            if exit {
                /// syscall number is stored inside orig_rax register. Transalte from number
                /// to syscall name using an array that stores all syscalls.  
                let mut syscallName = system_calls::SYSTEM_CALL_NAMES[(regs.orig_rax) as usize];
    
                //println!("{}", &syscallName);
                //println!("{} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} ",elapsed.as_secs_f64(),regs.r15, regs.r14,regs.r13, regs.r12,regs.r11, regs.r10,regs.r9,regs.r8,regs.rbp,regs.rbx,regs.rax,regs.rcx,regs.rdx,regs.rsi,regs.rdi);
                //pause();
                match map.get(&syscallName) {
                    
                    Some(&number) => map.insert(syscallName, number + 1),
                    _ => map.insert(syscallName, 1),
                };
            }
    
            unsafe {
                ptrace(
                    Request::PTRACE_SYSCALL,
                    pid,
                    ptr::null_mut(),
                    ptr::null_mut(),
                );
            }
    
            waitpid(pid, None);
            exit = !exit;
        }
    }

    let mut counter : i32 = 0;
    let mut word_size: usize = 22 as usize;
    let mut num_usize: usize = 4 as usize;

    println!("------------------------------------------");
    println!("| System Calls         |Number|");
    println!("------------------------------------------");
    for (syscall, &number) in map.iter() {
    
        print!("|{}", syscall);
        for i in  0..(word_size - syscall.chars().count())  {
            print!(" ");
        }
        print!("| {}", number);
        for i in  0..(num_usize - number.to_string().chars().count())  {
            print!(" ");
        }
        println!(" |");
        word_size=22;
        num_usize=4;
        counter+=number;
    }
    println!("------------------------------------------\n");
    println!("Total System Calls: {}\n", counter); 
    
}

fn getProcessId(cmd:Command) -> nix::unistd::Pid{

    let mut newCmd = cmd;

    let output = newCmd.before_exec(traceme);

    let mut child = newCmd.spawn().expect("child process failed");

    let pid = nix::unistd::Pid::from_raw(child.id() as libc::pid_t);

    return pid;
}


pub fn get_regs(pid: nix::unistd::Pid) -> Result<user_regs_struct, nix::Error> {
    unsafe {
        let mut regs: user_regs_struct = mem::uninitialized();

        #[allow(deprecated)]
        let res = ptrace::ptrace(
            Request::PTRACE_GETREGS,
            pid,
            PT_NULL as *mut c_void,
            &mut regs as *mut _ as *mut c_void,
        );
        res.map(|_| regs)
    }
}


fn traceme() -> std::io::Result<(())> {
    match ptrace::traceme() {
        Ok(()) => Ok(()),
        Err(::nix::Error::Sys(errno)) => Err(std::io::Error::from_raw_os_error(errno as i32)),
        Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
    }

}

fn pause() {

    let mut stdin = io::stdin();
    let mut stdout = io::stdout();

    // We want the cursor to stay at the end of the line, so we print without a newline and flush manually.
    write!(stdout, "Press any key to continue...").unwrap();
    stdout.flush().unwrap();

    // Read a single byte and discard
    let _ = stdin.read(&mut [0u8]).unwrap();
}