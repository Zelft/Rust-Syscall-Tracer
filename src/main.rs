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
    /*
    *   Danny Andres Piedra Acuña
    *   Tarea Corta #1
    *   Rastreador de System Calls
    *   2016210168
    *   16/03/2020
    *   This Code is a modification of repository : https://github.com/gs0510/rustrace.git
    */

//This module holds the System Call Names and their corresponding Descriptions
mod system_calls;


fn main() {

    //Data Structure that holds the program arguments
    let argv: Vec<_> = std::env::args().collect();
    
    //Variable declarations used to parse the program's options 
    let mut v_option : bool = false;
    let mut V_option : bool = false;
    let mut first : bool = false;

    //Data Structure to hold the program to be execute and it's arguments
    //Code to parse the program's arguments and options
    let mut cmd = Command :: new(&argv[0]); 
    for i in argv {
        if i!="-v" && i!="-V" && i!="rastreador" && i!="./rastreador" && first==false{
            cmd = Command::new(i);
            first=true;
        }
        else if i!="-v" && i!="-V" && i!="rastreador" && i!="./rastreador" && first==true{
            cmd.arg(i);
        }
        else if i=="-v"{
            v_option = true;
        }else if i=="-V"{
            V_option = true;
        } 
    }


    //Hashmap to store the count of calls, can compare to strace for numbers!
    let mut map = HashMap::new();

    //Function Call that execute's the tracee program as a child thread and returns it's process id
    let pid = getProcessId(cmd);

    //allow parent to be stopped everytime there is a SIGTRAP sent because a syscall happened.
    ptrace::setoptions(
        pid,
        Options::PTRACE_O_TRACESYSGOOD | Options::PTRACE_O_TRACEEXEC,
    )
    .unwrap();

    //This method waits for the process to return its id
    waitpid(pid, None);

    /// Whether we are exiting (rather than entering) a syscall.
    /// ptrace is stopped both times when exiting and entering a syscall, we only
    /// need to stop once.  
    let mut exit = true;
        loop {
            //We take a timestamp
            let start = Instant::now();
            //get the registers from the address where ptrace is stopped.
            let regs = match get_regs(pid) {
                Ok(x) => x,
                Err(err ) => {
                    eprintln!("End of ptrace {:?}", err);
                    break;
                }
            };
            //We close the timestamp here in order to capture the systemcall's duration
            let elapsed = start.elapsed();

            if exit {
                /// syscall number is stored inside orig_rax register. Transalte from number
                /// to syscall name using an array that stores all syscalls.  
                /// Same index is used to index the Syscall's description
                let mut syscallName = system_calls::SYSTEM_CALL_NAMES[(regs.orig_rax) as usize];
                let mut syscallDescription = system_calls::SYSCALLS_DESCRIPTIONS[(regs.orig_rax) as usize];
                
                //Proceed to evaluate which information to present based on user's input option parsing
                if(V_option==true){
                    println!("-------------------------------------------------------------------------------------- ");
                    println!("System Call Name :{} \nSystem Call Description: {} \nSyscall Duration: {} nanoseconds. ", &syscallName, &syscallDescription, elapsed.as_nanos());
                    println!("-------------------------------------------------------------------------------------- ");
                    pause();
                }
                else if(v_option==true){
                    println!("-------------------------------------------------------------------------------------- ");
                    println!("System Call Name :{} \nSystem Call Description: {} \nSyscall Duration: {} nanoseconds. ", &syscallName, &syscallDescription, elapsed.as_nanos());
                    println!("-------------------------------------------------------------------------------------- ");
                }

                //Insertion of system call name on Hashmap
                //If systemcall already took place and for example failed, it increases the quantity to represent the number 
                //of calls made to that one Syscall 
                match map.get(&syscallName) {
                    
                    Some(&number) => map.insert(syscallName, number + 1),
                    _ => map.insert(syscallName, 1),
                };
            }
            //Unsafe instruction tells the compiler to allow the instruction configuration
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


    let mut counter : i32 = 0;
    let mut word_size: usize = 22 as usize;
    let mut num_usize: usize = 4 as usize;

    //Prints in console the System Call's Table along with their number of calls.

    println!("-------------------------------");
    println!("| System Calls         |Number|");
    println!("-------------------------------");
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
    println!("-------------------------------\n");
    println!("Total System Calls: {}\n", counter); 
    
}



//This function takes the command and its arguments and
//tells the tracer to allow this program to be traced and then proceeds to execute it.   
fn getProcessId(cmd:Command) -> nix::unistd::Pid{

    let mut newCmd = cmd;

    let output = newCmd.before_exec(traceme);

    let mut child = newCmd.spawn().expect("child process failed");

    let pid = nix::unistd::Pid::from_raw(child.id() as libc::pid_t);

    return pid;
}

//This function takes the process id and detects a SystemCall made
//through a ptrace request of type PTRACE_GETREGS and then returns a struct holding all registers involved.
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

//This function indicates that this process is to be traced by its parent. 
//This is the only ptrace request to be issued by the tracee.
fn traceme() -> std::io::Result<(())> {
    match ptrace::traceme() {
        Ok(()) => Ok(()),
        Err(::nix::Error::Sys(errno)) => Err(std::io::Error::from_raw_os_error(errno as i32)),
        Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
    }

}

// Function used to stay at the end of the line, so system prints without a newline and flushes manually.
fn pause() {

    let mut stdin = io::stdin();
    let mut stdout = io::stdout();
    
    write!(stdout, "Press enter to continue...").unwrap();
    stdout.flush().unwrap();
    let _ = stdin.read(&mut [0u8]).unwrap();
}

