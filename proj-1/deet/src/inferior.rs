use libc::user_regs_struct;
use nix::sys::ptrace;
use nix::sys::signal;
use nix::sys::signal::Signal::SIGTRAP;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::File;
use std::io::Error;
use std::io::{self, BufRead};
use std::mem::size_of;
use std::os::unix::process::CommandExt;
use std::process::Child;
use std::process::Command;

use crate::dwarf_data::DwarfData;
use crate::dwarf_data::Type;
use crate::dwarf_data::Variable;

pub enum Status {
    /// Indicates inferior stopped. Contains the signal that stopped the process, as well as the
    /// current instruction pointer that it is stopped at.
    Stopped(signal::Signal, usize),

    /// Indicates inferior exited normally. Contains the exit status code.
    Exited(i32),

    /// Indicates the inferior exited due to a signal. Contains the signal that killed the
    /// process.
    Signaled(signal::Signal),
}

/// This function calls ptrace with PTRACE_TRACEME to enable debugging on a process. You should use
/// pre_exec with Command to call this in the child process.
fn child_traceme() -> Result<(), std::io::Error> {
    ptrace::traceme().or(Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "ptrace TRACEME failed",
    )))
}

pub struct Inferior {
    child: Child,
    orig_bytes: HashMap<usize, u8>,
}

fn align_addr_to_word(addr: usize) -> usize {
    addr & (-(size_of::<usize>() as isize) as usize)
}

impl Inferior {
    /// Attempts to start a new inferior process. Returns Some(Inferior) if successful, or None if
    /// an error is encountered.
    pub fn new(target: &str, args: &Vec<String>, breakpoints: &HashSet<usize>) -> Option<Inferior> {
        // TODO: implement me!
        let mut cmd = Command::new(target);
        unsafe {
            cmd.pre_exec(child_traceme);
        }

        let child = cmd
            .args(args)
            .spawn()
            .expect("Failed to execute subprocess");

        let mut inferior = Inferior {
            child,
            orig_bytes: HashMap::new(),
        };
        if let Ok(Status::Stopped(sig, _)) = inferior.wait(None) {
            if sig != SIGTRAP {
                return None;
            }
        } else {
            return None;
        };

        inferior.install_breakpoints(breakpoints).ok()?;
        return Some(inferior);
    }

    pub fn install_breakpoints(&mut self, breakpoints: &HashSet<usize>) -> Result<(), nix::Error> {
        for addr in breakpoints.iter() {
            if self.orig_bytes.contains_key(addr) {
                continue;
            }
            // 0xcc means SIGINT
            let orig_byte = self.write_byte(*addr, 0xcc)?;
            self.orig_bytes.insert(*addr, orig_byte);
        }

        Ok(())
    }

    /// Returns the pid of this inferior.
    pub fn pid(&self) -> Pid {
        nix::unistd::Pid::from_raw(self.child.id() as i32)
    }

    fn cur_regs(&self) -> Result<user_regs_struct, nix::Error> {
        ptrace::getregs(self.pid())
    }

    pub fn cont(&mut self) -> Result<Status, nix::Error> {
        let regs = self.cur_regs()?;
        let rip = regs.rip as usize;
        // if inferior is stopped at a breakpoint
        if self.stop_at_breakpoint(&rip) {
            let breakpoint = rip;
            // Ok(None) ==> resume successfully
            // Ok(Some(status)) ==> child process terminates
            if let Some(status) = self.resume_instruction_to_breakpoint(&breakpoint)? {
                return Ok(status);
            }
        }
        // ptrace::cont to resume normal execution
        // wait for inferior to stop or terminate
        ptrace::cont(self.pid(), None)?;
        let status = self.wait(None)?;
        if let Status::Stopped(sig, cur) = status {
            if !self.hit_breakpoint(&cur) {
                return Ok(Status::Stopped(sig, cur));
            }

            let breakpoint = cur - 1;
            self.resume_breakpoint_to_instruction(&breakpoint)?;
            return Ok(Status::Stopped(sig, breakpoint));
        }
        return Ok(status);
    }

    pub fn next(&mut self) -> Result<Status, nix::Error> {
        let regs = self.cur_regs()?;
        let rip = regs.rip as usize;
        // if inferior is stopped at a breakpoint
        if self.stop_at_breakpoint(&rip) {
            let breakpoint = rip;
            // Ok(None) ==> resume successfully
            // Ok(Some(status)) ==> child process terminates
            if let Some(status) = self.resume_instruction_to_breakpoint(&breakpoint)? {
                return Ok(status);
            }
        }
        // ptrace::step to resume normal execution for one instruction
        // wait for inferior to stop or terminate
        ptrace::step(self.pid(), None)?;
        let status = self.wait(None)?;
        if let Status::Stopped(sig, cur) = status {
            if !self.hit_breakpoint(&cur) {
                return Ok(Status::Stopped(sig, cur));
            }

            let breakpoint = cur - 1;
            self.resume_breakpoint_to_instruction(&breakpoint)?;
            return Ok(Status::Stopped(sig, breakpoint));
        }
        return Ok(status);
    }

    fn hit_breakpoint(&self, addr: &usize) -> bool {
        return self.orig_bytes.contains_key(&(addr - 1));
    }

    fn stop_at_breakpoint(&self, addr: &usize) -> bool {
        return self.orig_bytes.contains_key(addr);
    }

    pub fn print_variable_msg(&self, debug_data: &DwarfData, var_name: &str) {
        if let Some(variable) = self.get_variable(debug_data, var_name) {
            Self::print_variable(&variable);
        } else {
            println!("Error finding variables: {}", var_name);
        }
    }

    /// a for associated function
    pub fn print_variable_msg_a(debug_data: &DwarfData, var_name: &str) {
        if let Some(variable) = Self::get_variable_a(debug_data, var_name) {
            Self::print_variable(&variable);
        } else {
            println!("Error finding variables: {}", var_name);
        }
    }

    fn print_variable(variable: &Variable) {
        println!(
            "line: {:?} | name: {:?} | type: {:?} | addr: {:?} ",
            variable.line_number, variable.name, variable.entity_type, variable.location
        );
    }

    /// From debug_data
    /// With var_name
    /// At addr
    fn get_variable(&self, debug_data: &DwarfData, var_name: &str) -> Option<Variable> {
        let cur_regs = self.cur_regs().ok()?;
        let cur_addr = cur_regs.rip as usize;
        debug_data.get_variable_with_name_and_addr(var_name, &cur_addr)
    }

    /// a for associated function
    fn get_variable_a(debug_data: &DwarfData, var_name: &str) -> Option<Variable> {
        debug_data.get_global_variable_with_name(var_name)
    }

    /// WARN: rip was set to the breakpoint
    fn resume_breakpoint_to_instruction(&mut self, breakpoint: &usize) -> Result<(), nix::Error> {
        // if inferior hit a breakpoint (i.e. (%rip - 1) matches a breakpoint address):
        // restore the first byte of the instruction we replaced
        let orig_byte = *self.orig_bytes.get(&breakpoint).unwrap();
        Self::write_byte(self, *breakpoint, orig_byte)?;
        // set %rip = %rip - 1 to rewind the instruction pointer
        let mut regs = ptrace::getregs(self.pid())?;
        regs.rip = *breakpoint as u64;
        ptrace::setregs(self.pid(), regs)?;
        Ok(())
    }

    fn resume_instruction_to_breakpoint(
        &mut self,
        breakpoint: &usize,
    ) -> Result<Option<Status>, nix::Error> {
        // ptrace::step to go to next instruction
        ptrace::step(self.pid(), None)?;
        // wait for inferior to stop due to SIGTRAP
        //  (if the inferior terminates here, then you should return that status and
        // not go any further in this pseudocode)
        match self.wait(None)? {
            Status::Stopped(sig, cur) => {
                if sig != SIGTRAP {
                    return Ok(Some(Status::Stopped(sig, cur)));
                }
            }
            other => return Ok(Some(other)),
        };
        // restore 0xcc in the breakpoint location
        Self::write_byte(self, *breakpoint, 0xcc)?;
        Ok(None)
    }

    pub fn kill(&mut self) -> Result<(), Error> {
        return self.child.kill();
    }

    pub fn print_backtrace(&self, debug_data: &DwarfData) -> Result<(), nix::Error> {
        let regs = ptrace::getregs(self.pid())?;
        let mut rip_addr = regs.rip as usize;
        let mut rbp_addr = regs.rbp as usize;
        loop {
            let file_and_line = Self::get_file_name_and_line_number_at(debug_data, rip_addr);
            let func = Self::get_function_at(debug_data, rip_addr);
            if file_and_line.is_some() && func.is_some() {
                let (file, line) = file_and_line.unwrap();
                let function_name = func.unwrap();
                println!("{} ({}:{})", function_name, file, line);

                if function_name == "main" {
                    break;
                }
            } else {
                println!("*** (0x{:x})", rip_addr);
            }

            rip_addr = ptrace::read(self.pid(), (rbp_addr + 8) as ptrace::AddressType)? as usize;
            rbp_addr = ptrace::read(self.pid(), rbp_addr as ptrace::AddressType)? as usize;
        }

        Ok(())
    }

    pub fn print_stop_at(&self, debug_data: &DwarfData, addr: usize) {
        if let Some((file, line)) = Self::get_file_name_and_line_number_at(debug_data, addr) {
            println!("Stopped at {}:{}", file, line);
            Self::print_stop_at_from_src(&file, line);
        } else {
            println!("Stopped at 0x{:#}", addr);
        }
    }

    fn print_stop_at_from_src(file_path: &str, line_number: usize) {
        let line = Self::read_line_from_file(file_path, line_number)
            .expect(&format!("Error reading {}:{}", file_path, line_number));
        println!("{}\t{}", line_number, line);
    }

    fn read_line_from_file(file_path: &str, line_number: usize) -> io::Result<String> {
        let file = File::open(file_path)?;
        let reader = io::BufReader::new(file);
        let lines_iter = reader.lines().enumerate();

        for (i, line) in lines_iter {
            if i + 1 == line_number {
                return line;
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Line number out of range",
        ))
    }

    fn get_file_name_and_line_number_at(
        debug_data: &DwarfData,
        addr: usize,
    ) -> Option<(String, usize)> {
        let file_name_and_line_number = debug_data.get_line_from_addr(addr)?;
        return Some((
            file_name_and_line_number.file,
            file_name_and_line_number.number,
        ));
    }

    fn get_function_at(debug_data: &DwarfData, addr: usize) -> Option<String> {
        debug_data.get_function_from_addr(addr)
    }

    fn write_byte(&mut self, addr: usize, val: u8) -> Result<u8, nix::Error> {
        let aligned_addr = align_addr_to_word(addr);
        let byte_offset = addr - aligned_addr;
        let word = ptrace::read(self.pid(), aligned_addr as ptrace::AddressType)? as u64;
        let orig_byte = (word >> 8 * byte_offset) & 0xff;
        let masked_word = word & !(0xff << 8 * byte_offset);
        let updated_word = masked_word | ((val as u64) << 8 * byte_offset);
        ptrace::write(
            self.pid(),
            aligned_addr as ptrace::AddressType,
            updated_word as *mut std::ffi::c_void,
        )?;
        Ok(orig_byte as u8)
    }
    /// Calls waitpid on this inferior and returns a Status to indicate the state of the process
    /// after the waitpid call.
    pub fn wait(&self, options: Option<WaitPidFlag>) -> Result<Status, nix::Error> {
        Ok(match waitpid(self.pid(), options)? {
            WaitStatus::Exited(_pid, exit_code) => Status::Exited(exit_code),
            WaitStatus::Signaled(_pid, signal, _core_dumped) => Status::Signaled(signal),
            WaitStatus::Stopped(_pid, signal) => {
                let regs = ptrace::getregs(self.pid())?;
                Status::Stopped(signal, regs.rip as usize)
            }
            other => panic!("waitpid returned unexpected status: {:?}", other),
        })
    }
}
