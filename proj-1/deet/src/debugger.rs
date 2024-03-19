use crate::debugger_command::DebuggerCommand;
use crate::dwarf_data::{DwarfData, Error as DwarfError};
use crate::inferior::Inferior;
use crate::inferior::Status;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use std::collections::HashSet;

pub struct Debugger {
    target: String,
    history_path: String,
    readline: Editor<()>,
    inferior: Option<Inferior>,
    debug_data: DwarfData,
    breakpoints: HashSet<usize>,
}

impl Debugger {
    /// Initializes the debugger.
    pub fn new(target: &str) -> Debugger {
        // TODO (milestone 3): initialize the DwarfData
        let debug_data = match DwarfData::from_file(target) {
            Ok(val) => val,
            Err(DwarfError::ErrorOpeningFile) => {
                println!("Could not open file {}", target);
                std::process::exit(1);
            }
            Err(DwarfError::DwarfFormatError(err)) => {
                println!("Could not debugging symbols from {}: {:?}", target, err);
                std::process::exit(1);
            }
        };

        debug_data.print();

        let history_path = format!("{}/.deet_history", std::env::var("HOME").unwrap());
        let mut readline = Editor::<()>::new();
        // Attempt to load history from ~/.deet_history if it exists
        let _ = readline.load_history(&history_path);

        Debugger {
            target: target.to_string(),
            history_path,
            readline,
            inferior: None,
            debug_data,
            breakpoints: HashSet::new(),
        }
    }

    pub fn run(&mut self) {
        loop {
            match self.get_next_command() {
                DebuggerCommand::Run(args) => {
                    if let Some(inferior) = Inferior::new(&self.target, &args, &self.breakpoints) {
                        self.kill_inferior_if_exist();
                        // Create the inferior
                        self.set_inferior(inferior);
                        // TODO (milestone 1): make the inferior run
                        // You may use self.inferior.as_mut().unwrap() to get a mutable reference
                        // to the Inferior object
                        self.continue_inferior_running()
                    } else {
                        println!("Error starting subprocess");
                    }
                }
                DebuggerCommand::Quit => {
                    self.kill_inferior_if_exist();
                    return;
                }
                DebuggerCommand::Cont => {
                    if self.inferior.is_none() {
                        println!("No child stopped");
                        continue;
                    }
                    self.continue_inferior_running()
                }
                DebuggerCommand::BackTrace => {
                    if self.inferior.is_none() {
                        println!("No child to print");
                        continue;
                    }
                    self.inferior
                        .as_ref()
                        .unwrap()
                        .print_backtrace(&self.debug_data)
                        .expect("Error printing backtrace");
                }
                DebuggerCommand::BreakPoint(breakpoint_str) => {
                    if breakpoint_str.starts_with('*') {
                        self.set_addr_breakpoint(breakpoint_str);
                        continue;
                    }
                    if breakpoint_str.chars().next().unwrap().is_ascii_digit() {
                        self.set_line_breakpoint(breakpoint_str);
                        continue;
                    }
                    self.set_func_breakpoint(breakpoint_str);
                }
                DebuggerCommand::Next => {
                    if self.inferior.is_none() {
                        println!("No child stopped");
                        continue;
                    }
                    self.next_step_inferior();
                }
                DebuggerCommand::Print(var_name) => {
                    self.print_variable(var_name.as_ref());
                }
            }
        }
    }

    fn print_variable(&self, var_name: &str) {
        if self.inferior.is_some() {
            let inferior = self.inferior.as_ref().unwrap();
            inferior.print_variable_msg(&self.debug_data, var_name);
            return;
        }

        Inferior::print_variable_msg_a(&self.debug_data, var_name)
    }

    fn set_inferior(&mut self, inferior: Inferior) {
        self.inferior = Some(inferior);
    }

    fn set_func_breakpoint(&mut self, func_str: String) {
        if let Some(addr) = self.debug_data.get_addr_for_function(None, &func_str) {
            println!("Set breakpoint {} at {:x}", self.breakpoints.len(), addr);
            self.set_breakpoint(addr);
        } else {
            println!("Error setting f-breakpoint: {}", func_str);
        }
    }

    fn set_line_breakpoint(&mut self, line_str: String) {
        let line = line_str.parse::<usize>();
        if let Err(_) = line {
            println!("Error setting l-breakpoint: {}", line_str);
            return;
        }

        let line = line.unwrap();

        if let Some(addr) = self.debug_data.get_addr_for_line(None, line) {
            println!("Set breakpoint {} at {:x}", self.breakpoints.len(), addr);
            self.set_breakpoint(addr);
        } else {
            println!("Error setting l-breakpoint: {}", line_str);
        }
    }

    fn set_addr_breakpoint(&mut self, addr_str: String) {
        if let Some(addr) = Self::parse_address(&addr_str[1..]) {
            println!("Set breakpoint {} at {:x}", self.breakpoints.len(), addr);
            self.set_breakpoint(addr);
        } else {
            println!("Error setting a-breakpoint: {}", addr_str);
        }
    }

    fn set_breakpoint(&mut self, breakpoint: usize) {
        let set_changed = self.breakpoints.insert(breakpoint);
        let inferior_exist = self.inferior.is_some();
        if set_changed && inferior_exist {
            self.inferior
                .as_mut()
                .unwrap()
                .install_breakpoints(&self.breakpoints)
                .expect("Error installing breakpoints: ");
        }
    }

    fn parse_address(addr: &str) -> Option<usize> {
        let addr_without_0x = if addr.to_lowercase().starts_with("0x") {
            &addr[2..]
        } else {
            &addr
        };
        usize::from_str_radix(addr_without_0x, 16).ok()
    }

    fn continue_inferior_running(&mut self) {
        assert!(self.inferior.is_some());

        self.make_inferior_run(Inferior::cont);
    }

    fn next_step_inferior(&mut self) {
        assert!(self.inferior.is_some());

        self.make_inferior_run(Inferior::next);
    }

    fn make_inferior_run(&mut self, run_method: fn(&mut Inferior) -> Result<Status, nix::Error>) {
        let inferior = self.inferior.as_mut().unwrap();
        match run_method(inferior) {
            Err(error) => eprintln!("failed to execute subprocess: {}", error),
            Ok(Status::Exited(exit_status)) => {
                println!("Child exited (status {})", exit_status);
                self.run_inferior_finished()
            }
            Ok(Status::Stopped(sig, cur)) => {
                println!("Child stopped (signal: {})", sig);
                self.print_verbose_stop_at_msg(cur);
            }
            Ok(Status::Signaled(sig)) => {
                println!("Child stopped (signal: {})", sig);
                self.run_inferior_finished()
            }
        }
    }

    fn run_inferior_finished(&mut self) {
        self.inferior = None;
        self.breakpoints.clear();
    }

    fn kill_inferior_if_exist(&mut self) {
        if self.inferior.is_none() {
            return;
        }
        let inferior = self.inferior.as_mut().unwrap();
        let i_pid = inferior.pid();
        println!("Killing running inferior (pid {})", i_pid);
        inferior
            .kill()
            .expect(&format!("Error killing inferior (pid {})", i_pid))
    }

    fn print_verbose_stop_at_msg(&self, addr: usize) {
        assert!(self.inferior.is_some());
        self.inferior
            .as_ref()
            .unwrap()
            .print_stop_at(&self.debug_data, addr)
    }

    /// This function prompts the user to enter a command, and continues re-prompting until the user
    /// enters a valid command. It uses DebuggerCommand::from_tokens to do the command parsing.
    ///
    /// You don't need to read, understand, or modify this function.
    fn get_next_command(&mut self) -> DebuggerCommand {
        loop {
            // Print prompt and get next line of user input
            match self.readline.readline("(deet) ") {
                Err(ReadlineError::Interrupted) => {
                    // User pressed ctrl+c. We're going to ignore it
                    println!("Type \"quit\" to exit");
                }
                Err(ReadlineError::Eof) => {
                    // User pressed ctrl+d, which is the equivalent of "quit" for our purposes
                    return DebuggerCommand::Quit;
                }
                Err(err) => {
                    panic!("Unexpected I/O error: {:?}", err);
                }
                Ok(line) => {
                    if line.trim().len() == 0 {
                        continue;
                    }
                    self.readline.add_history_entry(line.as_str());
                    if let Err(err) = self.readline.save_history(&self.history_path) {
                        println!(
                            "Warning: failed to save history file at {}: {}",
                            self.history_path, err
                        );
                    }
                    let tokens: Vec<&str> = line.split_whitespace().collect();
                    if let Some(cmd) = DebuggerCommand::from_tokens(&tokens) {
                        return cmd;
                    } else {
                        println!("Unrecognized command.");
                    }
                }
            }
        }
    }
}
