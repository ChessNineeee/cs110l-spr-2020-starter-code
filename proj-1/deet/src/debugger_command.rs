pub enum DebuggerCommand {
    BackTrace,
    BreakPoint(String),
    Cont,
    Next,
    Print(String),
    Quit,
    Run(Vec<String>),
}

impl DebuggerCommand {
    pub fn from_tokens(tokens: &Vec<&str>) -> Option<DebuggerCommand> {
        let args = tokens[1..].to_vec();
        let first_string_of_tokens =
            || -> Option<String> { Some(args.iter().map(|s| s.to_string()).next()?) };
        match tokens[0] {
            "q" | "quit" => Some(DebuggerCommand::Quit),
            "r" | "run" => Some(DebuggerCommand::Run(
                args.iter().map(|s| s.to_string()).collect(),
            )),
            "c" | "cont" | "continue" => Some(DebuggerCommand::Cont),
            "bt" | "back" | "backtrace" => Some(DebuggerCommand::BackTrace),
            "b" | "break" => {
                if args.len() != 1 {
                    println!("BreakPoint usage: b|break {{addr|func_name|line}}");
                    return None;
                }
                Some(DebuggerCommand::BreakPoint(first_string_of_tokens()?))
            }
            "n" | "next" => Some(DebuggerCommand::Next),
            "p" | "print" => {
                if args.len() != 1 {
                    println!("Print usage: p|print {{var_name}}");
                    return None;
                }
                Some(DebuggerCommand::Print(first_string_of_tokens()?))
            }
            // Default case:
            _ => None,
        }
    }
}
