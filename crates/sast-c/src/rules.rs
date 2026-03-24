use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceKind {
    Argv,
    GetEnv,
    ScanfFamily,
    Read,
    Recv,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SinkKind {
    Strcpy,
    Strcat,
    Sprintf,
    Gets,
    System,
    Exec,
    Popen,
    PrintfFamily,
    Memcpy,
    MallocFamily,
    Free,
}

pub fn is_source_function(name: &str) -> Option<SourceKind> {
    match name {
        "getenv" => Some(SourceKind::GetEnv),
        "scanf" | "fscanf" | "sscanf" => Some(SourceKind::ScanfFamily),
        "read" => Some(SourceKind::Read),
        "recv" => Some(SourceKind::Recv),
        _ => None,
    }
}

pub fn is_sink_function(name: &str) -> Option<SinkKind> {
    match name {
        "strcpy" => Some(SinkKind::Strcpy),
        "strcat" => Some(SinkKind::Strcat),
        // Treat `sprintf` as dangerous; `snprintf` is size-bounded and handled separately if needed.
        "sprintf" | "vsprintf" => Some(SinkKind::Sprintf),
        "gets" => Some(SinkKind::Gets),
        "system" => Some(SinkKind::System),
        "popen" => Some(SinkKind::Popen),
        "memcpy" | "memmove" => Some(SinkKind::Memcpy),
        "malloc" | "calloc" | "realloc" => Some(SinkKind::MallocFamily),
        "free" => Some(SinkKind::Free),
        _ => {
            if name.starts_with("exec") {
                Some(SinkKind::Exec)
            } else if is_printf_family(name) {
                Some(SinkKind::PrintfFamily)
            } else {
                None
            }
        }
    }
}

pub fn is_printf_family(name: &str) -> bool {
    matches!(
        name,
        "printf"
            | "fprintf"
            | "sprintf"
            | "snprintf"
            | "vprintf"
            | "vfprintf"
            | "vsprintf"
            | "vsnprintf"
    )
}

pub fn dangerous_buffer_funcs() -> HashSet<&'static str> {
    ["strcpy", "strcat", "sprintf", "gets", "memcpy", "memmove"]
        .into_iter()
        .collect()
}
