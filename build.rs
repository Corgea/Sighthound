fn main() {
    emit_rerun("rules");
}

fn emit_rerun(root: &str) {
    let mut pending = vec![std::path::PathBuf::from(root)];
    while let Some(path) = pending.pop() {
        println!("cargo:rerun-if-changed={}", path.display());
        let entries = std::fs::read_dir(&path).unwrap_or_else(|error| {
            panic!("failed to read directory '{}': {error}", path.display())
        });
        for entry in entries {
            let entry = entry.unwrap_or_else(|error| {
                panic!("failed to read directory entry in '{}': {error}", path.display())
            });
            let child = entry.path();
            if child.is_dir() {
                pending.push(child);
            } else {
                println!("cargo:rerun-if-changed={}", child.display());
            }
        }
    }
}
