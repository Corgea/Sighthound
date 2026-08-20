fn main() {
    emit_rerun("rules");
}

fn emit_rerun(path: &str) {
    println!("cargo:rerun-if-changed={path}");
    let entries = std::fs::read_dir(path)
        .unwrap_or_else(|error| panic!("failed to read directory '{path}': {error}"));
    for entry in entries {
        let entry = entry
            .unwrap_or_else(|error| panic!("failed to read directory entry in '{path}': {error}"));
        let child = entry.path();
        let Some(child_str) = child.to_str() else {
            continue;
        };
        if child.is_dir() {
            emit_rerun(child_str);
        } else {
            println!("cargo:rerun-if-changed={child_str}");
        }
    }
}
