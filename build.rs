fn main() {
    emit_rerun("rules");
}

fn emit_rerun(path: &str) {
    println!("cargo:rerun-if-changed={path}");
    let Ok(entries) = std::fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
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
