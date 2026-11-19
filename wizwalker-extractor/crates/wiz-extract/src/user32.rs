use std::{
    env, fs,
    path::{Path, PathBuf},
};

pub fn local_path(executable: &Path) -> Option<PathBuf> {
    let path = if cfg!(target_os = "windows") {
        let windows = PathBuf::from(env::var_os("SystemRoot")?);
        let system = if cfg!(target_pointer_width = "32") {
            "Sysnative"
        } else {
            "System32"
        };
        windows.join(system).join("user32.dll")
    } else {
        let executable = env::current_dir().ok()?.join(executable);
        wine_user32(&executable).or_else(|| wine_user32(&fs::canonicalize(executable).ok()?))?
    };
    path.is_file().then_some(path)
}

fn wine_user32(executable: &Path) -> Option<PathBuf> {
    let drive = executable.ancestors().find(|path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("drive_c"))
    })?;
    Some(drive.join("windows/system32/user32.dll"))
}
