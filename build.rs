fn main() {
    println!("cargo:rerun-if-changed=.env");
    let mut res = winres::WindowsResource::new();
    res.set_icon("resources/logo.ico");
    if let Err(e) = res.compile() {
        eprintln!("Failed to set icon: {}", e);
        std::process::exit(1);
    }
}
