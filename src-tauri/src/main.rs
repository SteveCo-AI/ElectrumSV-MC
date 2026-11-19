fn main() {
    let mut args = std::env::args_os().skip(1);
    let first = args.next();
    if first.as_deref() == Some(std::ffi::OsStr::new("--agent")) {
        let mut dir = None;
        let mut caps = electrumsv_mc_lib::agent::Capabilities::default();
        while let Some(arg) = args.next() {
            match arg.to_str() {
                Some("--data-dir") if dir.is_none() => {
                    dir = args
                        .next()
                        .and_then(|s| s.into_string().ok())
                        .filter(|s| !s.is_empty() && !s.starts_with("--"));
                    if dir.is_none() {
                        eprintln!("data directory must be a nonempty UTF-8 path");
                        std::process::exit(2);
                    }
                }
                Some("--enable-payments") if !caps.payments => caps.payments = true,
                Some("--allow-network") if !caps.network => caps.network = true,
                Some("--allow-broadcast") if !caps.broadcast => caps.broadcast = true,
                Some("--enable-wallet-maintenance") if !caps.wallet_maintenance => caps.wallet_maintenance = true,
                _ => {
                    eprintln!("invalid or duplicate agent option");
                    std::process::exit(2);
                }
            }
        }
        let Some(dir) = dir else {
            eprintln!("--data-dir is required");
            std::process::exit(2);
        };
        if let Err(error) = caps.validate() {
            eprintln!("{error}");
            std::process::exit(2);
        }
        if let Err(e) = electrumsv_mc_lib::agent::run(dir, caps) {
            eprintln!("agent: {e}");
            std::process::exit(1);
        }
    } else if first.as_deref() == Some(std::ffi::OsStr::new("--help")) {
        println!("Usage: electrumsv-mc [--agent --data-dir DIRECTORY [--enable-payments] [--allow-network] [--allow-broadcast] [--enable-wallet-maintenance]]");
    } else if first.is_some() {
        eprintln!("Unknown arguments. Usage: electrumsv-mc [--agent --data-dir DIRECTORY]");
        std::process::exit(2);
    } else {
        electrumsv_mc_lib::run()
    }
}
