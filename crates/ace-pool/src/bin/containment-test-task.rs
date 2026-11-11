//! A test task for containment's tests in `tests/containment.rs`. It contains itself, unless
//! given `--uncontained`, and then tries one action, such as forking or reading a file.
//!
//! ```text
//! containment-test-task [--uncontained] [--thread-before] [--read PATH]... [--write PATH]...
//!     [--port PORT]... [--memory-mb MB] [--cpu-seconds SECONDS] ACTION [ARGUMENT]
//! ```
//!
//! It prints `contained` once containment applies, then a line when the action finishes, and
//! exits 0. It exits 3 when containment fails and 4 when the action fails with an error, and
//! prints the error. A blocked call or a limit kills it with a signal instead.
//!
//! `containment-test-task tool` is the sandbox runner's tool process (`ace_pool::tools::tool_main`),
//! so the runner's tests can run this binary, `--uncontained`, as the tool it contains.

use std::env;
use std::fs;
use std::hint::black_box;
use std::io::{self, Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::os::unix::process::parent_id;
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::thread;

use ace_pool::{SandboxProfile, contain};
use ace_sdk::{Resources, Sandbox};

const USAGE: &str = "usage: containment-test-task [--uncontained] [--thread-before] \
    [--read PATH]... [--write PATH]... [--port PORT]... [--memory-mb MB] \
    [--cpu-seconds SECONDS] ACTION [ARGUMENT]";

struct Args {
    contained: bool,
    thread_before: bool,
    profile: SandboxProfile,
    action: String,
    argument: Option<String>,
}

fn main() -> ExitCode {
    if env::args().nth(1).as_deref() == Some("tool") {
        return ace_pool::tools::tool_main();
    }
    let args = match parse(env::args().skip(1)) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("{error}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    if args.thread_before {
        // a thread that outlives containment, as an async runtime's workers would
        thread::spawn(|| {
            loop {
                thread::park();
            }
        });
    }
    if args.contained {
        match contain(&args.profile) {
            Ok(contained) => println!("contained: {contained:?}"),
            Err(error) => {
                eprintln!("containment failed: {error}");
                return ExitCode::from(3);
            }
        }
        // the tests wait for this line before they look at the process
        io::stdout().flush().expect("flushing stdout");
    }
    match act(&args.action, args.argument.as_deref()) {
        Ok(done) => {
            println!("{done}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{} failed: {error}", args.action);
            ExitCode::from(4)
        }
    }
}

fn parse(mut raw: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut args = Args {
        contained: true,
        thread_before: false,
        profile: SandboxProfile::new(Resources::DEFAULT, Sandbox::Contained),
        action: String::new(),
        argument: None,
    };
    let number = |flag: &str, value: Option<String>| -> Result<u64, String> {
        value
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| format!("{flag} needs a number"))
    };
    while let Some(arg) = raw.next() {
        match arg.as_str() {
            "--uncontained" => args.contained = false,
            "--thread-before" => args.thread_before = true,
            "--read" => args.profile.read_paths.push(path(&arg, raw.next())?),
            "--write" => args.profile.write_paths.push(path(&arg, raw.next())?),
            "--port" => {
                let port = number(&arg, raw.next())?;
                let port = u16::try_from(port).map_err(|_| "--port needs a port number")?;
                args.profile.tcp_ports.push(port);
            }
            "--memory-mb" => {
                args.profile.address_space_bytes = number(&arg, raw.next())? * 1024 * 1024;
            }
            "--cpu-seconds" => args.profile.cpu_seconds = number(&arg, raw.next())?,
            flag if flag.starts_with("--") => return Err(format!("unknown flag {flag}")),
            _ => {
                args.action = arg;
                args.argument = raw.next();
                break;
            }
        }
    }
    if args.action.is_empty() {
        return Err("no action".into());
    }
    Ok(args)
}

fn path(flag: &str, value: Option<String>) -> Result<PathBuf, String> {
    value
        .map(PathBuf::from)
        .ok_or_else(|| format!("{flag} needs a path"))
}

/// Tries the action and says what it did.
fn act(action: &str, argument: Option<&str>) -> io::Result<String> {
    let argument = || argument.ok_or_else(|| io::Error::other("the action needs an argument"));
    let port = || -> io::Result<u16> { argument()?.parse().map_err(io::Error::other) };
    match action {
        "nothing" => Ok("did nothing".into()),
        "fork" => fork(),
        "exec" => exec(),
        "thread" => {
            let thread = thread::Builder::new().spawn(|| "a thread ran")?;
            Ok(thread.join().expect("the thread doesn't panic").into())
        }
        "spawn" => {
            let status = Command::new("/bin/true").status()?;
            Ok(format!("spawned /bin/true: {status}"))
        }
        "read" => {
            let bytes = fs::read(argument()?)?;
            Ok(format!("read {} bytes", bytes.len()))
        }
        "write" => {
            fs::write(argument()?, "written by a test task\n")?;
            Ok("wrote".into())
        }
        "connect" => {
            TcpStream::connect(("127.0.0.1", port()?))?;
            Ok("connected".into())
        }
        "udp" => {
            let socket = UdpSocket::bind("127.0.0.1:0")?;
            socket.send_to(b"from a test task", ("127.0.0.1", port()?))?;
            Ok("sent a datagram".into())
        }
        "signal-parent" => {
            let parent = libc::pid_t::try_from(parent_id()).map_err(io::Error::other)?;
            // Signal 0 checks the permission and sends nothing.
            // SAFETY: kill takes two integers.
            if unsafe { libc::kill(parent, 0) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(format!("may signal parent {parent}"))
        }
        "allocate" => {
            let megabytes: usize = argument()?.parse().map_err(io::Error::other)?;
            // filled, so every page is touched
            let block = vec![1u8; megabytes * 1024 * 1024];
            black_box(&block);
            Ok(format!("allocated {megabytes} MB"))
        }
        "cpu" => {
            let seconds: f64 = argument()?.parse().map_err(io::Error::other)?;
            while cpu_seconds()? < seconds {
                black_box(());
            }
            Ok(format!("spun for {seconds} CPU seconds"))
        }
        "wait" => {
            // until the test closes stdin
            io::stdin().read_to_end(&mut Vec::new())?;
            Ok("stdin closed".into())
        }
        "sleep" => {
            let seconds: u64 = argument()?.parse().map_err(io::Error::other)?;
            thread::sleep(std::time::Duration::from_secs(seconds));
            Ok(format!("slept {seconds} s"))
        }
        "socket" => {
            // a TCP socket, which a tool may not make
            TcpStream::connect(("127.0.0.1", port()?))?;
            Ok("connected".into())
        }
        "write-mb" => {
            // a file of this many MB in the working directory
            let megabytes: usize = argument()?.parse().map_err(io::Error::other)?;
            let mut file = fs::File::create("big")?;
            let block = vec![b'x'; 1024 * 1024];
            for _ in 0..megabytes {
                file.write_all(&block)?;
            }
            Ok(format!("wrote {megabytes} MB"))
        }
        "open-files" => {
            let count: usize = argument()?.parse().map_err(io::Error::other)?;
            let mut files = Vec::new();
            for _ in 0..count {
                files.push(fs::File::open("/dev/null")?);
            }
            Ok(format!("opened {} files", files.len()))
        }
        "print-mb" => {
            let megabytes: usize = argument()?.parse().map_err(io::Error::other)?;
            let block = vec![b'y'; 1024 * 1024];
            let mut stdout = io::stdout().lock();
            for _ in 0..megabytes {
                stdout.write_all(&block)?;
            }
            Ok(String::new())
        }
        "keep-many" => {
            // more files than a run keeps
            fs::create_dir("many")?;
            for i in 0..ace_sdk::tools::MAX_KEPT_FILES + 10 {
                fs::write(format!("many/{i:06}"), "x")?;
            }
            Ok("left many files".into())
        }
        "keep" => {
            // a file to keep, and a symlink and a hard link that mustn't be
            fs::write("out", "kept\n")?;
            std::os::unix::fs::symlink("/etc/passwd", "link")?;
            fs::write("twice", "linked\n")?;
            fs::hard_link("twice", "twice-again")?;
            Ok("left files".into())
        }
        _ => Err(io::Error::other(format!("unknown action {action}"))),
    }
}

fn fork() -> io::Result<String> {
    // SAFETY: the child calls only _exit.
    match unsafe { libc::fork() } {
        -1 => Err(io::Error::last_os_error()),
        // SAFETY: _exit ends the child without running anything else.
        0 => unsafe { libc::_exit(0) },
        child => {
            let mut status = 0;
            // SAFETY: waitpid writes one int, which lives for the call.
            if unsafe { libc::waitpid(child, &mut status, 0) } == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(format!("forked child {child}"))
        }
    }
}

/// Replaces the process with /bin/true, which exits 0. It returns only on an error.
fn exec() -> io::Result<String> {
    let program = c"/bin/true";
    let argv = [program.as_ptr(), std::ptr::null()];
    // SAFETY: argv is a null-terminated array of C strings that live for the call.
    unsafe { libc::execv(program.as_ptr(), argv.as_ptr()) };
    Err(io::Error::last_os_error())
}

fn cpu_seconds() -> io::Result<f64> {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes one timespec, which lives for the call.
    if unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut now) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(now.tv_sec as f64 + now.tv_nsec as f64 / 1e9)
}
