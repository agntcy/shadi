use std::io::ErrorKind;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

// The probe `shadi_sandbox::network_blocked_by_kernel` makes: exits 0 when the
// kernel refuses the connection with a permission error, 1 otherwise.
fn main() {
    let probe: SocketAddr = "192.0.2.1:9".parse().expect("probe address");
    match TcpStream::connect_timeout(&probe, Duration::from_millis(300)) {
        Err(err) if err.kind() == ErrorKind::PermissionDenied => std::process::exit(0),
        _ => std::process::exit(1),
    }
}
