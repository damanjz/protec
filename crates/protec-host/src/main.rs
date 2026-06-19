mod nativemsg;
mod pipe;
mod protocol;

use std::io::{stdin, stdout};

fn main() {
    let mut input = stdin().lock();
    let mut output = stdout().lock();

    loop {
        let msg = match nativemsg::read_message(&mut input) {
            Ok(Some(m)) => m,
            Ok(None) => break, // browser closed the port
            Err(_) => break,
        };

        // Relay the raw JSON to the app; if the app isn't running, synthesize
        // an Error response so the extension shows a friendly state.
        let reply = match pipe::round_trip(&msg) {
            Ok(body) => body,
            Err(_) => serde_json::to_vec(&protocol::Response::Error {
                message: "Protec desktop app is not running".into(),
            })
            .unwrap_or_default(),
        };

        if nativemsg::write_message(&mut output, &reply).is_err() {
            break;
        }
    }
}
