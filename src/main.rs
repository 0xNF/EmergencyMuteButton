mod audio;
mod win_event;

use std::{process::exit, time::Duration};

use crate::audio::set_system_volume_to_zero;

fn main() {
    let listening_event_ids = [4624, 4625, 4626, 4800, 4801, 4802, 4803];

    if let Err(e) = set_system_volume_to_zero() {
        eprintln!("failed to set system volume: {e}");
        exit(-1)
    }

    if let Err(e) = win_event::listen_for_events(
        "Security",
        &listening_event_ids,
        Duration::from_millis(10),
        win_event::EventFetchOption::FromBeginning,
        win_event::print_event_log_details,
    ) {
        eprintln!("failed to listen for events: {}", e);
        exit(-1)
    }
}
