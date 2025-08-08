mod audio;
mod auditpol;
mod service;
mod win32;
mod win_event;

use crate::audio::set_system_volume_to_zero;
use crate::service::SERVICE_NAME;
use env_logger;
use std::ffi::OsString;
use std::sync::mpsc::{Receiver, Sender};
use std::{process::exit, time::Duration};
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

#[macro_use]
extern crate windows_service;
define_windows_service!(ffi_service_main, service_main);

fn service_main(_arguments: Vec<OsString>) {
    env_logger::init();
    log::info!("Starting EmergencyMuteButton as Windows Service");
    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel::<()>();
    let shutdown_tx_ctrl_c = shutdown_tx.clone();
    ctrlc::set_handler(move || {
        log::info!("ctrl-c: Shutting down win event log subscription");
        println!("Shutting down win event log subscription");
        shutdown_tx_ctrl_c.send(()).unwrap();
    })
    .expect("Error setting Ctrl-C handler");

    if let Err(e) = run_service(shutdown_tx.clone(), shutdown_rx) {
        log::error!("service error: {}", e);
        eprintln!("{}", e);
    }
}

fn run_service(
    shutdown_tx: Sender<()>,
    shutdown_rx: Receiver<()>,
) -> Result<(), windows_service::Error> {
    /* Set up logging */
    log::info!("EmergencyMuteButton is Starting...");
    /* Define service status */
    let status_handle =
        service_control_handler::register(
            SERVICE_NAME,
            move |control_event| match control_event {
                ServiceControl::Stop => {
                    shutdown_tx.send(()).unwrap();
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NotImplemented,
            },
        )?;
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    })?;
    /* Main service loop */
    log::info!("EmergencyMuteButton is running...");
    app_main(shutdown_rx);
    log::info!("EmergencyMuteButton is stopping...");
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;
    Ok(())
}

fn app_main(shutdown_signal: Receiver<()>) {
    /* Enable Auditing of required events */
    match auditpol::enable_audit_policies() {
        Ok(_) => log::info!("Audit policies are enabled"),
        Err(e) => {
            log::error!("failed to enable audit policies: {}", e);
            eprintln!("failed to enable audit policies: {}", e);
            exit(-1)
        }
    }

    let listening_event_ids = [4624, 4625, 4626, 4800, 4801, 4802, 4803];
    let which_log = "Security";
    if let Err(e) = win_event::listen_for_events(
        which_log,
        &listening_event_ids,
        Duration::from_secs(1),
        win_event::EventFetchOption::FromSubscriptionTime,
        |e| {
            win_event::print_event_log_details(e);
            if let Err(e) = set_system_volume_to_zero() {
                log::error!("{}", e);
                eprintln!("{}", e);
            }
        },
        shutdown_signal,
    ) {
        log::error!("{}", e);
        eprintln!("failed to listen for events: {}", e);
        exit(-1)
    }
}

fn main() {
    env_logger::init();
    log::info!("Starting EmergencyMuteButton");

    if std::env::args().any(|arg| arg == "install") {
        service::install_service();
        return;
    }

    if std::env::args().any(|arg| arg == "uninstall") {
        service::uninstall_service();
        return;
    }
    if let Err(e) = service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        eprintln!("Failed to start service: {:?}", e);
    }
}
