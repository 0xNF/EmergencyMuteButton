use windows_service::{
    service::{ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType},
    service_manager::{ServiceManager, ServiceManagerAccess},
};

pub const SERVICE_NAME: &str = "EmergencyMuteButton";
pub const SERVICE_DISPLAY_NAME: &str = "Emergency Mute Button";
pub const SERVICE_DESCRIPTION: &str = "Mutes primary speaker when computer is locked or unlocked";

pub fn install_service() {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE).unwrap();
    let service_info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: SERVICE_DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe().unwrap(),
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None, // Local system account
        account_password: None,
    };
    manager
        .create_service(
            &service_info,
            ServiceAccess::START
                .union(ServiceAccess::STOP)
                .union(ServiceAccess::CHANGE_CONFIG),
        )
        .expect("Failed to create EmergencyMuteButton Service")
        .set_description(SERVICE_DESCRIPTION)
        .expect("Failed to set EmergencyMuteButton Description");
    println!("EmergencyMuteButton Service installed successfully");
}
pub fn uninstall_service() {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::ALL_ACCESS).unwrap();
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::DELETE)
        .unwrap();
    service.delete().unwrap();
    println!("EmergencyMuteButton Service uninstalled successfully");
}
