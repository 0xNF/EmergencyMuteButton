use windows::{
    Win32::{
        Media::Audio::{
            EDataFlow, ERole, Endpoints::IAudioEndpointVolume, IMMDeviceEnumerator,
            MMDeviceEnumerator,
        },
        System::Com::{
            CLSCTX_ALL, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
        },
    },
    core::Error,
};

pub fn set_system_volume_to_zero() -> Result<(), AudioError> {
    unsafe {
        CoInitializeEx(None, COINIT_APARTMENTTHREADED)
            .ok()
            .map_err(|e| AudioError::from(e))
    }?;

    unsafe {
        let device_enumerator: IMMDeviceEnumerator =
            CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL)?;
        let device = device_enumerator.GetDefaultAudioEndpoint(EDataFlow(0), ERole(1))?;
        let volume_ptr: IAudioEndpointVolume = device.Activate(CLSCTX_ALL, None)?;
        volume_ptr.SetMute(true, std::ptr::null())?;
    }

    Ok(())
}

pub fn uninitialize_com() {
    unsafe {
        CoUninitialize();
    }
}

#[derive(Debug, Clone)]
pub enum AudioError {
    Win32(i32, String),
}
impl std::fmt::Display for AudioError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // AudioError::Unknown(s) => write!(f, "Unknown Audio Error: {}", s),
            AudioError::Win32(code, msg) => write!(f, "Win32 Error {}: {}", code, msg),
        }
    }
}

impl From<Error> for AudioError {
    fn from(value: Error) -> Self {
        AudioError::Win32(value.code().0, value.message())
    }
}
