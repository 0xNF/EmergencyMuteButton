pub struct WidePcwstr {
    // Keep the vector alive as long as the PCWSTR exists
    _data: Vec<u16>,
    pub pcwstr: windows::core::PCWSTR,
}
impl WidePcwstr {
    pub fn new(s: &str) -> Self {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        let data: Vec<u16> = OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let pcwstr = windows::core::PCWSTR(data.as_ptr());

        Self {
            _data: data,
            pcwstr,
        }
    }

    pub fn as_pcwstr(&self) -> windows::core::PCWSTR {
        self.pcwstr
    }
}
