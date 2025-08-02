use quick_xml::Reader;
use quick_xml::events::Event;
use std::thread;
use std::time::Duration;
use windows::Win32::System::EventLog::*;
use windows::Win32::System::Memory::{GetProcessHeap, HEAP_FLAGS, HeapAlloc, HeapFree};

#[derive(Debug)]
pub enum EventFetchOption {
    FromBeginning,
    FromSubscriptionTime,
}

impl Into<u32> for EventFetchOption {
    fn into(self) -> u32 {
        match self {
            EventFetchOption::FromBeginning => EvtSubscribeStartAtOldestRecord.0,
            EventFetchOption::FromSubscriptionTime => EvtSubscribeToFutureEvents.0,
        }
    }
}

pub fn listen_for_events(
    event_log_section: &str,
    event_ids: &[u32],
    polling: Duration,
    event_fetch_option: EventFetchOption,
    event_handler: impl Fn(&EventLogEvent) + Send + 'static,
) -> Result<(), EventLogError> {
    log::info!(
        "Loading event listener. Duration: {:#?};  Fetch Option: {:#?}; From: {} Event Ids: {:#?}",
        polling,
        &event_fetch_option,
        event_log_section,
        &event_ids,
    );

    let channel = WidePcwstr::new(event_log_section).as_pcwstr();
    let query = create_event_log_query(event_log_section, event_ids);
    let query = WidePcwstr::new(&query);
    let query = query.as_pcwstr();
    log::trace!("Made pcwide strings");

    let callback_wrapper = Box::new(CallbackWrapper {
        _callback: Box::new(event_handler),
    });

    // Convert to raw pointer
    let user_context = Box::into_raw(callback_wrapper) as *mut std::ffi::c_void;
    log::trace!("made callback c_void ptr");

    // Open a subscription to the event logca
    let _subscription = unsafe {
        EvtSubscribe(
            None,
            None,
            channel,
            query,
            None,
            Some(user_context),
            Some(event_callback),
            event_fetch_option.into(),
        )
    }
    .map_err(|e| EventLogError::Subscription(e.code().0, e.message()))?;

    log::debug!("made Event Log subscription");

    ctrlc::set_handler(move || {
        log::info!("ctrl-c: Shutting down win event log subscription");
        println!("Shutting down win event log subscription");
        // Clean up the subscription
        unsafe {
            if let Err(e) = EvtClose(_subscription) {
                eprintln!(
                    "Failed to close subscription channel, artifacts may remain: {}",
                    e
                );
            }
        };
        std::process::exit(-1)
    })
    .expect("Error setting Ctrl-C handler");

    log::info!("Listening for new PC lock/unlock events");
    println!("Listening for new PC lock/unlock events");
    loop {
        thread::sleep(polling);
        log::trace!("Sleeping for poll duration");
    }
}

unsafe extern "system" fn event_callback(
    _: EVT_SUBSCRIBE_NOTIFY_ACTION,
    user_context: *const std::ffi::c_void,
    event_handle: EVT_HANDLE,
) -> u32 {
    log::trace!("Got an event callback");
    let callback = user_context as *mut Box<dyn Fn(&EventLogEvent)>;

    unsafe {
        match parse_event_log_event(event_handle) {
            Err(e) => eprintln!("{}", e),
            Ok(evt) => {
                if !callback.is_null() {
                    (**callback)(&evt);
                }
            }
        }
    };
    0
}

fn create_event_log_query(event_log_section: &str, event_ids: &[u32]) -> String {
    log::trace!("construcing {} log xml query strings", event_ids.len());
    let mut query = format!("<QueryList><Query Id=\"0\" Path=\"{}\">", event_log_section);

    for &event_id in event_ids {
        query.push_str(&format!(
            "<Select Path=\"Security\">*[System[(EventID={})]]</Select>",
            event_id
        ));
    }

    query.push_str(r#"<Suppress Path="Security">*[EventData[Data[1]="S-1-5-18"]]</Suppress>"#);
    query.push_str("</Query></QueryList>");

    query
}

unsafe fn parse_event_log_event(event_handle: EVT_HANDLE) -> Result<EventLogEvent, EventLogError> {
    log::trace!("Parsing log event from handle: {}", &event_handle.0);
    // Ensure event handle is valid
    if event_handle.is_invalid() {
        return Err(EventLogError::Win32(0, "Invalid event handle".to_string()));
    }

    // Initial buffer size query
    let mut buffer_used: u32 = 0;
    let mut buffer_required: u32 = 0;

    // Get process heap
    let process_heap = unsafe { GetProcessHeap() }.map_err(|e| EventLogError::from(e))?;

    // Allocate buffer with extra padding
    let buffer_size = buffer_required.max(buffer_used).max(4096) as usize;
    let buffer = unsafe { HeapAlloc(process_heap, HEAP_FLAGS(0), buffer_size) };

    if buffer.is_null() {
        return Err(EventLogError::HeapAllocation(
            "Failed to allocate buffer".to_string(),
        ));
    }

    // Reset buffer tracking variables
    buffer_used = 0;
    buffer_required = buffer_size as u32;

    // Actual rendering with padded buffer
    let render_result = unsafe {
        EvtRender(
            None,
            event_handle,
            EvtRenderEventXml.0,
            buffer_required,
            Some(buffer),
            &mut buffer_used,
            &mut buffer_required,
        )
    };
    log::trace!("Rendered result");

    // Error handling
    render_result.map_err(|error| EventLogError::EventRendering {
        error_code: error.code().0,
        buffer_used,
        buffer_required,
    })?;

    // Convert buffer to XML string
    let xml_slice =
        unsafe { std::slice::from_raw_parts(buffer as *const u16, (buffer_used / 2) as usize) };

    let xml_string = String::from_utf16_lossy(xml_slice);

    // Parse XML and handle potential errors
    let event = parse_event_xml(&xml_string)?;

    // Always free the buffer
    unsafe {
        log::trace!("Freed wide string pointer buffer");
        HeapFree(process_heap, HEAP_FLAGS(0), Some(buffer))
            .map_err(|e| EventLogError::Win32(e.code().0, e.to_string()))?;
    }

    Ok(event)
}

pub fn print_event_log_details(event: &EventLogEvent) {
    // Print event details
    println!("Event ID: {}", event.event_id);
    println!("Timestamp: {}", event.timestamp);
    println!("Message: {}", event.message);
    println!("---");
}

pub struct EventLogEvent {
    pub event_id: i32,
    pub message: String,
    pub timestamp: String,
}

fn parse_event_xml(xml: &str) -> Result<EventLogEvent, EventLogError> {
    log::trace!("Parsing event xml string, len {}", xml.len());
    let mut reader = Reader::from_str(xml);

    let mut event_id: i32 = 0;
    let mut timestamp = String::new();
    let mut message = String::new();

    let mut current_tag = Vec::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                current_tag.push(e.name().0.to_vec());

                // Check for specific attributes in TimeCreated
                if e.name().as_ref() == b"TimeCreated" {
                    for attr in e.attributes() {
                        let attr = attr.map_err(|e| EventLogError::XmlParsing(e.to_string()))?;
                        if attr.key == quick_xml::name::QName(b"SystemTime") {
                            timestamp = String::from_utf8_lossy(attr.value.as_ref()).to_string();
                        }
                    }
                }
            }
            Ok(Event::End(e)) => {
                if let Some(last_tag) = current_tag.pop() {
                    if last_tag == e.name().0.to_vec() {
                        // Reset parsing state if needed
                    }
                }
            }
            Ok(Event::Text(e)) => {
                let y = e.into_inner();
                let text = String::from_utf8_lossy(&y);

                // Check for EventID
                if current_tag.last().map_or(false, |tag| tag == b"EventID") {
                    let event_id_str = text.to_string();
                    event_id = event_id_str.parse().map_err(|e| {
                        EventLogError::XmlParsing(format!(
                            "Expected eventId to be parseable as an i32, but it wasn't: {}",
                            e
                        ))
                    })?;
                }

                // Collect message from EventData
                if current_tag.iter().any(|tag| tag == b"EventData") {
                    message.push_str(&text);
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(e.into()),
            _ => {}
        }
    }

    Ok(EventLogEvent {
        event_id,
        message,
        timestamp,
    })
}

#[derive(Debug)]
pub enum EventLogError {
    Win32(i32, String),
    Subscription(i32, String),
    HeapAllocation(String),
    EventRendering {
        error_code: i32,
        buffer_used: u32,
        buffer_required: u32,
    },
    XmlParsing(String),
    IoError(std::io::Error),
}

impl std::fmt::Display for EventLogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventLogError::Win32(code, msg) => write!(f, "Win32 Error {}: {}", code, msg),
            EventLogError::Subscription(code, msg) => {
                write!(f, "Event Log Subscription Error {}: {}", code, msg)
            }
            EventLogError::HeapAllocation(msg) => write!(f, "Heap Allocation Error: {}", msg),
            EventLogError::EventRendering {
                error_code,
                buffer_used,
                buffer_required,
            } => write!(
                f,
                "Event Rendering Error: code {}, buffer used {}, buffer required {}",
                error_code, buffer_used, buffer_required
            ),
            EventLogError::XmlParsing(msg) => write!(f, "XML Parsing Error: {}", msg),
            EventLogError::IoError(e) => write!(f, "IO Error: {}", e),
        }
    }
}

impl std::error::Error for EventLogError {}

// Implement From traits for easy error conversion
impl From<windows::core::Error> for EventLogError {
    fn from(value: windows::core::Error) -> Self {
        EventLogError::Win32(value.code().0, value.message())
    }
}

impl From<std::io::Error> for EventLogError {
    fn from(value: std::io::Error) -> Self {
        EventLogError::IoError(value)
    }
}

impl From<quick_xml::Error> for EventLogError {
    fn from(value: quick_xml::Error) -> Self {
        EventLogError::XmlParsing(value.to_string())
    }
}

struct WidePcwstr {
    // Keep the vector alive as long as the PCWSTR exists
    _data: Vec<u16>,
    pcwstr: windows::core::PCWSTR,
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

struct CallbackWrapper {
    _callback: Box<dyn Fn(&EventLogEvent) + Send>,
}

unsafe impl Send for CallbackWrapper {}
unsafe impl Sync for CallbackWrapper {}
