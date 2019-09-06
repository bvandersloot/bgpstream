use std::error::Error;
use std::ffi::CString;

use element::{Element,ElementError};

pub const FOREVER: u32 = 0;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BGPStreamError {
    Construction,
    InvalidFilter(String),
    OperationOutOfOrder(String),
    StartFailed,
    RecordGetFailure,
    ElementFailure(ElementError),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum StreamState {
    New,
    IntervalSet,
    Started,
    Ongoing,
    Complete,
}

pub struct Stream {
    internal: *mut bgpstream_sys::bgpstream_t,
    record: *mut bgpstream_sys::bgpstream_record_t,
    state: StreamState,
}

pub struct Iter<'a> {
    stream  : &'a mut Stream,
}

impl Stream {
    pub fn new() -> Result<Stream, BGPStreamError> {
        let stream = unsafe { bgpstream_sys::bgpstream_create() };
        if stream.is_null() {
            return Err(BGPStreamError::Construction);
        }
        let record = unsafe { bgpstream_sys::bgpstream_record_create() };
        if record.is_null() {
            return Err(BGPStreamError::Construction);
        }
        Ok(Stream {
            internal: stream,
            record: record,
            state: StreamState::New,
        })
    }

    pub fn add_filter(&mut self, filter: String) -> Result<(), BGPStreamError> {
        if self.state >= StreamState::Started {
            return Err(BGPStreamError::OperationOutOfOrder("Cannot add filter after running".to_string()));
        }
        let filter_cstring = CString::new(filter)?;
        unsafe {
            let result = bgpstream_sys::bgpstream_parse_filter_string(self.internal, filter_cstring.as_c_str().as_ptr());
            if result == 0 {
                return Err(BGPStreamError::InvalidFilter(filter_cstring.into_string()?));
            }
        }
        Ok(())
    }

    pub fn add_interval_filter(&mut self, begin_time : u32, end_time : u32) -> Result<(), BGPStreamError> {
        if self.state >= StreamState::Started {
            return Err(BGPStreamError::OperationOutOfOrder("Cannot change interval after running".to_string()));
        }
        self.state = StreamState::IntervalSet;
        unsafe {
            bgpstream_sys::bgpstream_add_interval_filter(self.internal, begin_time, end_time);
        }
        Ok(())
    }

    pub fn iter(&mut self) -> Result<Iter, BGPStreamError> {
        if self.state >= StreamState::Started {
            return Err(BGPStreamError::OperationOutOfOrder("Must start after interval is set and can only be done once".to_string()));
        }
        self.state = StreamState::Started;
        let result = unsafe{ bgpstream_sys::bgpstream_start(self.internal) };
        match result {
            0 => 
                Ok(Iter {
                    stream: self,
                }),
            _ => Err(BGPStreamError::StartFailed),
        }
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        if !self.internal.is_null() {
            unsafe {
                bgpstream_sys::bgpstream_stop(self.internal);
                bgpstream_sys::bgpstream_destroy(self.internal);
            }
        }
        if !self.record.is_null() {
            unsafe {
                bgpstream_sys::bgpstream_record_destroy(self.record);
            }
        }
        
    }
}

impl<'a> Iterator for Iter<'a> {
    type Item = Result<Element, BGPStreamError>;
    fn next(&mut self) -> Option<Result<Element, BGPStreamError>> {
        let current_state = self.stream.state;
        assert!(current_state >= StreamState::Started);
        if current_state == StreamState::Complete {
            return None;
        }
        if current_state == StreamState::Started {
            let ret_code = unsafe{ bgpstream_sys::bgpstream_get_next_record(self.stream.internal, self.stream.record) };
            if ret_code < 0 {
                self.stream.state = StreamState::Complete;
                return Some(Err(BGPStreamError::RecordGetFailure));
            } else if ret_code == 0 {
                self.stream.state = StreamState::Complete;
                return None;
            } else {
                self.stream.state = StreamState::Ongoing;
            }
        }
        assert!(self.stream.state == StreamState::Ongoing);
        let raw_elem = unsafe { bgpstream_sys::bgpstream_record_get_next_elem(self.stream.record) };
        if raw_elem.is_null() {
            self.stream.state = StreamState::Started;
            return self.next();
        }
        let elem = Element::create(raw_elem);
        match elem {
            Ok(some) => Some(Ok(some)),
            Err(element_err) => Some(Err(BGPStreamError::ElementFailure(element_err))),
        }
    }
}

impl std::convert::From<std::ffi::NulError> for BGPStreamError {
    fn from(_e : std::ffi::NulError) -> Self {
        BGPStreamError::InvalidFilter("Null character in filter string".to_string())
    }
}

impl std::convert::From<std::ffi::IntoStringError> for BGPStreamError {
    fn from(e : std::ffi::IntoStringError) -> Self {
        BGPStreamError::InvalidFilter(e.description().to_string())
    }
}
