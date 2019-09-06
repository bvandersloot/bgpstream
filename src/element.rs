
use num_traits::FromPrimitive;
use std::error::Error;
use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::{Duration, SystemTime};

pub type ASN = u32;

#[repr(u32)]
#[derive(FromPrimitive, Debug)]
enum ElementType {
    Announcement = bgpstream_sys::bgpstream_elem_type_t_BGPSTREAM_ELEM_TYPE_ANNOUNCEMENT,
    PeerState =  bgpstream_sys::bgpstream_elem_type_t_BGPSTREAM_ELEM_TYPE_PEERSTATE,
    Rib =  bgpstream_sys::bgpstream_elem_type_t_BGPSTREAM_ELEM_TYPE_RIB,
    Unknown =  bgpstream_sys::bgpstream_elem_type_t_BGPSTREAM_ELEM_TYPE_UNKNOWN,
    Withdrawl =  bgpstream_sys::bgpstream_elem_type_t_BGPSTREAM_ELEM_TYPE_WITHDRAWAL,
}

#[repr(u32)]
#[derive(FromPrimitive, Debug)]
pub enum PeerState {
    Active = bgpstream_sys::bgpstream_elem_peerstate_t_BGPSTREAM_ELEM_PEERSTATE_ACTIVE,
    Clearing = bgpstream_sys::bgpstream_elem_peerstate_t_BGPSTREAM_ELEM_PEERSTATE_CLEARING,
    Connect = bgpstream_sys::bgpstream_elem_peerstate_t_BGPSTREAM_ELEM_PEERSTATE_CONNECT,
    Deleted = bgpstream_sys::bgpstream_elem_peerstate_t_BGPSTREAM_ELEM_PEERSTATE_DELETED,
    Established = bgpstream_sys::bgpstream_elem_peerstate_t_BGPSTREAM_ELEM_PEERSTATE_ESTABLISHED,
    Idle = bgpstream_sys::bgpstream_elem_peerstate_t_BGPSTREAM_ELEM_PEERSTATE_IDLE,
    OpenConfirm = bgpstream_sys::bgpstream_elem_peerstate_t_BGPSTREAM_ELEM_PEERSTATE_OPENCONFIRM,
    OpenSent = bgpstream_sys::bgpstream_elem_peerstate_t_BGPSTREAM_ELEM_PEERSTATE_OPENSENT,
    Unknown = bgpstream_sys::bgpstream_elem_peerstate_t_BGPSTREAM_ELEM_PEERSTATE_UNKNOWN,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ElementError {
    IpParseError(String),
    AsnParseError,
    Utf8Error(String),
    UnexpectedType,
    StringParseError,
}

#[derive(Debug)]
pub struct Element {
    timestamp: SystemTime,
    peer_addr: IpAddr,
    peer_asn: ASN,
    project: String,
    collector: String,
    data: ElementData,
}

#[derive(Debug)]
pub enum ElementData {
    Announcement(AnnouncementData),
    Rib(AnnouncementData),
    Withdrawl(WithdrawlData),
    PeerState(PeerData),
}

#[derive(Debug)]
pub struct AnnouncementData {
    prefix: Prefix,
    next_hop: IpAddr,
    as_path: AsPath,
    communities: CommunitySet,
}

#[derive(Debug)]
pub struct PeerData {
    old_peer_state: PeerState,
    new_peer_state: PeerState,
}

#[derive(Debug)]
pub struct WithdrawlData {
    prefix: Prefix,
}

#[derive(Debug)]
pub struct Prefix {
    addr: IpAddr,
    length: u8,
}

#[derive(Debug)]
pub enum PathEntry {
    As(ASN),
    Collection(Vec<ASN>),
}

type AsPath = Vec<PathEntry>;

type CommunitySet = Vec<(ASN, u16)>;

impl Element {
    pub fn create(element : *mut bgpstream_sys::bgpstream_elem_t, record : *const bgpstream_sys::bgpstream_record_t) -> Result<Self,ElementError> {
        assert!(!element.is_null());
        let elem = unsafe{ (*element) };
        let element_type = match ElementType::from_u32(elem.type_) {
            Some(et) => et,
            None => return Err(ElementError::UnexpectedType),
        };
        let data = match element_type {
            ElementType::Announcement => {
                Ok(ElementData::Announcement(AnnouncementData{
                    prefix: Prefix{ 
                        addr: parse_addr(elem.prefix.address)?,
                        length: elem.prefix.mask_len,
                    },
                    next_hop: parse_addr(elem.nexthop)?,
                    as_path: parse_as_path(elem.aspath)?, 
                    communities: parse_communities(elem.communities)?,
                }))
            },
            ElementType::Rib => {
                Ok(ElementData::Rib(AnnouncementData{
                    prefix: Prefix{ 
                        addr: parse_addr(elem.prefix.address)?,
                        length: elem.prefix.mask_len,
                    },
                    next_hop: parse_addr(elem.nexthop)?,
                    as_path: parse_as_path(elem.aspath)?, 
                    communities: parse_communities(elem.communities)?,
                }))
            },
            ElementType::Withdrawl => {
                Ok(ElementData::Withdrawl(WithdrawlData{
                    prefix: Prefix{ 
                        addr: parse_addr(elem.prefix.address)?,
                        length: elem.prefix.mask_len,
                    },
                }))
                    
            },
            ElementType::PeerState => {
                Ok(ElementData::PeerState(PeerData{
                    old_peer_state: PeerState::from_u32(elem.old_state).unwrap(),
                    new_peer_state: PeerState::from_u32(elem.new_state).unwrap(),
                }))
            },
            ElementType::Unknown => {
                Err(ElementError::UnexpectedType)
            },
        }?;
        let collector_buf = unsafe {&*(&(*record).attributes.dump_collector[..] as *const[i8] as *const[u8])};
        let project_buf = unsafe {&*(&(*record).attributes.dump_project[..] as *const[i8] as *const[u8])};
        Ok(Element{
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(elem.timestamp as u64),
            peer_addr: parse_addr(elem.peer_address)?,
            peer_asn: elem.peer_asnumber,
            collector: str_from_buf(collector_buf)?.to_owned(),
            project: str_from_buf(project_buf)?.to_owned(),
            data: data,
        })
    }
}

fn parse_addr(addr : bgpstream_sys::bgpstream_addr_storage_t) -> Result<IpAddr, ElementError> {
    unsafe {
        match bgpstream_sys::bgpstream_ipv2number(addr.version) {
            4 => Ok(IpAddr::V4(Ipv4Addr::from(addr.__bindgen_anon_1.ipv4.s_addr))),
            6 => Ok(IpAddr::V6(Ipv6Addr::from(addr.__bindgen_anon_1.ipv6.__u6_addr.__u6_addr8))),
            _ => Err(ElementError::IpParseError(format!("Incorrect address version {}", addr.version))),
        }
    }
}

fn parse_communities(comm : *mut bgpstream_sys::bgpstream_community_set_t) -> Result<CommunitySet, ElementError> {
    let mut res = vec![];
    unsafe {
        let n = bgpstream_sys::bgpstream_community_set_size(comm);
        for i in 0..n {
            let c = bgpstream_sys::bgpstream_community_set_get(comm, i);
            if c.is_null() {
                return Err(ElementError::AsnParseError);
            }
            res.push(((*c).asn as ASN, (*c).value));
        }
    }
    Ok(res)
}

fn parse_as_path(path : *mut bgpstream_sys::bgpstream_as_path_t) -> Result<AsPath, ElementError> {
    let mut buffer : Vec<i8> = Vec::with_capacity(4096);
    unsafe {
        let c_buf = buffer.as_mut_ptr();
        let written = bgpstream_sys::bgpstream_as_path_snprintf(c_buf, 4096, path);
        if written >= 4096 {
            return Err(ElementError::AsnParseError);
        }
        let c_str = CStr::from_ptr(c_buf);
        let path_str = c_str.to_str()?;
        return as_path_from_str(path_str);       
    }
}

fn as_path_from_str(path_str : &str) -> Result<AsPath, ElementError> {
    let mut res = vec![];
    for node in path_str.split(' ') {
        if node.starts_with('{') || node.starts_with('[') || node.starts_with('(') {
            let trimmed = node.trim_matches(|c| c == '{' || c == '[' || c == '(' || c == '}' || c == ']' || c == ')');
            let mut sub_res = vec![];
            for sub_node in trimmed.split(',') {
                sub_res.push(u32::from_str(sub_node)?);
            }
            res.push(PathEntry::Collection(sub_res));
        } else {
            res.push(PathEntry::As(u32::from_str(node)?));
        }
    }
    Ok(res)
}

fn str_from_buf(buf : &[u8]) -> Result<&str, ElementError> {
    let len = buf.iter()
        .enumerate()
        .find(|&(_, &byte)| byte == 0)
        .map_or_else(|| buf.len(), |(len, _)| len+1);
    let c_str = CStr::from_bytes_with_nul(&buf[..len])?;
    return Ok(c_str.to_str()?);
}   

impl std::convert::From<std::ffi::FromBytesWithNulError> for ElementError {
    fn from(_e : std::ffi::FromBytesWithNulError) -> Self {
        ElementError::StringParseError
    }
}

impl std::convert::From<std::str::Utf8Error> for ElementError {
    fn from(e : std::str::Utf8Error) -> Self {
        ElementError::Utf8Error(e.description().to_string())
    }
}

impl std::convert::From<std::num::ParseIntError> for ElementError {
    fn from(_e : std::num::ParseIntError) -> Self {
        ElementError::AsnParseError
    }
}
