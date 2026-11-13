//! Native, bounded, interface-scoped Bonjour adapter. Keep in a current-thread
//! event loop; cancellation of `recv` preserves all operation state.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::ffi::{CStr, CString, c_char, c_void};
use std::io;
use std::net::Ipv4Addr;
use std::ptr;
use std::rc::Rc;
use std::time::{Duration, Instant};

const LIMIT: usize = 128;
const TXT_LIMIT: usize = 1300;
const ADD: u32 = 2;
const SCAN_INTERVAL: Duration = Duration::from_millis(25);
const REFRESH_INTERVAL: Duration = Duration::from_secs(30);
type Ref = *mut c_void;
type Reply = unsafe extern "C" fn(
    Ref,
    u32,
    u32,
    i32,
    *const c_char,
    *const c_char,
    *const c_char,
    *mut c_void,
);
type RegisterReply =
    unsafe extern "C" fn(Ref, u32, i32, *const c_char, *const c_char, *const c_char, *mut c_void);
type ResolveReply = unsafe extern "C" fn(
    Ref,
    u32,
    u32,
    i32,
    *const c_char,
    *const c_char,
    u16,
    u16,
    *const u8,
    *mut c_void,
);
type QueryReply = unsafe extern "C" fn(
    Ref,
    u32,
    u32,
    i32,
    *const c_char,
    u16,
    u16,
    u16,
    *const c_void,
    u32,
    *mut c_void,
);

#[link(name = "System")]
unsafe extern "C" {
    fn DNSServiceRegister(
        sd: *mut Ref,
        flags: u32,
        index: u32,
        name: *const c_char,
        kind: *const c_char,
        domain: *const c_char,
        host: *const c_char,
        port: u16,
        len: u16,
        txt: *const c_void,
        callback: Option<RegisterReply>,
        context: *mut c_void,
    ) -> i32;
    fn DNSServiceBrowse(
        sd: *mut Ref,
        flags: u32,
        index: u32,
        kind: *const c_char,
        domain: *const c_char,
        callback: Option<Reply>,
        context: *mut c_void,
    ) -> i32;
    fn DNSServiceResolve(
        sd: *mut Ref,
        flags: u32,
        index: u32,
        name: *const c_char,
        kind: *const c_char,
        domain: *const c_char,
        callback: Option<ResolveReply>,
        context: *mut c_void,
    ) -> i32;
    fn DNSServiceQueryRecord(
        sd: *mut Ref,
        flags: u32,
        index: u32,
        name: *const c_char,
        rrtype: u16,
        class: u16,
        callback: Option<QueryReply>,
        context: *mut c_void,
    ) -> i32;
    fn DNSServiceRefSockFD(sd: Ref) -> i32;
    fn DNSServiceProcessResult(sd: Ref) -> i32;
    fn DNSServiceRefDeallocate(sd: Ref);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct OperationId(u64);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ServiceKey {
    pub interface_index: u32,
    pub name: String,
    pub service_type: String,
    pub domain: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressRecord {
    pub address: Ipv4Addr,
    pub ttl: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRecord {
    pub key: ServiceKey,
    pub port: u16,
    pub txt: Vec<u8>,
    pub addresses: Vec<AddressRecord>,
    pub observed_at: Instant,
    pub srv_ttl: Option<u32>,
    pub txt_ttl: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MdnsEvent {
    Registered {
        operation: OperationId,
        key: ServiceKey,
    },
    Upsert {
        operation: OperationId,
        record: ServiceRecord,
    },
    Remove {
        operation: OperationId,
        key: ServiceKey,
    },
    Error {
        operation: OperationId,
        code: i32,
    },
}

pub fn validate_txt(txt: &[u8]) -> io::Result<()> {
    if txt.len() > TXT_LIMIT {
        return Err(invalid("TXT exceeds 1300 bytes"));
    }
    let mut offset = 0;
    while offset < txt.len() {
        offset += 1 + usize::from(txt[offset]);
        if offset > txt.len() {
            return Err(invalid("truncated TXT field"));
        }
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn string(value: &str) -> io::Result<CString> {
    if value.is_empty() || value.len() > 1005 {
        return Err(invalid("empty or oversized DNS name"));
    }
    CString::new(value).map_err(|_| invalid("NUL in DNS name"))
}
fn native(code: i32) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!("DNS-SD error {code}")))
    }
}

#[derive(Clone)]
enum Raw {
    Browse(u32, u32, i32, String, String, String),
    Registered(i32, String, String, String),
    Resolved(u32, i32, String, String, u16, Vec<u8>),
    Record(u32, u32, i32, u16, Vec<u8>, u32),
}
#[derive(Default)]
struct Queue {
    items: VecDeque<(u64, Raw)>,
    overflow: bool,
}
struct Context {
    token: u64,
    queue: Rc<RefCell<Queue>>,
    registration: bool,
}
impl Context {
    fn push(&self, raw: Raw) {
        let mut queue = self.queue.borrow_mut();
        if queue.items.len() == LIMIT {
            queue.overflow = true;
        } else {
            queue.items.push_back((self.token, raw));
        }
    }
}

unsafe fn text(value: *const c_char) -> String {
    if value.is_null() {
        return String::new();
    }
    // SAFETY: DNS-SD callback contract supplies a NUL-terminated string.
    unsafe { CStr::from_ptr(value) }
        .to_string_lossy()
        .into_owned()
}
unsafe extern "C" fn reply(
    _: Ref,
    flags: u32,
    index: u32,
    error: i32,
    name: *const c_char,
    kind: *const c_char,
    domain: *const c_char,
    context: *mut c_void,
) {
    // SAFETY: boxed context outlives native ref; callbacks run synchronously.
    let context = unsafe { &*context.cast::<Context>() };
    let (name, kind, domain) = if error == 0 {
        // SAFETY: successful callback supplies valid DNS-SD strings.
        unsafe { (text(name), text(kind), text(domain)) }
    } else {
        Default::default()
    };
    context.push(if context.registration {
        Raw::Registered(error, name, kind, domain)
    } else {
        Raw::Browse(flags, index, error, name, kind, domain)
    });
}
unsafe extern "C" fn registered(
    sd: Ref,
    flags: u32,
    error: i32,
    name: *const c_char,
    kind: *const c_char,
    domain: *const c_char,
    context: *mut c_void,
) {
    // SAFETY: adapts DNSServiceRegisterReply ABI to shared copying.
    unsafe { reply(sd, flags, 0, error, name, kind, domain, context) };
}
unsafe extern "C" fn resolved(
    _: Ref,
    _: u32,
    index: u32,
    error: i32,
    fullname: *const c_char,
    host: *const c_char,
    port: u16,
    len: u16,
    txt: *const u8,
    context: *mut c_void,
) {
    // SAFETY: boxed context outlives native ref and synchronous callbacks.
    let context = unsafe { &*context.cast::<Context>() };
    let (fullname, host, bytes) = if error == 0 {
        // SAFETY: successful callback supplies strings and len bytes.
        unsafe { (text(fullname), text(host), copy_bytes(txt.cast(), len)) }
    } else {
        Default::default()
    };
    context.push(Raw::Resolved(
        index,
        error,
        fullname,
        host,
        u16::from_be(port),
        bytes,
    ));
}
unsafe fn copy_bytes(data: *const c_void, len: u16) -> Vec<u8> {
    if usize::from(len) > TXT_LIMIT {
        return vec![0; TXT_LIMIT + 1];
    }
    if len == 0 || data.is_null() {
        return Vec::new();
    }
    // SAFETY: successful native callback guarantees len readable bytes.
    unsafe { std::slice::from_raw_parts(data.cast::<u8>(), usize::from(len)) }.to_vec()
}
unsafe extern "C" fn queried(
    _: Ref,
    flags: u32,
    index: u32,
    error: i32,
    _: *const c_char,
    kind: u16,
    _: u16,
    len: u16,
    data: *const c_void,
    ttl: u32,
    context: *mut c_void,
) {
    // SAFETY: context is stable for the native callback.
    let context = unsafe { &*context.cast::<Context>() };
    let bytes = if error == 0 {
        // SAFETY: successful callback supplies len readable bytes.
        unsafe { copy_bytes(data, len) }
    } else {
        Vec::new()
    };
    context.push(Raw::Record(flags, index, error, kind, bytes, ttl));
}

struct NativeRef {
    raw: Ref,
    context: Box<Context>,
    operation: OperationId,
    key: Option<ServiceKey>,
    deadline: Option<Instant>,
    query_kind: Option<u16>,
}
impl Drop for NativeRef {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            // SAFETY: unique live DNSServiceRef, destroyed before boxed context.
            unsafe { DNSServiceRefDeallocate(self.raw) };
        }
    }
}
struct Cached {
    record: ServiceRecord,
    expires: BTreeMap<Ipv4Addr, Instant>,
    host: String,
    srv_expires: Option<Instant>,
    txt_expires: Option<Instant>,
}

/// Single-thread RAII owner; callbacks only enqueue bounded copied data.
pub struct MdnsClient {
    refs: BTreeMap<u64, NativeRef>,
    queue: Rc<RefCell<Queue>>,
    events: VecDeque<MdnsEvent>,
    services: BTreeMap<(OperationId, ServiceKey), Cached>,
    watched: BTreeMap<(OperationId, ServiceKey), Instant>,
    next_scan: Instant,
    next: u64,
}
impl Default for MdnsClient {
    fn default() -> Self {
        Self::new()
    }
}
impl MdnsClient {
    pub fn new() -> Self {
        Self {
            refs: BTreeMap::new(),
            queue: Rc::default(),
            events: VecDeque::new(),
            services: BTreeMap::new(),
            watched: BTreeMap::new(),
            next_scan: Instant::now(),
            next: 1,
        }
    }
    fn allocate(
        &mut self,
        operation: Option<OperationId>,
        key: Option<ServiceKey>,
        registration: bool,
    ) -> io::Result<(u64, NativeRef)> {
        if self.refs.len() >= LIMIT {
            return Err(invalid("DNS-SD operation limit"));
        }
        let token = self.next;
        self.next = self
            .next
            .checked_add(1)
            .ok_or_else(|| invalid("operation id exhausted"))?;
        Ok((
            token,
            NativeRef {
                raw: ptr::null_mut(),
                context: Box::new(Context {
                    token,
                    queue: self.queue.clone(),
                    registration,
                }),
                operation: operation.unwrap_or(OperationId(token)),
                key,
                deadline: None,
                query_kind: None,
            },
        ))
    }
    pub fn register(
        &mut self,
        interface_index: u32,
        name: &str,
        service_type: &str,
        port: u16,
        txt: &[u8],
    ) -> io::Result<OperationId> {
        validate_interface(interface_index)?;
        validate_txt(txt)?;
        if port == 0 {
            return Err(invalid("zero port"));
        }
        let name = string(name)?;
        let kind = string(service_type)?;
        let (token, mut reference) = self.allocate(
            None,
            Some(ServiceKey {
                interface_index,
                name: name.to_string_lossy().into_owned(),
                service_type: service_type.into(),
                domain: "local.".into(),
            }),
            true,
        )?;
        // SAFETY: native copies inputs; callback context is boxed and stable.
        native(unsafe {
            DNSServiceRegister(
                &mut reference.raw,
                0,
                interface_index,
                name.as_ptr(),
                kind.as_ptr(),
                c"local.".as_ptr(),
                ptr::null(),
                port.to_be(),
                txt.len() as u16,
                txt.as_ptr().cast(),
                Some(registered),
                (&mut *reference.context as *mut Context).cast(),
            )
        })?;
        let id = reference.operation;
        self.refs.insert(token, reference);
        Ok(id)
    }
    pub fn browse(&mut self, interface_index: u32, service_type: &str) -> io::Result<OperationId> {
        validate_interface(interface_index)?;
        let kind = string(service_type)?;
        let (token, mut reference) = self.allocate(None, None, false)?;
        // SAFETY: valid out ref, copied strings and stable boxed context.
        native(unsafe {
            DNSServiceBrowse(
                &mut reference.raw,
                0,
                interface_index,
                kind.as_ptr(),
                c"local.".as_ptr(),
                Some(reply),
                (&mut *reference.context as *mut Context).cast(),
            )
        })?;
        reference.key = Some(ServiceKey {
            interface_index,
            name: String::new(),
            service_type: service_type.into(),
            domain: "local.".into(),
        });
        let id = reference.operation;
        self.refs.insert(token, reference);
        Ok(id)
    }
    pub fn cancel(&mut self, operation: OperationId) {
        self.refs.retain(|_, value| value.operation != operation);
        self.services.retain(|(id, _), _| *id != operation);
        self.watched.retain(|(id, _), _| *id != operation);
        self.events
            .retain(|event| event_operation(event) != operation);
    }
    fn emit(&mut self, event: MdnsEvent) {
        if self.events.len() == LIMIT {
            self.queue.borrow_mut().overflow = true;
        } else {
            self.events.push_back(event);
        }
    }
    fn fail(&mut self, operation: OperationId, code: i32) {
        self.cancel(operation);
        self.emit(MdnsEvent::Error { operation, code });
    }
    fn remove_service(&mut self, operation: OperationId, key: &ServiceKey) {
        self.refs
            .retain(|_, r| !(r.operation == operation && r.key.as_ref() == Some(key)));
        self.services.remove(&(operation, key.clone()));
        self.events.retain(|event| !matches!(event, MdnsEvent::Upsert { operation: id, record } if *id == operation && record.key == *key));
        self.emit(MdnsEvent::Remove {
            operation,
            key: key.clone(),
        });
    }
    fn fail_reference(&mut self, token: u64, code: i32) {
        let Some(reference) = self.refs.get(&token) else {
            return;
        };
        let operation = reference.operation;
        if reference.context.registration
            || reference.key.as_ref().is_none_or(|key| key.name.is_empty())
        {
            self.fail(operation, code);
        } else if let Some(key) = reference.key.clone() {
            self.remove_service(operation, &key);
        }
    }
    fn claim_scan(&mut self, now: Instant) -> bool {
        if now < self.next_scan {
            return false;
        }
        self.next_scan = now + SCAN_INTERVAL;
        true
    }
    fn due_refreshes(&mut self, now: Instant) -> Vec<(OperationId, ServiceKey)> {
        let mut due = Vec::new();
        for (key, deadline) in &mut self.watched {
            if *deadline <= now {
                *deadline = now + REFRESH_INTERVAL;
                due.push(key.clone());
            }
        }
        due
    }
    fn process_callback(&mut self, token: u64, raw: Raw) {
        let owner = self.refs.get(&token).map(|r| (r.operation, r.key.clone()));
        if self.handle(token, raw).is_err()
            && let Some((operation, Some(key))) = owner
        {
            self.remove_service(operation, &key);
        }
    }
    fn expire_records(&mut self, now: Instant) {
        let mut updates = Vec::new();
        for ((operation, _), cached) in &mut self.services {
            let before = cached.expires.len();
            cached.expires.retain(|_, deadline| *deadline > now);
            let srv_expired = cached.srv_expires.is_some_and(|deadline| deadline <= now);
            let txt_expired = cached.txt_expires.is_some_and(|deadline| deadline <= now);
            if srv_expired {
                cached.record.port = 0;
                cached.srv_expires = None;
            }
            if txt_expired {
                cached.record.txt.clear();
                cached.txt_expires = None;
            }
            if cached.expires.len() != before || srv_expired || txt_expired {
                refresh(cached);
                updates.push(MdnsEvent::Upsert {
                    operation: *operation,
                    record: cached.record.clone(),
                });
            }
        }
        for update in updates {
            self.emit(update);
        }
    }
    fn resolve(&mut self, operation: OperationId, key: ServiceKey) -> io::Result<()> {
        if self
            .refs
            .values()
            .any(|r| r.operation == operation && r.key.as_ref() == Some(&key))
        {
            return Ok(());
        }
        let name = string(&key.name)?;
        let kind = string(&key.service_type)?;
        let domain = string(&key.domain)?;
        let (token, mut reference) = self.allocate(Some(operation), Some(key.clone()), false)?;
        reference.deadline = Some(Instant::now() + Duration::from_secs(10));
        // SAFETY: stable context and copied names, scoped to observed interface.
        native(unsafe {
            DNSServiceResolve(
                &mut reference.raw,
                0,
                key.interface_index,
                name.as_ptr(),
                kind.as_ptr(),
                domain.as_ptr(),
                Some(resolved),
                (&mut *reference.context as *mut Context).cast(),
            )
        })?;
        self.refs.insert(token, reference);
        Ok(())
    }
    fn query(
        &mut self,
        operation: OperationId,
        key: &ServiceKey,
        name: &str,
        kind: u16,
    ) -> io::Result<()> {
        let name = string(name)?;
        let (token, mut reference) = self.allocate(Some(operation), Some(key.clone()), false)?;
        reference.query_kind = Some(kind);
        // SAFETY: valid out ref, scoped query, stable callback context.
        native(unsafe {
            DNSServiceQueryRecord(
                &mut reference.raw,
                0,
                key.interface_index,
                name.as_ptr(),
                kind,
                1,
                Some(queried),
                (&mut *reference.context as *mut Context).cast(),
            )
        })?;
        self.refs.insert(token, reference);
        Ok(())
    }
    fn handle(&mut self, token: u64, raw: Raw) -> io::Result<()> {
        let Some(reference) = self.refs.get(&token) else {
            return Ok(());
        };
        let operation = reference.operation;
        let Some(key) = reference.key.clone() else {
            return Ok(());
        };
        match raw {
            Raw::Registered(error, name, service_type, domain) => {
                if error != 0 {
                    self.fail(operation, error);
                } else {
                    self.emit(MdnsEvent::Registered {
                        operation,
                        key: ServiceKey {
                            name,
                            service_type,
                            domain,
                            ..key
                        },
                    });
                }
            }
            Raw::Browse(flags, index, error, name, service_type, domain) => {
                if error != 0 {
                    self.fail(operation, error);
                    return Ok(());
                }
                if index != key.interface_index {
                    return Ok(());
                }
                let key = ServiceKey {
                    interface_index: index,
                    name,
                    service_type,
                    domain,
                };
                if flags & ADD != 0 {
                    if !self.watched.contains_key(&(operation, key.clone())) {
                        if self.watched.len() >= LIMIT {
                            return Ok(());
                        }
                        self.watched
                            .insert((operation, key.clone()), Instant::now() + REFRESH_INTERVAL);
                        if self.resolve(operation, key.clone()).is_err() {
                            self.remove_service(operation, &key);
                        }
                    }
                } else {
                    self.watched.remove(&(operation, key.clone()));
                    self.remove_service(operation, &key);
                }
            }
            Raw::Resolved(index, error, fullname, host, port, txt) => {
                self.refs.remove(&token);
                if error != 0 {
                    self.remove_service(operation, &key);
                    return Ok(());
                }
                if index != key.interface_index {
                    return Ok(());
                }
                validate_txt(&txt)?;
                if port == 0 || self.services.len() >= LIMIT {
                    return Err(invalid("invalid or excessive service records"));
                }
                self.services.insert(
                    (operation, key.clone()),
                    Cached {
                        record: ServiceRecord {
                            key: key.clone(),
                            port,
                            txt,
                            addresses: Vec::new(),
                            observed_at: Instant::now(),
                            srv_ttl: None,
                            txt_ttl: None,
                        },
                        expires: BTreeMap::new(),
                        host: host.clone(),
                        srv_expires: None,
                        txt_expires: None,
                    },
                );
                self.query(operation, &key, &host, 1)?;
                self.query(operation, &key, &fullname, 16)?;
                self.query(operation, &key, &fullname, 33)?;
            }
            Raw::Record(flags, index, error, kind, bytes, ttl) => {
                if error != 0 {
                    self.remove_service(operation, &key);
                    return Ok(());
                }
                if index != key.interface_index {
                    return Ok(());
                }
                let Some(cached) = self.services.get_mut(&(operation, key.clone())) else {
                    return Ok(());
                };
                let mut new_host = None;
                if kind == 1 && bytes.len() == 4 {
                    let address = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
                    if flags & ADD != 0 && ttl > 0 {
                        if cached.expires.len() >= LIMIT && !cached.expires.contains_key(&address) {
                            return Err(invalid("excessive A records"));
                        }
                        cached.expires.insert(
                            address,
                            Instant::now() + Duration::from_secs(u64::from(ttl)),
                        );
                    } else {
                        cached.expires.remove(&address);
                    }
                    refresh(cached);
                } else if kind == 16 {
                    validate_txt(&bytes)?;
                    if flags & ADD == 0 || ttl == 0 {
                        cached.record.txt.clear();
                        cached.txt_expires = None;
                    } else {
                        cached.record.txt = bytes;
                        cached.txt_expires =
                            Some(Instant::now() + Duration::from_secs(u64::from(ttl)));
                    }
                } else if kind == 33 {
                    if flags & ADD == 0 || ttl == 0 {
                        cached.record.port = 0;
                        cached.srv_expires = None;
                    } else {
                        let (port, host) = parse_srv(&bytes)?;
                        cached.record.port = port;
                        cached.srv_expires =
                            Some(Instant::now() + Duration::from_secs(u64::from(ttl)));
                        if !host.eq_ignore_ascii_case(&cached.host) {
                            cached.host = host.clone();
                            cached.expires.clear();
                            refresh(cached);
                            new_host = Some(host);
                        }
                    }
                } else {
                    return Ok(());
                }
                refresh(cached);
                let record = cached.record.clone();
                if let Some(host) = new_host {
                    self.refs.retain(|_, r| {
                        !(r.operation == operation
                            && r.key.as_ref() == Some(&key)
                            && r.query_kind == Some(1))
                    });
                    self.query(operation, &key, &host, 1)?;
                }
                self.emit(MdnsEvent::Upsert { operation, record });
            }
        }
        Ok(())
    }
    pub async fn recv(&mut self) -> io::Result<MdnsEvent> {
        loop {
            if self.queue.borrow().overflow {
                self.refs.clear();
                self.services.clear();
                self.watched.clear();
                self.events.clear();
                *self.queue.borrow_mut() = Queue::default();
                return Err(io::Error::other(
                    "DNS-SD event queue overflow; all operations cancelled",
                ));
            }
            if let Some(event) = self.events.pop_front() {
                return Ok(event);
            }
            tokio::time::sleep_until(self.next_scan.into()).await;
            if !self.claim_scan(Instant::now()) {
                continue;
            }
            let tokens: Vec<u64> = self.refs.keys().copied().collect();
            for token in tokens {
                let Some(reference) = self.refs.get(&token) else {
                    continue;
                };
                if reference
                    .deadline
                    .is_some_and(|deadline| deadline <= Instant::now())
                {
                    self.fail_reference(token, -65568);
                    continue;
                }
                // SAFETY: reference is live; fd belongs to DNS-SD.
                let fd = unsafe { DNSServiceRefSockFD(reference.raw) };
                if fd < 0 {
                    self.fail_reference(token, -65563);
                    continue;
                }
                let mut poll = libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: initialized pollfd, zero timeout never blocks.
                let result = unsafe { libc::poll(&mut poll, 1, 0) };
                if result < 0 {
                    if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    self.fail_reference(token, -65563);
                    continue;
                }
                if poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                    self.fail_reference(token, -65563);
                    continue;
                }
                if poll.revents & libc::POLLIN != 0 {
                    // SAFETY: readable live ref; callbacks only enqueue owned
                    // data, never mutate/destroy refs during ProcessResult.
                    let code = unsafe { DNSServiceProcessResult(reference.raw) };
                    if code != 0 {
                        self.fail_reference(token, code);
                    }
                }
            }
            loop {
                let next = self.queue.borrow_mut().items.pop_front();
                let Some((token, raw)) = next else {
                    break;
                };
                self.process_callback(token, raw);
            }
            self.expire_records(Instant::now());
            for (operation, key) in self.due_refreshes(Instant::now()) {
                self.refs
                    .retain(|_, r| !(r.operation == operation && r.key.as_ref() == Some(&key)));
                if self.resolve(operation, key.clone()).is_err() {
                    self.remove_service(operation, &key);
                }
            }
        }
    }
}
fn event_operation(event: &MdnsEvent) -> OperationId {
    match event {
        MdnsEvent::Registered { operation, .. }
        | MdnsEvent::Upsert { operation, .. }
        | MdnsEvent::Remove { operation, .. }
        | MdnsEvent::Error { operation, .. } => *operation,
    }
}
fn parse_srv(bytes: &[u8]) -> io::Result<(u16, String)> {
    if bytes.len() < 8 || bytes.len() > 261 {
        return Err(invalid("invalid SRV length"));
    }
    let port = u16::from_be_bytes([bytes[4], bytes[5]]);
    if port == 0 {
        return Err(invalid("zero SRV port"));
    }
    let mut offset = 6;
    let mut host = String::new();
    loop {
        let len = usize::from(
            *bytes
                .get(offset)
                .ok_or_else(|| invalid("truncated SRV name"))?,
        );
        offset += 1;
        if len == 0 {
            if offset != bytes.len() || host.is_empty() {
                return Err(invalid("invalid SRV target"));
            }
            return Ok((port, host));
        }
        if len > 63 || offset + len > bytes.len() {
            return Err(invalid("invalid SRV label"));
        }
        for byte in &bytes[offset..offset + len] {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') {
                host.push(char::from(*byte));
            } else {
                use std::fmt::Write;
                write!(&mut host, "\\{byte:03}").expect("writing a String is infallible");
            }
        }
        host.push('.');
        offset += len;
    }
}
fn refresh(cached: &mut Cached) {
    let now = Instant::now();
    cached.record.observed_at = now;
    let remaining = |deadline: Instant| {
        let duration = deadline.saturating_duration_since(now);
        duration
            .as_secs()
            .saturating_add(u64::from(duration.subsec_nanos() > 0))
            .min(u64::from(u32::MAX)) as u32
    };
    cached.record.srv_ttl = cached.srv_expires.map(remaining);
    cached.record.txt_ttl = cached.txt_expires.map(remaining);
    cached.record.addresses = cached
        .expires
        .iter()
        .map(|(address, deadline)| AddressRecord {
            address: *address,
            ttl: remaining(*deadline),
        })
        .collect();
}
fn validate_interface(index: u32) -> io::Result<()> {
    if index == 0 {
        return Err(invalid("explicit physical interface required"));
    }
    let interfaces = crate::interface::enumerate_interfaces()?;
    if !interfaces
        .iter()
        .any(|i| i.index == index && i.is_physical_candidate() && !i.is_loopback)
    {
        return Err(invalid("interface is not an up physical LAN interface"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
