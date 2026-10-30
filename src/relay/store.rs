//! メモリ内ストア（元 lib/store.js の移植）。再起動で全て消える。
//!
//! メッセージ id はカーソルを兼ねる。起動時刻の Unix ミリ秒から始めるので、
//! 再起動前のカーソルより新しいメッセージの id が必ず大きくなる。

use super::js::{self, is_js_whitespace, utf16_len};
use super::RelayError;
use axum::body::Bytes;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use rand::RngCore;
use serde::Serialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::ops::Bound;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;
use tokio::time::Instant;

pub const MAX_TEXT: usize = 20_000;
pub const MAX_SUBJECT: usize = 200;
pub const MAX_FILE_BYTES: usize = 3 * 1024 * 1024;
pub const MAX_FILES_PER_MESSAGE: usize = 5;
pub const DEFAULT_MAX_TOTAL_STORAGE_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_WAIT_SECONDS: f64 = 280.0;
const MAX_THREAD_MESSAGES: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Muse,
    Grok,
}

impl Side {
    pub fn as_str(self) -> &'static str {
        match self {
            Side::Muse => "muse",
            Side::Grok => "grok",
        }
    }
    pub fn other(self) -> Side {
        match self {
            Side::Muse => Side::Grok,
            Side::Grok => Side::Muse,
        }
    }
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// JS の `Date.prototype.toISOString()` と同じ形（UTC・ミリ秒・`Z`）。
pub fn iso_ms(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let milli = ms.rem_euclid(1000);
    let sod = secs.rem_euclid(86_400);
    // Howard Hinnant の civil_from_days
    let z = secs.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{milli:03}Z",
        sod / 3600,
        sod % 3600 / 60,
        sod % 60
    )
}

fn random_hex(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Clone, Serialize)]
pub struct AttachmentView {
    pub id: String,
    pub filename: String,
    pub content_type: String,
    pub size: usize,
    pub sha256: String,
    pub download_url: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MessageView {
    pub id: String,
    pub cursor: String,
    pub thread_id: String,
    pub sender: &'static str,
    pub text: String,
    pub created_at: String,
    pub read: bool,
    pub read_at: Option<String>,
    pub attachments: Vec<AttachmentView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreadView {
    pub id: String,
    pub subject: String,
    pub started_by: &'static str,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unread_count: Option<usize>,
}

/// `get_attachment` / ファイル DL 用。
pub struct AttachmentContent {
    pub meta: AttachmentView,
    pub message_id: u64,
    pub data: Bytes,
}

struct Thread {
    id: String,
    subject: String,
    started_by: Side,
    created_at: i64,
    updated_at: i64,
    message_ids: Vec<u64>,
}

struct Message {
    id: u64,
    thread_id: String,
    sender: Side,
    text: String,
    created_at: i64,
    read_at: Option<i64>,
    attachment_ids: Vec<String>,
    /// 内部記録専用。API には出さない。
    webhook_status: Option<String>,
}

struct Attachment {
    id: String,
    message_id: u64,
    filename: String,
    content_type: String,
    sha256: String,
    data: Bytes,
}

struct Inner {
    next_id: u64,
    threads: HashMap<String, Thread>,
    messages: BTreeMap<u64, Message>,
    attachments: HashMap<String, Attachment>,
    total_bytes: u64,
}

pub struct Store {
    inner: Mutex<Inner>,
    /// メッセージ追加で long-poll を起こす。
    added: Notify,
    waiting: AtomicUsize,
    /// 停止中。以後の long-poll は待たずに返す。
    closed: AtomicBool,
    max_total_bytes: u64,
    /// `{PUBLIC_URL}/relay/v1`（download_url 用）
    base: String,
}

struct NewAttachment {
    filename: String,
    content_type: String,
    data: Vec<u8>,
}

/// listIncoming の引数。値は JS と同じく緩く解釈する。
#[derive(Debug, Default)]
pub struct ListArgs {
    pub since: Value,
    pub unread_only: Value,
    pub limit: Value,
    pub thread_id: Value,
    pub wait: Value,
}

/// Node の `Buffer.from(s, 'base64')` 同様、パディング有無と余りビットを問わない。
const LENIENT_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

fn decode_base64(raw: &str) -> Option<Vec<u8>> {
    let mut clean = raw;
    if let Some(rest) = clean.strip_prefix("data:") {
        if let Some(pos) = rest.find(";base64,") {
            if !rest[..pos].contains(',') {
                clean = &rest[pos + ";base64,".len()..];
            }
        }
    }
    let clean: String = clean.chars().filter(|c| !is_js_whitespace(*c)).collect();
    let body = clean.trim_end_matches('=');
    let padding = clean.len() - body.len();
    if padding > 2
        || !body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'_' | b'-'))
    {
        return None;
    }
    let mut normalized: String = body
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    // 4n+1 文字の端数は Node と同じく捨てる
    if normalized.len() % 4 == 1 {
        normalized.pop();
    }
    LENIENT_BASE64.decode(normalized).ok()
}

fn validate_attachments(list: &Value) -> Result<Vec<NewAttachment>, RelayError> {
    let items = match list {
        Value::Null => return Ok(Vec::new()),
        Value::Array(items) => items,
        _ => return Err(RelayError::bad_request("\"attachments\" must be an array")),
    };
    if items.len() > MAX_FILES_PER_MESSAGE {
        return Err(RelayError::bad_request(format!(
            "at most {MAX_FILES_PER_MESSAGE} attachments per message"
        )));
    }
    let mut total = 0usize;
    let mut out = Vec::with_capacity(items.len());
    for (i, a) in items.iter().enumerate() {
        let Some(a) = a.as_object() else {
            return Err(RelayError::bad_request(format!(
                "attachments[{i}] must be an object"
            )));
        };
        let filename = match a.get("filename").and_then(Value::as_str) {
            Some(f) if !js::trim(f).is_empty() && utf16_len(f) <= 255 => f,
            _ => {
                return Err(RelayError::bad_request(format!(
                    "attachments[{i}].filename is required (max 255 chars)"
                )))
            }
        };
        let content_type = match a.get("content_type").unwrap_or(&Value::Null) {
            Value::Null => None,
            Value::String(s) if utf16_len(s) <= 255 => Some(s.as_str()),
            _ => {
                return Err(RelayError::bad_request(format!(
                    "attachments[{i}].content_type must be a string"
                )))
            }
        };
        let encoded = match a.get("content_base64").and_then(Value::as_str) {
            Some(s) if !s.is_empty() => s,
            _ => {
                return Err(RelayError::bad_request(format!(
                    "attachments[{i}].content_base64 is required"
                )))
            }
        };
        let Some(data) = decode_base64(encoded) else {
            return Err(RelayError::bad_request(format!(
                "attachments[{i}].content_base64 is not valid base64"
            )));
        };
        if data.is_empty() {
            return Err(RelayError::bad_request(format!(
                "attachments[{i}] is empty"
            )));
        }
        if data.len() > MAX_FILE_BYTES {
            return Err(RelayError::new(
                413,
                format!(
                    "attachments[{i}] is {} bytes; the limit is {MAX_FILE_BYTES} bytes per file",
                    data.len()
                ),
            ));
        }
        total += data.len();
        if total > MAX_FILE_BYTES {
            return Err(RelayError::new(
                413,
                format!(
                    "attachments total {total} bytes; the limit is {MAX_FILE_BYTES} bytes per message"
                ),
            ));
        }
        let filename: String = filename
            .chars()
            .map(|c| match c {
                '/' | '\\' | '\0' | '\r' | '\n' => '_',
                c => c,
            })
            .collect();
        out.push(NewAttachment {
            filename: js::trim(&filename).to_string(),
            content_type: content_type
                .filter(|s| !s.is_empty())
                .unwrap_or("application/octet-stream")
                .to_string(),
            data,
        });
    }
    Ok(out)
}

/// 先頭 `n` UTF-16 コードユニット（JS の `slice(0, n)`）。サロゲートペアは割らない。
fn utf16_prefix(s: &str, n: usize) -> &str {
    let mut units = 0;
    for (i, c) in s.char_indices() {
        units += c.len_utf16();
        if units > n {
            return &s[..i];
        }
    }
    s
}

/// `wait` の秒数（null / 空文字は 0、上限 280）。
fn parse_wait(w: &Value) -> Result<f64, RelayError> {
    if w.is_null() || w.as_str() == Some("") {
        return Ok(0.0);
    }
    let n = js::number(w);
    if !n.is_finite() || n < 0.0 {
        return Err(RelayError::bad_request(
            "\"wait\" must be a number of seconds",
        ));
    }
    Ok(n.min(MAX_WAIT_SECONDS))
}

fn clamp_limit(v: &Value, default: f64, max: f64) -> usize {
    let n = js::number(v);
    let n = if n.is_nan() || n == 0.0 { default } else { n };
    n.clamp(1.0, max) as usize
}

/// `id > after`（after は 0 以上の有限数）を満たす最小の id。
fn first_id_after(after: f64) -> u64 {
    if after >= u64::MAX as f64 {
        u64::MAX
    } else {
        (after.floor() as u64).saturating_add(1)
    }
}

/// JS の `String(n)`（整数なら小数点なし）。
fn number_string(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e21 {
        format!("{}", n as i128)
    } else {
        format!("{n}")
    }
}

struct WaitGuard<'a>(&'a AtomicUsize);

impl<'a> WaitGuard<'a> {
    fn new(counter: &'a AtomicUsize) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self(counter)
    }
}

impl Drop for WaitGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Inner {
    fn fmt_attachment(&self, base: &str, id: &str) -> Option<AttachmentView> {
        let a = self.attachments.get(id)?;
        Some(AttachmentView {
            id: a.id.clone(),
            filename: a.filename.clone(),
            content_type: a.content_type.clone(),
            size: a.data.len(),
            sha256: a.sha256.clone(),
            download_url: format!("{base}/files/{}", a.id),
        })
    }

    fn fmt_message(&self, base: &str, m: &Message) -> MessageView {
        MessageView {
            id: m.id.to_string(),
            cursor: m.id.to_string(),
            thread_id: m.thread_id.clone(),
            sender: m.sender.as_str(),
            text: m.text.clone(),
            created_at: iso_ms(m.created_at),
            read: m.read_at.is_some(),
            read_at: m.read_at.map(iso_ms),
            attachments: m
                .attachment_ids
                .iter()
                .filter_map(|id| self.fmt_attachment(base, id))
                .collect(),
        }
    }

    fn fmt_thread(&self, t: &Thread, counts_for: Option<Side>) -> ThreadView {
        let (message_count, unread_count) = match counts_for {
            None => (None, None),
            Some(reader) => {
                let from = reader.other();
                let unread = t
                    .message_ids
                    .iter()
                    .filter_map(|id| self.messages.get(id))
                    .filter(|m| m.sender == from && m.read_at.is_none())
                    .count();
                (Some(t.message_ids.len()), Some(unread))
            }
        };
        ThreadView {
            id: t.id.clone(),
            subject: t.subject.clone(),
            started_by: t.started_by.as_str(),
            created_at: iso_ms(t.created_at),
            updated_at: iso_ms(t.updated_at),
            message_count,
            unread_count,
        }
    }

    fn unread_from(&self, from: Side) -> usize {
        self.messages
            .values()
            .filter(|m| m.sender == from && m.read_at.is_none())
            .count()
    }
}

impl Store {
    pub fn new(base: impl Into<String>, max_total_bytes: u64) -> Self {
        Self {
            inner: Mutex::new(Inner {
                next_id: now_ms().max(1) as u64,
                threads: HashMap::new(),
                messages: BTreeMap::new(),
                attachments: HashMap::new(),
                total_bytes: 0,
            }),
            added: Notify::new(),
            waiting: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            max_total_bytes,
            base: base.into(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// long-poll 中のリクエスト数。
    #[cfg(test)]
    pub fn waiting(&self) -> usize {
        self.waiting.load(Ordering::SeqCst)
    }

    /// 待機中・以後の long-poll をすぐ返させる。graceful shutdown が最大 280 秒待たされないように。
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.added.notify_waiters();
    }

    /// `check` が値を返すか `wait` が過ぎるまで待つ。メッセージ追加で即座に再判定する。
    /// 呼び出し側の future が drop されれば（クライアント切断）待機もそこで終わる。
    async fn wait_for<T>(
        &self,
        wait: Duration,
        mut check: impl FnMut(&Inner) -> Option<T>,
    ) -> Option<T> {
        let _guard = WaitGuard::new(&self.waiting);
        let deadline = Instant::now() + wait;
        loop {
            let notified = self.added.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(found) = check(&self.lock()) {
                return Some(found);
            }
            if self.closed.load(Ordering::SeqCst) {
                return None;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return None;
            }
        }
    }

    pub fn send_message(&self, sender: Side, body: &Value) -> Result<MessageView, RelayError> {
        let empty = Map::new();
        let b = body.as_object().unwrap_or(&empty);
        let field = |k: &str| b.get(k).unwrap_or(&Value::Null);

        let atts = validate_attachments(field("attachments"))?;
        let text = match field("text") {
            Value::Null if !atts.is_empty() => "",
            Value::String(s) if !js::trim(s).is_empty() || !atts.is_empty() => s.as_str(),
            _ => {
                return Err(RelayError::bad_request(
                    "\"text\" is required (it may be empty only when attachments are included)",
                ))
            }
        };
        if utf16_len(text) > MAX_TEXT {
            return Err(RelayError::bad_request(format!(
                "\"text\" is longer than {MAX_TEXT} characters"
            )));
        }
        let subject = match field("subject") {
            Value::Null => None,
            Value::String(s) if utf16_len(s) <= MAX_SUBJECT => Some(s.as_str()),
            _ => {
                return Err(RelayError::bad_request(
                    "\"subject\" must be a string of at most 200 characters",
                ))
            }
        };

        let mut inner = self.lock();
        if !atts.is_empty() {
            let add: u64 = atts.iter().map(|a| a.data.len() as u64).sum();
            if inner.total_bytes + add > self.max_total_bytes {
                return Err(RelayError::new(
                    507,
                    "relay attachment storage is full; ask the operator to clean up old files",
                ));
            }
        }
        let now = now_ms();
        let thread_id = match field("thread_id") {
            Value::Null => {
                let id = format!("thr_{}", random_hex(8));
                let subject = subject
                    .filter(|s| !s.is_empty())
                    .or_else(|| Some(utf16_prefix(text, 80)).filter(|s| !s.is_empty()))
                    .or_else(|| atts.first().map(|a| a.filename.as_str()))
                    .filter(|s| !s.is_empty())
                    .unwrap_or("attachment")
                    .to_string();
                inner.threads.insert(
                    id.clone(),
                    Thread {
                        id: id.clone(),
                        subject,
                        started_by: sender,
                        created_at: now,
                        updated_at: now,
                        message_ids: Vec::new(),
                    },
                );
                id
            }
            Value::String(tid) => match inner.threads.get_mut(tid) {
                Some(t) => {
                    t.updated_at = now;
                    tid.clone()
                }
                None => return Err(RelayError::new(404, format!("thread {tid} not found"))),
            },
            _ => return Err(RelayError::bad_request("\"thread_id\" must be a string")),
        };

        let id = inner.next_id;
        inner.next_id += 1;
        let mut attachment_ids = Vec::with_capacity(atts.len());
        for a in atts {
            let att_id = format!("att_{}", random_hex(10));
            let sha256 = Sha256::digest(&a.data)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            inner.total_bytes += a.data.len() as u64;
            inner.attachments.insert(
                att_id.clone(),
                Attachment {
                    id: att_id.clone(),
                    message_id: id,
                    filename: a.filename,
                    content_type: a.content_type,
                    sha256,
                    data: Bytes::from(a.data),
                },
            );
            attachment_ids.push(att_id);
        }
        if let Some(t) = inner.threads.get_mut(&thread_id) {
            t.message_ids.push(id);
        }
        let message = Message {
            id,
            thread_id,
            sender,
            text: text.to_string(),
            created_at: now,
            read_at: None,
            attachment_ids,
            webhook_status: None,
        };
        let view = inner.fmt_message(&self.base, &message);
        inner.messages.insert(id, message);
        drop(inner);
        self.added.notify_waiters();
        Ok(view)
    }

    /// `reader` 宛て（相手が送った）メッセージ。`wait > 0` なら 1 件以上になるまで待つ。
    pub async fn list_incoming(&self, reader: Side, args: ListArgs) -> Result<Value, RelayError> {
        let from = reader.other();
        let after = if args.since.is_null() || args.since.as_str() == Some("") {
            0.0
        } else {
            js::number(&args.since)
        };
        if !after.is_finite() || after < 0.0 {
            return Err(RelayError::bad_request(
                "\"since\" must be a cursor value returned by this API",
            ));
        }
        let limit = clamp_limit(&args.limit, 50.0, 200.0);
        let unread_only = !matches!(&args.unread_only, Value::Bool(false))
            && !matches!(args.unread_only.as_str(), Some("false" | "0"));
        let thread_id = js::truthy_string(&args.thread_id);
        let wait = parse_wait(&args.wait)?;
        let start = first_id_after(after);

        let query = |inner: &Inner| -> Vec<MessageView> {
            inner
                .messages
                .range((Bound::Included(start), Bound::Unbounded))
                .map(|(_, m)| m)
                .filter(|m| m.sender == from)
                .filter(|m| !unread_only || m.read_at.is_none())
                .filter(|m| thread_id.as_deref().is_none_or(|t| m.thread_id == t))
                .take(limit)
                .map(|m| inner.fmt_message(&self.base, m))
                .collect()
        };
        let messages = self
            .wait_for(Duration::from_secs_f64(wait), |inner| {
                Some(query(inner)).filter(|rows| !rows.is_empty())
            })
            .await
            .unwrap_or_default();

        let unread_total = self.lock().unread_from(from);
        let next_cursor = match messages.last() {
            Some(m) => Value::String(m.cursor.clone()),
            None if after != 0.0 => Value::String(number_string(after)),
            None => Value::Null,
        };
        let has_more = messages.len() == limit;
        let timed_out = messages.is_empty();
        let mut out = json!({
            "messages": messages,
            "next_cursor": next_cursor,
            "unread_total": unread_total,
            "has_more": has_more,
        });
        if wait > 0.0 {
            out["timed_out"] = json!(timed_out);
        }
        Ok(out)
    }

    /// `thread_id` で `after_id` より後に相手が送った最初の 1 件を待つ（ask 用）。
    pub async fn wait_for_reply(
        &self,
        reader: Side,
        thread_id: &str,
        after_id: u64,
        wait_seconds: f64,
    ) -> Option<MessageView> {
        let from = reader.other();
        let wait = Duration::from_secs_f64(wait_seconds.clamp(0.0, MAX_WAIT_SECONDS));
        self.wait_for(wait, |inner| {
            let thread = inner.threads.get(thread_id)?;
            thread
                .message_ids
                .iter()
                .filter(|id| **id > after_id)
                .filter_map(|id| inner.messages.get(id))
                .find(|m| m.sender == from)
                .map(|m| inner.fmt_message(&self.base, m))
        })
        .await
    }

    pub fn get_thread(&self, id: &Value) -> Result<Value, RelayError> {
        let id = match id.as_str() {
            Some(s) if !s.is_empty() => s,
            _ => return Err(RelayError::bad_request("\"thread_id\" is required")),
        };
        let inner = self.lock();
        let Some(t) = inner.threads.get(id) else {
            return Err(RelayError::new(404, format!("thread {id} not found")));
        };
        let messages: Vec<MessageView> = t
            .message_ids
            .iter()
            .take(MAX_THREAD_MESSAGES)
            .filter_map(|id| inner.messages.get(id))
            .map(|m| inner.fmt_message(&self.base, m))
            .collect();
        Ok(json!({ "thread": inner.fmt_thread(t, None), "messages": messages }))
    }

    pub fn get_attachment(&self, id: &Value) -> Result<AttachmentContent, RelayError> {
        let id = match id.as_str() {
            Some(s)
                if s.len() > 4
                    && s.starts_with("att_")
                    && s[4..]
                        .bytes()
                        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) =>
            {
                s
            }
            _ => {
                return Err(RelayError::bad_request(
                    "\"attachment_id\" must look like att_...",
                ))
            }
        };
        let inner = self.lock();
        let (Some(a), Some(meta)) = (
            inner.attachments.get(id),
            inner.fmt_attachment(&self.base, id),
        ) else {
            return Err(RelayError::new(404, format!("attachment {id} not found")));
        };
        Ok(AttachmentContent {
            meta,
            message_id: a.message_id,
            data: a.data.clone(),
        })
    }

    pub fn list_threads(&self, reader: Side, limit: &Value) -> Value {
        let limit = clamp_limit(limit, 20.0, 100.0);
        let inner = self.lock();
        let mut threads: Vec<&Thread> = inner.threads.values().collect();
        threads.sort_by(|a, b| {
            (b.updated_at, b.message_ids.last()).cmp(&(a.updated_at, a.message_ids.last()))
        });
        let threads: Vec<ThreadView> = threads
            .into_iter()
            .take(limit)
            .map(|t| inner.fmt_thread(t, Some(reader)))
            .collect();
        json!({ "threads": threads })
    }

    /// `reader` 宛てのメッセージを既読にする。`message_ids` > `thread_id` > `up_to_cursor`。
    pub fn mark_read(&self, reader: Side, body: &Value) -> Result<Value, RelayError> {
        let empty = Map::new();
        let b = body.as_object().unwrap_or(&empty);
        let field = |k: &str| b.get(k).unwrap_or(&Value::Null);
        let from = reader.other();

        enum Target {
            Ids(Vec<u64>),
            Thread(String),
            UpTo(f64),
        }
        let target = match field("message_ids") {
            Value::Array(ids) if !ids.is_empty() => {
                let ids: Vec<f64> = ids
                    .iter()
                    .map(js::number)
                    .filter(|n| n.is_finite())
                    .collect();
                if ids.is_empty() {
                    return Err(RelayError::bad_request(
                        "\"message_ids\" must contain message ids",
                    ));
                }
                Target::Ids(
                    ids.into_iter()
                        .filter(|n| *n >= 0.0 && n.fract() == 0.0)
                        .map(|n| n as u64)
                        .collect(),
                )
            }
            _ => match js::truthy_string(field("thread_id")) {
                Some(t) => Target::Thread(t),
                None => {
                    let c = field("up_to_cursor");
                    if c.is_null() || c.as_str() == Some("") {
                        return Err(RelayError::bad_request(
                            "Provide one of \"message_ids\", \"thread_id\", or \"up_to_cursor\"",
                        ));
                    }
                    let c = js::number(c);
                    if !c.is_finite() {
                        return Err(RelayError::bad_request(
                            "\"up_to_cursor\" must be a cursor value",
                        ));
                    }
                    Target::UpTo(c)
                }
            },
        };

        let now = now_ms();
        let mut inner = self.lock();
        let mut marked = Vec::new();
        let mut mark = |m: &mut Message| {
            if m.sender == from && m.read_at.is_none() {
                m.read_at = Some(now);
                marked.push(m.id);
            }
        };
        match target {
            Target::Ids(ids) => {
                for id in ids {
                    if let Some(m) = inner.messages.get_mut(&id) {
                        mark(m);
                    }
                }
            }
            Target::Thread(tid) => {
                let ids = inner
                    .threads
                    .get(&tid)
                    .map(|t| t.message_ids.clone())
                    .unwrap_or_default();
                for id in ids {
                    if let Some(m) = inner.messages.get_mut(&id) {
                        mark(m);
                    }
                }
            }
            Target::UpTo(c) if c >= 0.0 => {
                let upper = if c >= u64::MAX as f64 {
                    u64::MAX
                } else {
                    c.floor() as u64
                };
                for (_, m) in inner.messages.range_mut(..=upper) {
                    mark(m);
                }
            }
            Target::UpTo(_) => {}
        }
        marked.sort_unstable();
        marked.dedup();
        let ids: Vec<String> = marked.iter().map(u64::to_string).collect();
        Ok(json!({ "marked_read": ids.len(), "message_ids": ids }))
    }

    pub fn set_webhook_status(&self, id: &str, status: String) {
        let Ok(id) = id.parse::<u64>() else { return };
        if let Some(m) = self.lock().messages.get_mut(&id) {
            m.webhook_status = Some(status);
        }
    }

    #[cfg(test)]
    pub fn webhook_status(&self, id: &str) -> Option<String> {
        let id = id.parse::<u64>().ok()?;
        self.lock().messages.get(&id)?.webhook_status.clone()
    }

    #[cfg(test)]
    pub fn total_bytes(&self) -> u64 {
        self.lock().total_bytes
    }
}

#[cfg(test)]
mod store_tests {
    use super::*;

    #[test]
    fn iso_matches_js_to_iso_string() {
        assert_eq!(iso_ms(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_ms(951_782_400_000), "2000-02-29T00:00:00.000Z");
        assert_eq!(iso_ms(1_700_000_000_123), "2023-11-14T22:13:20.123Z");
        assert_eq!(iso_ms(4_102_444_799_999), "2099-12-31T23:59:59.999Z");
    }

    #[test]
    fn base64_is_lenient_like_node() {
        assert_eq!(decode_base64("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(decode_base64("aGVsbG8").unwrap(), b"hello");
        assert_eq!(
            decode_base64("data:text/plain;base64,aGVs\nbG8=").unwrap(),
            b"hello"
        );
        assert_eq!(decode_base64("-_8").unwrap(), decode_base64("+/8").unwrap());
        assert!(decode_base64("aGVsbG8===").is_none());
        assert!(decode_base64("aGV*bG8=").is_none());
    }

    #[test]
    fn subject_prefix_counts_utf16_units() {
        assert_eq!(utf16_prefix("abc", 2), "ab");
        assert_eq!(utf16_prefix("a😀b", 2), "a");
        assert_eq!(utf16_prefix("a😀b", 3), "a😀");
        assert_eq!(utf16_prefix("abc", 80), "abc");
    }

    #[tokio::test]
    async fn close_ends_waits_at_once() {
        let store = std::sync::Arc::new(Store::new("https://x/relay/v1", 100));
        let waiter = store.clone();
        let started = std::time::Instant::now();
        let poll = tokio::spawn(async move {
            waiter
                .list_incoming(
                    Side::Muse,
                    ListArgs {
                        wait: json!(30),
                        ..Default::default()
                    },
                )
                .await
        });
        while store.waiting() == 0 {
            tokio::task::yield_now().await;
        }
        store.close();
        let out = poll.await.unwrap().unwrap();
        assert_eq!(out["timed_out"], true);
        assert!(started.elapsed() < Duration::from_secs(2));
        // 停止後の待機も即座に返る
        assert!(store
            .wait_for_reply(Side::Muse, "thr_x", 0, 30.0)
            .await
            .is_none());
        assert_eq!(store.waiting(), 0);
    }

    #[test]
    fn ids_start_from_the_clock() {
        let before = now_ms() as u64;
        let store = Store::new("https://x/relay/v1", 100);
        let m = store
            .send_message(Side::Muse, &json!({ "text": "hi" }))
            .unwrap();
        let id: u64 = m.id.parse().unwrap();
        assert!(id >= before && id <= now_ms() as u64, "{id}");
        assert_eq!(m.id, m.cursor);
    }
}
