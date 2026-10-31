//! メモリ内ストア（元 lib/store.js の移植）。再起動で全て消える。
//!
//! データは「部屋」（OAuth の subject = GitHub 数値 id）ごとに分かれ、部屋をまたいで見えない。
//! メッセージ id はカーソルを兼ねる。部屋ごとのカウンタを部屋を最初に使った時刻の Unix ミリ秒から始めるので、
//! 再起動前のカーソルより新しいメッセージの id が必ず大きくなり、id の差から他の部屋の動きは読めない。
//!
//! 保存量は部屋ごとと全部屋の合計の両方で数え（`Limits`）、上限を超える書き込みは断る。自動では消さない。

use super::js::{self, is_js_whitespace, utf16_len};
use super::webhook::WebhookTarget;
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;
use tokio::time::Instant;

pub const MAX_TEXT: usize = 20_000;
pub const MAX_SUBJECT: usize = 200;
pub const MAX_FILE_BYTES: usize = 3 * 1024 * 1024;
pub const MAX_FILES_PER_MESSAGE: usize = 5;
const MB: u64 = 1024 * 1024;
/// RELAY_MAX_TOTAL_STORAGE_BYTES の既定（全部屋の添付の合計）。1 部屋はその半分まで。
pub const DEFAULT_MAX_TOTAL_STORAGE_BYTES: u64 = 64 * MB;
pub const MAX_WAIT_SECONDS: f64 = 280.0;
pub const MAX_THREAD_MESSAGES: usize = 500;
pub const MAX_AGENT_NAME: usize = 64;

// 保存量の概算で 1 件ごとに足す固定分（構造体・map のノード・id 文字列・アロケータの端数）
const MESSAGE_OVERHEAD: u64 = 320;
const THREAD_OVERHEAD: u64 = 256;
const ATTACHMENT_OVERHEAD: u64 = 256;
const AGENT_OVERHEAD: u64 = 128;

/// relay がメモリに抱える量の上限。部屋ごとの値と全部屋の合計の両方で数える。
#[derive(Debug, Clone)]
pub struct Limits {
    pub room_messages: usize,
    pub total_messages: usize,
    /// 本文・名前・件名・添付のメタ情報・スレッド・登録の概算バイト数
    pub room_data_bytes: u64,
    pub total_data_bytes: u64,
    /// 添付の中身
    pub room_attachment_bytes: u64,
    pub total_attachment_bytes: u64,
    /// `register_agent` の登録数
    pub room_agents: usize,
    /// 同時に待機できる ask / check_messages
    pub room_waits: usize,
    pub total_waits: usize,
}

impl Limits {
    /// 添付の全体上限（RELAY_MAX_TOTAL_STORAGE_BYTES）と既定値。部屋ごとの値は全体の半分。
    pub fn with_total_attachment_bytes(total_attachment_bytes: u64) -> Self {
        Self {
            room_messages: 10_000,
            total_messages: 20_000,
            room_data_bytes: 32 * MB,
            total_data_bytes: 64 * MB,
            room_attachment_bytes: total_attachment_bytes / 2,
            total_attachment_bytes,
            room_agents: 100,
            room_waits: 16,
            total_waits: 64,
        }
    }
}

/// 保存済みの量。メッセージと添付は消さないので増えるだけ、登録は置き換え・解除で戻る。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Usage {
    pub messages: usize,
    pub data_bytes: u64,
    pub attachment_bytes: u64,
}

impl Usage {
    fn add(&mut self, other: Usage) {
        self.messages += other.messages;
        self.data_bytes += other.data_bytes;
        self.attachment_bytes += other.attachment_bytes;
    }
}

/// 上限に達したときのエラー（507 相当）。
fn full(what: String) -> RelayError {
    RelayError::new(
        507,
        format!("{what}; the relay keeps data in memory and frees it only when it restarts"),
    )
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
}

#[derive(Debug, Clone, Serialize)]
pub struct MessageView {
    pub id: String,
    pub cursor: String,
    pub thread_id: String,
    pub from: String,
    pub to: String,
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
    pub started_by: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unread_count: Option<usize>,
}

/// `get_attachment` 用。
pub struct AttachmentContent {
    pub meta: AttachmentView,
    pub message_id: u64,
    pub data: Bytes,
}

struct Thread {
    id: String,
    subject: String,
    started_by: String,
    created_at: i64,
    updated_at: i64,
    message_ids: Vec<u64>,
}

struct Message {
    id: u64,
    thread_id: String,
    from: String,
    to: String,
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

/// `register_agent` の登録。webhook の値は API に出さない。
struct AgentRecord {
    webhook: Option<WebhookTarget>,
    /// 保存量に数えた分
    bytes: u64,
}

fn agent_bytes(name: &str, webhook: Option<&WebhookTarget>) -> u64 {
    let webhook = webhook.map_or(0, |w| {
        w.url.len() + w.auth.as_ref().map_or(0, String::len) + w.secret.len()
    });
    AGENT_OVERHEAD + (name.len() + webhook) as u64
}

struct Room {
    /// 次のメッセージ id（部屋ごと）
    next_id: u64,
    threads: HashMap<String, Thread>,
    messages: BTreeMap<u64, Message>,
    attachments: HashMap<String, Attachment>,
    agents: BTreeMap<String, AgentRecord>,
    usage: Usage,
}

struct Inner {
    rooms: HashMap<String, Room>,
    /// 全部屋の合計
    usage: Usage,
}

/// 待機中の long-poll。部屋ごとに起床用の `Notify` を持ち、送信はその部屋の待機だけを起こす。
#[derive(Default)]
struct Waiters {
    total: usize,
    rooms: HashMap<String, RoomWaiters>,
}

struct RoomWaiters {
    count: usize,
    wake: Arc<Notify>,
}

/// long-poll 1 件分の枠。drop で返る。
pub struct WaitSlot<'a> {
    store: &'a Store,
    room: String,
    wake: Arc<Notify>,
}

impl Drop for WaitSlot<'_> {
    fn drop(&mut self) {
        let mut w = self.store.lock_waiters();
        w.total -= 1;
        let empty = w.rooms.get_mut(&self.room).is_some_and(|r| {
            r.count -= 1;
            r.count == 0
        });
        if empty {
            w.rooms.remove(&self.room);
        }
    }
}

pub struct Store {
    inner: Mutex<Inner>,
    waiters: Mutex<Waiters>,
    /// 停止中。以後の long-poll は待たずに返す。
    closed: AtomicBool,
    limits: Limits,
}

/// エージェント名（自己申告）。1–64 文字、空白だけ・制御文字は不可。大文字小文字は区別する。
pub fn agent_name(v: &Value, field: &str) -> Result<String, RelayError> {
    match v {
        Value::String(s)
            if (1..=MAX_AGENT_NAME).contains(&s.chars().count())
                && !js::trim(s).is_empty()
                && !s.chars().any(char::is_control) =>
        {
            Ok(s.clone())
        }
        Value::Null => Err(RelayError::bad_request(format!("\"{field}\" is required"))),
        _ => Err(RelayError::bad_request(format!(
            "\"{field}\" must be an agent name: 1-{MAX_AGENT_NAME} characters, not only whitespace, no control characters"
        ))),
    }
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

impl Room {
    fn new() -> Self {
        Self {
            next_id: now_ms().max(1) as u64,
            threads: HashMap::new(),
            messages: BTreeMap::new(),
            attachments: HashMap::new(),
            agents: BTreeMap::new(),
            usage: Usage::default(),
        }
    }

    fn fmt_attachment(&self, id: &str) -> Option<AttachmentView> {
        let a = self.attachments.get(id)?;
        Some(AttachmentView {
            id: a.id.clone(),
            filename: a.filename.clone(),
            content_type: a.content_type.clone(),
            size: a.data.len(),
            sha256: a.sha256.clone(),
        })
    }

    fn fmt_message(&self, m: &Message) -> MessageView {
        MessageView {
            id: m.id.to_string(),
            cursor: m.id.to_string(),
            thread_id: m.thread_id.clone(),
            from: m.from.clone(),
            to: m.to.clone(),
            text: m.text.clone(),
            created_at: iso_ms(m.created_at),
            read: m.read_at.is_some(),
            read_at: m.read_at.map(iso_ms),
            attachments: m
                .attachment_ids
                .iter()
                .filter_map(|id| self.fmt_attachment(id))
                .collect(),
        }
    }

    /// `counts` が Some なら message_count を付け、さらに Some(agent) ならその宛先の未読数も付ける。
    fn fmt_thread(&self, t: &Thread, counts: Option<Option<&str>>) -> ThreadView {
        let (message_count, unread_count) = match counts {
            None => (None, None),
            Some(reader) => {
                let unread = reader.map(|agent| {
                    t.message_ids
                        .iter()
                        .filter_map(|id| self.messages.get(id))
                        .filter(|m| m.to == agent && m.read_at.is_none())
                        .count()
                });
                (Some(t.message_ids.len()), unread)
            }
        };
        ThreadView {
            id: t.id.clone(),
            subject: t.subject.clone(),
            started_by: t.started_by.clone(),
            created_at: iso_ms(t.created_at),
            updated_at: iso_ms(t.updated_at),
            message_count,
            unread_count,
        }
    }

    fn unread_to(&self, agent: &str) -> usize {
        self.messages
            .values()
            .filter(|m| m.to == agent && m.read_at.is_none())
            .count()
    }
}

impl Inner {
    fn room(&self, room: &str) -> Option<&Room> {
        self.rooms.get(room)
    }
}

impl Store {
    pub fn new(limits: Limits) -> Self {
        Self {
            inner: Mutex::new(Inner {
                rooms: HashMap::new(),
                usage: Usage::default(),
            }),
            waiters: Mutex::default(),
            closed: AtomicBool::new(false),
            limits,
        }
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn lock_waiters(&self) -> MutexGuard<'_, Waiters> {
        self.waiters.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// long-poll 中のリクエスト数。
    #[cfg(test)]
    pub fn waiting(&self) -> usize {
        self.lock_waiters().total
    }

    /// 待機中・以後の long-poll をすぐ返させる。graceful shutdown が待たされないように。
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        for r in self.lock_waiters().rooms.values() {
            r.wake.notify_waiters();
        }
    }

    /// long-poll の枠を取る。部屋ごと・全体の上限を超えるなら待たずにエラー。
    pub fn reserve_wait(&self, room: &str) -> Result<WaitSlot<'_>, RelayError> {
        let l = &self.limits;
        let mut w = self.lock_waiters();
        if w.total >= l.total_waits {
            return Err(RelayError::new(
                429,
                format!(
                    "the relay already has {} waiting calls (its limit); try again shortly, or pass wait_seconds 0",
                    l.total_waits
                ),
            ));
        }
        if w.rooms.get(room).map_or(0, |r| r.count) >= l.room_waits {
            return Err(RelayError::new(
                429,
                format!(
                    "this room already has {} waiting ask/check_messages calls (its limit); let one finish, or pass wait_seconds 0",
                    l.room_waits
                ),
            ));
        }
        w.total += 1;
        let r = w
            .rooms
            .entry(room.to_string())
            .or_insert_with(|| RoomWaiters {
                count: 0,
                wake: Arc::default(),
            });
        r.count += 1;
        Ok(WaitSlot {
            store: self,
            room: room.to_string(),
            wake: r.wake.clone(),
        })
    }

    /// `room` で待っている long-poll に再判定させる。
    fn wake(&self, room: &str) {
        if let Some(r) = self.lock_waiters().rooms.get(room) {
            r.wake.notify_waiters();
        }
    }

    /// `check` が値を返すか `wait` が過ぎるまで待つ。枠が無いか `wait` が 0 なら 1 回だけ見る。
    /// 同じ部屋へのメッセージ追加で再判定する。呼び出し側の future が drop されれば（クライアント切断）
    /// 待機もそこで終わる。
    async fn wait_for<T>(
        &self,
        slot: Option<&WaitSlot<'_>>,
        wait: Duration,
        mut check: impl FnMut(&Inner) -> Option<T>,
    ) -> Option<T> {
        let Some(slot) = slot.filter(|_| !wait.is_zero()) else {
            return check(&self.lock());
        };
        let deadline = Instant::now() + wait;
        loop {
            let notified = slot.wake.notified();
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

    /// `add` を足しても部屋（`room`）と全体の上限に収まるか。
    fn check_capacity(&self, room: Usage, total: Usage, add: Usage) -> Result<(), RelayError> {
        let l = &self.limits;
        let over = |used: u64, add: u64, limit: u64| add > 0 && used + add > limit;
        let count = |n: usize| n as u64;
        if over(
            count(room.messages),
            count(add.messages),
            count(l.room_messages),
        ) {
            return Err(full(format!(
                "this room already holds {} messages (its limit)",
                l.room_messages
            )));
        }
        if over(
            count(total.messages),
            count(add.messages),
            count(l.total_messages),
        ) {
            return Err(full(format!(
                "the relay already holds {} messages across all rooms (its limit)",
                l.total_messages
            )));
        }
        if over(room.data_bytes, add.data_bytes, l.room_data_bytes) {
            return Err(full(format!(
                "this room's message storage is full ({} bytes of text and metadata)",
                l.room_data_bytes
            )));
        }
        if over(total.data_bytes, add.data_bytes, l.total_data_bytes) {
            return Err(full(format!(
                "the relay's message storage is full ({} bytes across all rooms)",
                l.total_data_bytes
            )));
        }
        if over(
            room.attachment_bytes,
            add.attachment_bytes,
            l.room_attachment_bytes,
        ) {
            return Err(full(format!(
                "this room's attachment storage is full ({} bytes)",
                l.room_attachment_bytes
            )));
        }
        if over(
            total.attachment_bytes,
            add.attachment_bytes,
            l.total_attachment_bytes,
        ) {
            return Err(full(format!(
                "the relay's attachment storage is full ({} bytes across all rooms)",
                l.total_attachment_bytes
            )));
        }
        Ok(())
    }

    /// `from` から `to` へのメッセージを保存する。宛先に webhook の登録があればそれも返す。
    pub fn send_message(
        &self,
        room: &str,
        from: &str,
        to: &str,
        b: &Map<String, Value>,
    ) -> Result<(MessageView, Option<WebhookTarget>), RelayError> {
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
        let thread_id = match field("thread_id") {
            Value::Null => None,
            Value::String(tid) => Some(tid.as_str()),
            _ => return Err(RelayError::bad_request("\"thread_id\" must be a string")),
        };
        // 新しいスレッドの件名
        let new_subject = thread_id.is_none().then(|| {
            subject
                .filter(|s| !s.is_empty())
                .or_else(|| Some(utf16_prefix(text, 80)).filter(|s| !s.is_empty()))
                .or_else(|| atts.first().map(|a| a.filename.as_str()))
                .filter(|s| !s.is_empty())
                .unwrap_or("attachment")
                .to_string()
        });
        let add = Usage {
            messages: 1,
            data_bytes: MESSAGE_OVERHEAD
                + (from.len() + to.len() + text.len()) as u64
                + new_subject
                    .as_ref()
                    .map_or(0, |s| THREAD_OVERHEAD + (s.len() + from.len()) as u64)
                + atts
                    .iter()
                    .map(|a| ATTACHMENT_OVERHEAD + (a.filename.len() + a.content_type.len()) as u64)
                    .sum::<u64>(),
            attachment_bytes: atts.iter().map(|a| a.data.len() as u64).sum(),
        };

        let mut guard = self.lock();
        let inner = &mut *guard;
        let existing = inner.rooms.get(room);
        if let Some(tid) = thread_id {
            let Some(t) = existing.and_then(|r| r.threads.get(tid)) else {
                return Err(RelayError::new(404, format!("thread {tid} not found")));
            };
            if t.message_ids.len() >= MAX_THREAD_MESSAGES {
                return Err(RelayError::new(
                    409,
                    format!("thread {tid} is full ({MAX_THREAD_MESSAGES} messages); start a new thread by omitting thread_id"),
                ));
            }
        }
        self.check_capacity(
            existing.map_or_else(Usage::default, |r| r.usage),
            inner.usage,
            add,
        )?;
        inner.usage.add(add);
        let r = inner
            .rooms
            .entry(room.to_string())
            .or_insert_with(Room::new);
        r.usage.add(add);
        let id = r.next_id;
        r.next_id += 1;
        let now = now_ms();
        let thread_id = match (thread_id, new_subject) {
            (Some(tid), _) => tid.to_string(),
            (None, subject) => {
                let tid = format!("thr_{}", random_hex(8));
                r.threads.insert(
                    tid.clone(),
                    Thread {
                        id: tid.clone(),
                        subject: subject.unwrap_or_default(),
                        started_by: from.to_string(),
                        created_at: now,
                        updated_at: now,
                        message_ids: Vec::new(),
                    },
                );
                tid
            }
        };
        if let Some(t) = r.threads.get_mut(&thread_id) {
            t.updated_at = now;
            t.message_ids.push(id);
        }

        let mut attachment_ids = Vec::with_capacity(atts.len());
        for a in atts {
            let att_id = format!("att_{}", random_hex(10));
            let sha256 = Sha256::digest(&a.data)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            r.attachments.insert(
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
        let target = r.agents.get(to).and_then(|a| a.webhook.clone());
        let message = Message {
            id,
            thread_id,
            from: from.to_string(),
            to: to.to_string(),
            text: text.to_string(),
            created_at: now,
            read_at: None,
            attachment_ids,
            webhook_status: target.is_none().then(|| "skipped:no_webhook".to_string()),
        };
        let view = r.fmt_message(&message);
        r.messages.insert(id, message);
        drop(guard);
        self.wake(room);
        Ok((view, target))
    }

    /// 部屋内で `agent` 宛てのメッセージ。`wait > 0` なら 1 件以上になるまで待つ。
    pub async fn check_messages(
        &self,
        room: &str,
        agent: &str,
        args: ListArgs,
    ) -> Result<Value, RelayError> {
        let after = if args.since.is_null() || args.since.as_str() == Some("") {
            0.0
        } else {
            js::number(&args.since)
        };
        if !after.is_finite() || after < 0.0 {
            return Err(RelayError::bad_request(
                "\"since_cursor\" must be a cursor value returned by this API",
            ));
        }
        let limit = clamp_limit(&args.limit, 50.0, 200.0);
        let unread_only = !matches!(&args.unread_only, Value::Bool(false))
            && !matches!(args.unread_only.as_str(), Some("false" | "0"));
        let thread_id = js::truthy_string(&args.thread_id);
        let wait = parse_wait(&args.wait)?;
        let slot = if wait > 0.0 {
            Some(self.reserve_wait(room)?)
        } else {
            None
        };
        let mut start = first_id_after(after);

        let query = |inner: &Inner| -> Option<Vec<MessageView>> {
            let r = inner.room(room)?;
            let rows: Vec<MessageView> = r
                .messages
                .range((Bound::Included(start), Bound::Unbounded))
                .map(|(_, m)| m)
                .filter(|m| m.to == agent)
                .filter(|m| !unread_only || m.read_at.is_none())
                .filter(|m| thread_id.as_deref().is_none_or(|t| m.thread_id == t))
                .take(limit)
                .map(|m| r.fmt_message(m))
                .collect();
            if rows.is_empty() {
                // 既存のメッセージが後から条件に合うことはないので、次は新しく増えた分だけ見る
                start = start.max(r.next_id);
                return None;
            }
            Some(rows)
        };
        let messages = self
            .wait_for(slot.as_ref(), Duration::from_secs_f64(wait), query)
            .await
            .unwrap_or_default();
        drop(slot);

        let unread_total = self.lock().room(room).map_or(0, |r| r.unread_to(agent));
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

    /// `thread_id` で `after_id` より後に `peer` が `agent` へ送った最初の 1 件を待つ（ask 用）。
    /// 待つには `reserve_wait` の枠が要る。
    #[allow(clippy::too_many_arguments)]
    pub async fn wait_for_reply(
        &self,
        slot: Option<&WaitSlot<'_>>,
        room: &str,
        agent: &str,
        peer: &str,
        thread_id: &str,
        after_id: u64,
        wait_seconds: f64,
    ) -> Option<MessageView> {
        let wait = Duration::from_secs_f64(wait_seconds.clamp(0.0, MAX_WAIT_SECONDS));
        self.wait_for(slot, wait, |inner| {
            let r = inner.room(room)?;
            let thread = r.threads.get(thread_id)?;
            thread
                .message_ids
                .iter()
                .filter(|id| **id > after_id)
                .filter_map(|id| r.messages.get(id))
                .find(|m| m.from == peer && m.to == agent)
                .map(|m| r.fmt_message(m))
        })
        .await
    }

    pub fn get_thread(&self, room: &str, id: &Value) -> Result<Value, RelayError> {
        let id = match id.as_str() {
            Some(s) if !s.is_empty() => s,
            _ => return Err(RelayError::bad_request("\"thread_id\" is required")),
        };
        let inner = self.lock();
        let Some((r, t)) = inner.room(room).and_then(|r| Some((r, r.threads.get(id)?))) else {
            return Err(RelayError::new(404, format!("thread {id} not found")));
        };
        let messages: Vec<MessageView> = t
            .message_ids
            .iter()
            .take(MAX_THREAD_MESSAGES)
            .filter_map(|id| r.messages.get(id))
            .map(|m| r.fmt_message(m))
            .collect();
        Ok(json!({ "thread": r.fmt_thread(t, None), "messages": messages }))
    }

    pub fn get_attachment(&self, room: &str, id: &Value) -> Result<AttachmentContent, RelayError> {
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
        let found = inner
            .room(room)
            .and_then(|r| Some((r.attachments.get(id)?, r.fmt_attachment(id)?)));
        let Some((a, meta)) = found else {
            return Err(RelayError::new(404, format!("attachment {id} not found")));
        };
        Ok(AttachmentContent {
            meta,
            message_id: a.message_id,
            data: a.data.clone(),
        })
    }

    /// 部屋内のスレッドを新しい順に。`agent` があればその宛先の未読数を付ける。
    pub fn list_threads(&self, room: &str, agent: Option<&str>, limit: &Value) -> Value {
        let limit = clamp_limit(limit, 20.0, 100.0);
        let inner = self.lock();
        let Some(r) = inner.room(room) else {
            return json!({ "threads": [] });
        };
        let mut threads: Vec<&Thread> = r.threads.values().collect();
        threads.sort_by(|a, b| {
            (b.updated_at, b.message_ids.last()).cmp(&(a.updated_at, a.message_ids.last()))
        });
        let threads: Vec<ThreadView> = threads
            .into_iter()
            .take(limit)
            .map(|t| r.fmt_thread(t, Some(agent)))
            .collect();
        json!({ "threads": threads })
    }

    /// `agent` 宛てのメッセージを既読にする。`message_ids` > `thread_id` > `up_to_cursor`。
    pub fn mark_read(&self, room: &str, agent: &str, body: &Value) -> Result<Value, RelayError> {
        let empty = Map::new();
        let b = body.as_object().unwrap_or(&empty);
        let field = |k: &str| b.get(k).unwrap_or(&Value::Null);

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
        if let Some(r) = inner.rooms.get_mut(room) {
            let mut mark = |m: &mut Message| {
                if m.to == agent && m.read_at.is_none() {
                    m.read_at = Some(now);
                    marked.push(m.id);
                }
            };
            match target {
                Target::Ids(ids) => {
                    for id in ids {
                        if let Some(m) = r.messages.get_mut(&id) {
                            mark(m);
                        }
                    }
                }
                Target::Thread(tid) => {
                    let ids = r
                        .threads
                        .get(&tid)
                        .map(|t| t.message_ids.clone())
                        .unwrap_or_default();
                    for id in ids {
                        if let Some(m) = r.messages.get_mut(&id) {
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
                    for (_, m) in r.messages.range_mut(..=upper) {
                        mark(m);
                    }
                }
                Target::UpTo(_) => {}
            }
        }
        marked.sort_unstable();
        marked.dedup();
        let ids: Vec<String> = marked.iter().map(u64::to_string).collect();
        Ok(json!({ "marked_read": ids.len(), "message_ids": ids }))
    }

    /// 登録を丸ごと置き換える。webhook の有無を返す。
    pub fn register_agent(
        &self,
        room: &str,
        agent: &str,
        webhook: Option<WebhookTarget>,
    ) -> Result<bool, RelayError> {
        let bytes = agent_bytes(agent, webhook.as_ref());
        let mut guard = self.lock();
        let inner = &mut *guard;
        let existing = inner.rooms.get(room);
        let old = existing.and_then(|r| r.agents.get(agent)).map(|a| a.bytes);
        if old.is_none() && existing.is_some_and(|r| r.agents.len() >= self.limits.room_agents) {
            return Err(RelayError::new(
                507,
                format!(
                    "this room already has {} registered agents (its limit); unregister one first",
                    self.limits.room_agents
                ),
            ));
        }
        let old = old.unwrap_or(0);
        let grow = Usage {
            data_bytes: bytes.saturating_sub(old),
            ..Usage::default()
        };
        self.check_capacity(
            existing.map_or_else(Usage::default, |r| r.usage),
            inner.usage,
            grow,
        )?;
        let r = inner
            .rooms
            .entry(room.to_string())
            .or_insert_with(Room::new);
        for usage in [&mut inner.usage, &mut r.usage] {
            usage.data_bytes = usage.data_bytes - old + bytes;
        }
        let has_webhook = webhook.is_some();
        r.agents
            .insert(agent.to_string(), AgentRecord { webhook, bytes });
        Ok(has_webhook)
    }

    /// 登録を消す（メッセージは残る）。消えたかどうかを返す。
    pub fn unregister_agent(&self, room: &str, agent: &str) -> bool {
        let mut guard = self.lock();
        let inner = &mut *guard;
        let Some(r) = inner.rooms.get_mut(room) else {
            return false;
        };
        let Some(old) = r.agents.remove(agent) else {
            return false;
        };
        r.usage.data_bytes -= old.bytes;
        inner.usage.data_bytes -= old.bytes;
        true
    }

    /// 登録 ∪ メッセージの from/to を名前順に。webhook の値は出さない。
    pub fn list_agents(&self, room: &str) -> Value {
        let inner = self.lock();
        let Some(r) = inner.room(room) else {
            return json!({ "agents": [] });
        };
        let mut names: BTreeMap<&str, bool> = r
            .agents
            .iter()
            .map(|(name, a)| (name.as_str(), a.webhook.is_some()))
            .collect();
        for m in r.messages.values() {
            names.entry(&m.from).or_insert(false);
            names.entry(&m.to).or_insert(false);
        }
        let agents: Vec<Value> = names
            .into_iter()
            .map(|(name, webhook)| json!({ "name": name, "webhook": webhook }))
            .collect();
        json!({ "agents": agents })
    }

    pub fn set_webhook_status(&self, room: &str, id: &str, status: String) {
        let Ok(id) = id.parse::<u64>() else { return };
        if let Some(m) = self
            .lock()
            .rooms
            .get_mut(room)
            .and_then(|r| r.messages.get_mut(&id))
        {
            m.webhook_status = Some(status);
        }
    }

    #[cfg(test)]
    pub fn webhook_status(&self, room: &str, id: &str) -> Option<String> {
        let id = id.parse::<u64>().ok()?;
        self.lock()
            .rooms
            .get(room)?
            .messages
            .get(&id)?
            .webhook_status
            .clone()
    }

    /// 部屋の保存量と全体の保存量。
    #[cfg(test)]
    pub fn usage(&self, room: &str) -> (Usage, Usage) {
        let inner = self.lock();
        let r = inner.room(room).map_or_else(Usage::default, |r| r.usage);
        (r, inner.usage)
    }
}

#[cfg(test)]
mod store_tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;

    /// 今すぐ終わっているか（待たない）。
    async fn ready<F: std::future::Future>(f: F) -> bool {
        tokio::time::timeout(Duration::ZERO, f).await.is_ok()
    }

    const ROOM: &str = "2429307";
    const OTHER: &str = "1001";

    fn args(v: Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap()
    }

    fn target(url: &str) -> WebhookTarget {
        WebhookTarget {
            url: url.into(),
            auth: None,
            secret: "s".into(),
        }
    }

    fn store() -> Store {
        Store::new(Limits::with_total_attachment_bytes(1024))
    }

    fn send(store: &Store, room: &str, v: Value) -> Result<MessageView, RelayError> {
        store
            .send_message(room, "muse", "grok", &args(v))
            .map(|(m, _)| m)
    }

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

    #[test]
    fn agent_names_are_validated() {
        for ok in ["grok", "Grok", "muse bot", "ミューズ", &"x".repeat(64)] {
            assert_eq!(agent_name(&json!(ok), "agent").unwrap(), ok);
        }
        assert_eq!(
            agent_name(&Value::Null, "to").unwrap_err().message,
            "\"to\" is required"
        );
        for bad in [
            json!(""),
            json!("   "),
            json!("a\nb"),
            json!("a\u{7}"),
            json!(1),
            json!("x".repeat(65)),
        ] {
            assert!(agent_name(&bad, "agent").is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn close_ends_waits_at_once() {
        let store = std::sync::Arc::new(store());
        let waiter = store.clone();
        let started = std::time::Instant::now();
        let poll = tokio::spawn(async move {
            waiter
                .check_messages(
                    ROOM,
                    "muse",
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
        let slot = store.reserve_wait(ROOM).unwrap();
        assert!(store
            .wait_for_reply(Some(&slot), ROOM, "muse", "grok", "thr_x", 0, 30.0)
            .await
            .is_none());
        drop(slot);
        assert_eq!(store.waiting(), 0);
    }

    #[test]
    fn ids_start_from_the_clock() {
        let before = now_ms() as u64;
        let store = store();
        let (m, _) = store
            .send_message(ROOM, "muse", "grok", &args(json!({ "text": "hi" })))
            .unwrap();
        let id: u64 = m.id.parse().unwrap();
        assert!(id >= before && id <= now_ms() as u64, "{id}");
        assert_eq!(m.id, m.cursor);
        assert_eq!((m.from.as_str(), m.to.as_str()), ("muse", "grok"));
    }

    #[tokio::test]
    async fn rooms_do_not_see_each_other() {
        let store = store();
        let (m, _) = store
            .send_message(
                ROOM,
                "muse",
                "grok",
                &args(json!({
                    "text": "secret plan",
                    "attachments": [{ "filename": "a.txt", "content_base64": "aGk=" }],
                })),
            )
            .unwrap();
        store
            .register_agent(ROOM, "grok", Some(target("https://hook.example/a")))
            .unwrap();
        let att = m.attachments[0].id.clone();

        let check = |room: &'static str| {
            store.check_messages(
                room,
                "grok",
                ListArgs {
                    unread_only: json!(false),
                    ..Default::default()
                },
            )
        };
        assert_eq!(check(ROOM).await.unwrap()["messages"][0]["id"], m.id);
        assert_eq!(check(OTHER).await.unwrap()["messages"], json!([]));
        assert_eq!(check(OTHER).await.unwrap()["unread_total"], 0);

        let thread = json!(m.thread_id);
        assert!(store.get_thread(ROOM, &thread).is_ok());
        assert_eq!(store.get_thread(OTHER, &thread).unwrap_err().status, 404);
        assert!(store.get_attachment(ROOM, &json!(att)).is_ok());
        assert_eq!(
            store
                .get_attachment(OTHER, &json!(att))
                .err()
                .unwrap()
                .status,
            404
        );
        assert_eq!(
            store.list_threads(OTHER, Some("grok"), &Value::Null),
            json!({ "threads": [] })
        );
        assert_eq!(store.list_agents(OTHER), json!({ "agents": [] }));
        assert_eq!(
            store
                .mark_read(OTHER, "grok", &json!({ "message_ids": [m.id] }))
                .unwrap()["marked_read"],
            0
        );
        // 別の部屋から既存スレッドへは書けない
        let err = store
            .send_message(
                OTHER,
                "muse",
                "grok",
                &args(json!({ "text": "x", "thread_id": m.thread_id })),
            )
            .unwrap_err();
        assert_eq!(err.status, 404);

        // 登録も部屋ごと。別の部屋の grok 宛てでは webhook の対象にならない
        let (_, hook) = store
            .send_message(OTHER, "muse", "grok", &args(json!({ "text": "x" })))
            .unwrap();
        assert!(hook.is_none());
        let (_, hook) = store
            .send_message(ROOM, "muse", "grok", &args(json!({ "text": "x" })))
            .unwrap();
        assert_eq!(hook.unwrap().url, "https://hook.example/a");
        assert!(!store.unregister_agent(OTHER, "grok"));
        assert!(store.unregister_agent(ROOM, "grok"));
        let (_, hook) = store
            .send_message(ROOM, "muse", "grok", &args(json!({ "text": "x" })))
            .unwrap();
        assert!(hook.is_none());
    }

    #[tokio::test]
    async fn replies_must_come_from_the_peer_to_the_asker() {
        let store = store();
        let (q, _) = store
            .send_message(ROOM, "muse", "grok", &args(json!({ "text": "q" })))
            .unwrap();
        let after: u64 = q.id.parse().unwrap();
        let in_thread = |text: &str| args(json!({ "text": text, "thread_id": q.thread_id }));
        store
            .send_message(ROOM, "carol", "muse", &in_thread("not grok"))
            .unwrap();
        store
            .send_message(ROOM, "grok", "carol", &in_thread("not to muse"))
            .unwrap();
        let reply = store
            .wait_for_reply(None, ROOM, "muse", "grok", &q.thread_id, after, 0.0)
            .await;
        assert!(reply.is_none());
        store
            .send_message(ROOM, "grok", "muse", &in_thread("answer"))
            .unwrap();
        let reply = store
            .wait_for_reply(None, ROOM, "muse", "grok", &q.thread_id, after, 0.0)
            .await
            .unwrap();
        assert_eq!(reply.text, "answer");
        assert_eq!(
            store
                .wait_for_reply(None, OTHER, "muse", "grok", &q.thread_id, after, 0.0)
                .await
                .map(|m| m.id),
            None
        );
    }

    /// id は部屋ごとに数えるので、他の部屋がどれだけ送っても自分の部屋の id は 1 ずつ増える。
    #[tokio::test]
    async fn ids_count_up_per_room() {
        let store = store();
        let first: u64 = send(&store, ROOM, json!({ "text": "a" }))
            .unwrap()
            .id
            .parse()
            .unwrap();
        let mut other = Vec::new();
        for _ in 0..5 {
            other.push(send(&store, OTHER, json!({ "text": "b" })).unwrap().id);
        }
        let second: u64 = send(&store, ROOM, json!({ "text": "c" }))
            .unwrap()
            .id
            .parse()
            .unwrap();
        assert_eq!(second, first + 1);
        let other: Vec<u64> = other.iter().map(|id| id.parse().unwrap()).collect();
        assert!(other.windows(2).all(|w| w[1] == w[0] + 1), "{other:?}");
        // 部屋ごとの id でも、その部屋のカーソルとしてそのまま使える
        let rows = store
            .check_messages(
                ROOM,
                "grok",
                ListArgs {
                    since: json!(first.to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(rows["messages"][0]["text"], "c");
    }

    #[test]
    fn message_counts_are_limited_per_room_and_in_total() {
        let store = Store::new(Limits {
            room_messages: 3,
            total_messages: 5,
            ..Limits::with_total_attachment_bytes(1024)
        });
        for _ in 0..3 {
            send(&store, ROOM, json!({ "text": "x" })).unwrap();
        }
        let err = send(&store, ROOM, json!({ "text": "x" })).unwrap_err();
        assert_eq!(err.status, 507);
        assert!(
            err.message
                .starts_with("this room already holds 3 messages"),
            "{}",
            err.message
        );
        // 他の部屋は全体の残り（2 件）まで
        send(&store, OTHER, json!({ "text": "x" })).unwrap();
        send(&store, OTHER, json!({ "text": "x" })).unwrap();
        let err = send(&store, OTHER, json!({ "text": "x" })).unwrap_err();
        assert!(
            err.message
                .starts_with("the relay already holds 5 messages across all rooms"),
            "{}",
            err.message
        );
        assert_eq!(store.usage(ROOM).0.messages, 3);
        assert_eq!(store.usage(OTHER).1.messages, 5);
    }

    #[test]
    fn message_data_is_counted_per_room_and_in_total() {
        let store = Store::new(Limits {
            room_data_bytes: 3_000,
            total_data_bytes: 4_000,
            ..Limits::with_total_attachment_bytes(1024)
        });
        // 本文・名前・件名・スレッドの固定分も数える
        let m = send(&store, ROOM, json!({ "text": "x".repeat(1_000) })).unwrap();
        let (room, total) = store.usage(ROOM);
        let expected = MESSAGE_OVERHEAD
            + ("muse".len() + "grok".len() + 1_000) as u64
            + THREAD_OVERHEAD
            + (80 + "muse".len()) as u64;
        assert_eq!(room.data_bytes, expected);
        assert_eq!(total, room);
        let reply = json!({ "text": "x".repeat(1_000), "thread_id": m.thread_id });
        send(&store, ROOM, reply.clone()).unwrap();
        let err = send(&store, ROOM, reply).unwrap_err();
        assert_eq!(err.status, 507);
        assert!(
            err.message
                .starts_with("this room's message storage is full (3000 bytes"),
            "{}",
            err.message
        );
        // 部屋には余裕があっても全体が埋まれば断る。断った分は数えない
        let before = store.usage(OTHER);
        let err = send(&store, OTHER, json!({ "text": "y".repeat(1_500) })).unwrap_err();
        assert!(
            err.message
                .starts_with("the relay's message storage is full (4000 bytes across all rooms)"),
            "{}",
            err.message
        );
        assert_eq!(store.usage(OTHER), before);
        send(&store, OTHER, json!({ "text": "small" })).unwrap();
    }

    #[test]
    fn attachment_bytes_are_limited_per_room_and_in_total() {
        let store = Store::new(Limits::with_total_attachment_bytes(24));
        let file = |n: usize| json!({ "text": "f", "attachments": [{ "filename": "a", "content_base64": STANDARD.encode(vec![1u8; n]) }] });
        send(&store, ROOM, file(8)).unwrap();
        // 1 部屋は全体（24）の半分（12）まで
        let err = send(&store, ROOM, file(8)).unwrap_err();
        assert_eq!(err.status, 507);
        assert!(
            err.message
                .starts_with("this room's attachment storage is full (12 bytes)"),
            "{}",
            err.message
        );
        send(&store, ROOM, file(4)).unwrap();
        send(&store, OTHER, file(12)).unwrap();
        let third = "3003";
        let err = send(&store, third, file(1)).unwrap_err();
        assert!(
            err.message
                .starts_with("the relay's attachment storage is full (24 bytes across all rooms)"),
            "{}",
            err.message
        );
        // 添付の無いメッセージは送れる
        send(&store, third, json!({ "text": "no files" })).unwrap();
        assert_eq!(store.usage(ROOM).0.attachment_bytes, 12);
        assert_eq!(store.usage(ROOM).1.attachment_bytes, 24);
    }

    #[test]
    fn threads_hold_at_most_500_messages() {
        let store = store();
        let first = send(&store, ROOM, json!({ "text": "0" })).unwrap();
        let reply = json!({ "text": "x", "thread_id": first.thread_id });
        for _ in 1..MAX_THREAD_MESSAGES {
            send(&store, ROOM, reply.clone()).unwrap();
        }
        let err = send(&store, ROOM, reply).unwrap_err();
        assert_eq!(err.status, 409);
        assert_eq!(
            err.message,
            format!(
                "thread {} is full (500 messages); start a new thread by omitting thread_id",
                first.thread_id
            )
        );
        let thread = store.get_thread(ROOM, &json!(first.thread_id)).unwrap();
        assert_eq!(
            thread["messages"].as_array().unwrap().len(),
            MAX_THREAD_MESSAGES
        );
        send(&store, ROOM, json!({ "text": "new thread" })).unwrap();
    }

    #[test]
    fn registrations_are_counted_and_given_back() {
        let store = Store::new(Limits {
            room_agents: 2,
            ..Limits::with_total_attachment_bytes(1024)
        });
        assert!(!store.register_agent(ROOM, "a", None).unwrap());
        let only_name = store.usage(ROOM).0.data_bytes;
        assert_eq!(only_name, AGENT_OVERHEAD + 1);
        // 置き換えは差分だけ数える
        assert!(store
            .register_agent(ROOM, "a", Some(target("https://hook.example/a")))
            .unwrap());
        let with_hook = store.usage(ROOM).0.data_bytes;
        assert_eq!(
            with_hook,
            only_name + ("https://hook.example/a".len() + 1) as u64
        );
        store.register_agent(ROOM, "b", None).unwrap();
        let err = store.register_agent(ROOM, "c", None).unwrap_err();
        assert_eq!(err.status, 507);
        assert!(
            err.message.starts_with(
                "this room already has 2 registered agents (its limit); unregister one first"
            ),
            "{}",
            err.message
        );
        // 登録済みの名前の置き換えは数に関係なくできる
        store.register_agent(ROOM, "b", None).unwrap();
        assert!(store.unregister_agent(ROOM, "a"));
        store.register_agent(ROOM, "c", None).unwrap();
        assert!(store.unregister_agent(ROOM, "b"));
        assert!(store.unregister_agent(ROOM, "c"));
        assert_eq!(store.usage(ROOM), (Usage::default(), Usage::default()));

        // 登録も保存量の上限に入る
        let store = Store::new(Limits {
            room_data_bytes: AGENT_OVERHEAD + 10,
            ..Limits::with_total_attachment_bytes(1024)
        });
        store.register_agent(ROOM, "short", None).unwrap();
        let err = store
            .register_agent(ROOM, "short", Some(target("https://hook.example/a")))
            .unwrap_err();
        assert!(err
            .message
            .starts_with("this room's message storage is full"));
        assert_eq!(store.usage(ROOM).0.data_bytes, AGENT_OVERHEAD + 5);
    }

    #[tokio::test]
    async fn waits_are_admitted_per_room_and_in_total() {
        let store = Store::new(Limits {
            room_waits: 2,
            total_waits: 3,
            ..Limits::with_total_attachment_bytes(1024)
        });
        let a = store.reserve_wait(ROOM).unwrap();
        let b = store.reserve_wait(ROOM).unwrap();
        let err = store.reserve_wait(ROOM).err().unwrap();
        assert_eq!(err.status, 429);
        assert!(
            err.message.starts_with("this room already has 2 waiting"),
            "{}",
            err.message
        );
        let c = store.reserve_wait(OTHER).unwrap();
        let err = store.reserve_wait(OTHER).err().unwrap();
        assert!(
            err.message
                .starts_with("the relay already has 3 waiting calls"),
            "{}",
            err.message
        );
        // 待機を伴わない check は枠を使わない
        let quick = store
            .check_messages(ROOM, "grok", ListArgs::default())
            .await
            .unwrap();
        assert_eq!(quick["messages"], json!([]));
        let err = store
            .check_messages(
                ROOM,
                "grok",
                ListArgs {
                    wait: json!(1),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert_eq!(err.status, 429);
        drop((a, b, c));
        assert_eq!(store.waiting(), 0);
        store.reserve_wait(ROOM).unwrap();
    }

    /// 送信はその部屋の待機だけを起こす。
    #[tokio::test]
    async fn a_send_wakes_only_its_own_room() {
        let store = std::sync::Arc::new(store());
        let slot_room = store.reserve_wait(ROOM).unwrap();
        let slot_other = store.reserve_wait(OTHER).unwrap();
        let waiting_room = store.lock_waiters().rooms[ROOM].wake.clone();
        let waiting_other = store.lock_waiters().rooms[OTHER].wake.clone();
        let room_woken = waiting_room.notified();
        let other_woken = waiting_other.notified();
        tokio::pin!(room_woken, other_woken);
        room_woken.as_mut().enable();
        other_woken.as_mut().enable();
        send(&store, ROOM, json!({ "text": "x" })).unwrap();
        assert!(ready(room_woken).await);
        assert!(!ready(other_woken).await);
        drop((slot_room, slot_other));
    }
}
