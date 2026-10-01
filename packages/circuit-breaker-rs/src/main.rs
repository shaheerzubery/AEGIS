//! Layer 5 — circuit breaker, Rust rewrite (Sprint 2 per PLAN.md and
//! post-Sprint-4 "Gap-closing backlog" per PROGRESS.md, 2026-08-22).
//!
//! Behaviorally identical HTTP API to packages/circuit-breaker/circuit_breaker.py
//! (the Python MVP, kept as-is — this runs alongside it, not in place of it,
//! same "config.py backend switch" philosophy as Gap #3's audit-logger, just
//! expressed as "point AEGIS_CIRCUIT_BREAKER_URL at whichever one you want"
//! rather than a config.py flag, since swapping a whole service isn't a
//! backend-selection concern the way SQLite-vs-Postgres was).
//!
//! Investigated first (see PROGRESS.md's "global-lock hypothesis" entry):
//! circuit-breaker's actual measured bottleneck under load was NOT lock/CPU
//! contention (CPU stayed at 5.5% even while struggling) — it looked more
//! like the `ThreadingHTTPServer` model itself (one OS thread per
//! connection) interacting with this platform's networking. So the honest
//! motivation for this rewrite is the *concurrency model* (async, not
//! thread-per-connection) and per-key locking (below) rather than "fixing
//! lock contention" that wasn't actually the measured problem.
//!
//! Per-(tenant, session) state lives behind its own `tokio::sync::Mutex`,
//! not one global lock — DashMap gives each key its own shard, and every
//! handler clones the `Arc<Mutex<SessionState>>` out of the DashMap entry
//! (a synchronous, non-blocking-across-await operation) *before* awaiting
//! that Mutex, specifically to avoid ever holding DashMap's own internal
//! (sync, non-async-aware) lock across an `.await` point — doing that is a
//! well-known correctness/deadlock hazard under an async runtime.
//!
//! Settings come from environment variables, not config.py — config.py is
//! explicitly scoped to the Python services this repo builds (see its own
//! module docstring); a Rust service reading env vars directly matches how
//! the other non-Python images in this repo (vault, audit-db) are already
//! configured. Names match this repo's existing convention
//! (`AEGIS_VIOLATION_THRESHOLD` etc.) so demo/docker-compose.yml can set
//! them as literals, same "keep in sync with config.py by hand" pattern.

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use dashmap::DashMap;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    env,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

type Key = (String, String); // (tenant_id, session_id)

struct SuspensionMeta {
    reason: String,
    suspended_at: f64, // unix epoch seconds, matching Python's time.time()
    // Gap-closing work (2026-09-16, see PROGRESS.md): a real per-suspension
    // tier now, not a literal derived at read time — matches
    // packages/circuit-breaker's _suspension_meta exactly.
    tier: String,
}

#[derive(Default)]
struct SessionState {
    violations: Vec<Instant>,
    activity: Vec<Instant>,
    suspended: bool,
    terminated: bool,
    meta: Option<SuspensionMeta>,
}

struct RateLimitCacheEntry {
    value: u32,
    fetched_at: Instant,
}

struct Config {
    violation_threshold: usize,
    violation_window_seconds: u64,
    rate_limit_window_seconds: u64,
    default_rate_limit: u32,
    rate_limit_cache_seconds: u64,
    policy_engine_url: String,
    port: u16,
    // Gap-closing work (2026-09-16, see PROGRESS.md): empty = disabled,
    // same convention as config.py's WEBHOOK_URL for the Python service.
    webhook_url: String,
    // Gap-closing work (2026-09-16, see PROGRESS.md): where hard_suspend/
    // emergency_kill fetch a session's real forensic snapshot from — same
    // role config.py's AUDIT_URL plays for circuit_breaker.py.
    audit_url: String,
}

impl Config {
    fn from_env() -> Self {
        fn env_or(name: &str, default: &str) -> String {
            env::var(name).unwrap_or_else(|_| default.to_string())
        }
        fn parse_or<T: std::str::FromStr>(name: &str, default: T) -> T {
            env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
        }
        Config {
            violation_threshold: parse_or("AEGIS_VIOLATION_THRESHOLD", 5),
            violation_window_seconds: parse_or("AEGIS_VIOLATION_WINDOW_SECONDS", 60),
            rate_limit_window_seconds: parse_or("AEGIS_RATE_LIMIT_WINDOW_SECONDS", 60),
            default_rate_limit: parse_or("AEGIS_RATE_LIMIT_PER_MINUTE", 60),
            rate_limit_cache_seconds: parse_or("AEGIS_RATE_LIMIT_CACHE_SECONDS", 30),
            policy_engine_url: env_or("AEGIS_POLICY_URL", "http://opa:8181"),
            port: parse_or("AEGIS_CIRCUIT_BREAKER_PORT", 9400),
            webhook_url: env_or("AEGIS_WEBHOOK_URL", ""),
            audit_url: env_or("AEGIS_AUDIT_URL", "http://audit-logger:9300"),
        }
    }
}

/// Real HTTP POST to config.webhook_url — mirrors
/// circuit_breaker.py's _send_webhook exactly (same "text" field for a
/// real Slack Incoming Webhook, same structured fields for a generic
/// receiver). Spawned via tokio::spawn by every caller below rather than
/// awaited inline, for the same reason audit_logger.py's forwards moved
/// off the request path: a slow/unreachable webhook receiver must never
/// add latency to a suspend response.
fn send_webhook(http: reqwest::Client, webhook_url: String, tenant_id: String, session_id: String, tier: &'static str, reason: String, event: &'static str) {
    if webhook_url.is_empty() {
        return;
    }
    tokio::spawn(async move {
        let payload = json!({
            "text": format!("[AEGIS circuit-breaker-rs] {event}: tenant={tenant_id} session={session_id} tier={tier} reason={reason}"),
            "event": event,
            "tenant_id": tenant_id,
            "session_id": session_id,
            "tier": tier,
            "reason": reason,
            "timestamp": now_unix(),
        });
        let _ = http
            .post(&webhook_url)
            .timeout(Duration::from_secs(2))
            .json(&payload)
            .send()
            .await; // best-effort — a down webhook receiver shouldn't matter here
    });
}

struct AppState {
    // Every value is wrapped in Arc<Mutex<_>> specifically so handlers can
    // clone the Arc out of the DashMap entry and drop DashMap's own guard
    // *before* awaiting the Mutex — see module doc comment.
    sessions: DashMap<Key, Arc<Mutex<SessionState>>>,
    rate_limits: DashMap<String, Arc<Mutex<RateLimitCacheEntry>>>,
    http: reqwest::Client,
    config: Config,
    // Gap-closing work (2026-09-16, see PROGRESS.md): hard_suspend/
    // emergency_kill tier parity with packages/circuit-breaker.
    // container_registry: populated by register_container — nothing is
    // killable by default. snapshots: the forensic snapshot captured at
    // hard_suspend/emergency_kill time, retrievable via GET /snapshot.
    // docker: None if the Docker Engine API wasn't reachable at startup
    // (e.g. no socket mounted) — emergency_kill degrades honestly in that
    // case rather than the whole service failing to start.
    container_registry: DashMap<Key, String>,
    snapshots: DashMap<Key, Value>,
    docker: Option<bollard::Docker>,
}

fn now_unix() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64()
}

fn prune(history: &mut Vec<Instant>, window: Duration, now: Instant) {
    history.retain(|t| now.duration_since(*t) < window);
}

fn get_or_create_session(state: &AppState, key: &Key) -> Arc<Mutex<SessionState>> {
    // Synchronous, no .await anywhere in this expression — the DashMap
    // shard guard from .entry() is created and dropped entirely within
    // this one statement, safe by construction.
    state
        .sessions
        .entry(key.clone())
        .or_insert_with(|| Arc::new(Mutex::new(SessionState::default())))
        .clone()
}

/// Read the configured limit from OPA's
/// data.policy.tenants.<tenant_id>.rate_limits, caching briefly per tenant
/// (same TTL-cache design as circuit_breaker.py's `_current_rate_limit`).
/// Falls back to the last known value (or the env default) if OPA is
/// unreachable or the tenant has no rate_limits configured.
async fn current_rate_limit(state: &AppState, tenant_id: &str) -> u32 {
    let now = Instant::now();

    if let Some(cache_arc) = state.rate_limits.get(tenant_id).map(|e| e.clone()) {
        let cache = cache_arc.lock().await;
        if now.duration_since(cache.fetched_at) < Duration::from_secs(state.config.rate_limit_cache_seconds) {
            return cache.value;
        }
    }

    let url = format!(
        "{}/v1/data/policy/tenants/{}/rate_limits/max_actions_per_minute",
        state.config.policy_engine_url, tenant_id
    );
    let fetched: Option<u32> = match state
        .http
        .get(&url)
        .timeout(Duration::from_secs(2))
        .send()
        .await
    {
        Ok(resp) => resp
            .json::<Value>()
            .await
            .ok()
            .and_then(|body| body.get("result").and_then(|v| v.as_u64()))
            .map(|v| v as u32),
        Err(_) => None,
    };

    let cache_arc = state
        .rate_limits
        .entry(tenant_id.to_string())
        .or_insert_with(|| {
            Arc::new(Mutex::new(RateLimitCacheEntry {
                value: state.config.default_rate_limit,
                fetched_at: now,
            }))
        })
        .clone();
    let mut cache = cache_arc.lock().await;
    if let Some(v) = fetched {
        cache.value = v;
        cache.fetched_at = now;
    }
    cache.value
}

fn extract_reason(body: &Bytes) -> String {
    if body.is_empty() {
        return "unspecified".to_string();
    }
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("reason").and_then(|r| r.as_str()).map(str::to_string))
        .unwrap_or_else(|| "unspecified".to_string())
}

async fn record_violation(
    State(state): State<Arc<AppState>>,
    Path((tenant_id, session_id)): Path<(String, String)>,
) -> Json<Value> {
    let session = get_or_create_session(&state, &(tenant_id.clone(), session_id.clone()));
    let mut s = session.lock().await;
    let now = Instant::now();
    prune(&mut s.violations, Duration::from_secs(state.config.violation_window_seconds), now);
    s.violations.push(now);

    let mut newly_suspended = false;
    let mut reason_for_webhook = String::new();
    if s.violations.len() >= state.config.violation_threshold && !s.suspended {
        s.suspended = true;
        newly_suspended = true;
        let reason = format!(
            "{} policy violations in {}s (threshold={})",
            s.violations.len(),
            state.config.violation_window_seconds,
            state.config.violation_threshold
        );
        reason_for_webhook = reason.clone();
        s.meta = Some(SuspensionMeta { reason, suspended_at: now_unix(), tier: "soft_pause".to_string() });
    }
    let violations_in_window = s.violations.len();
    let suspended = s.suspended;
    drop(s); // release the session lock before dispatching the webhook below

    if newly_suspended {
        println!(
            "[circuit-breaker-rs] WEBHOOK: tenant={tenant_id} session={session_id} suspended after violation threshold reached ({reason_for_webhook})"
        );
        send_webhook(
            state.http.clone(),
            state.config.webhook_url.clone(),
            tenant_id.clone(),
            session_id.clone(),
            "soft_pause",
            reason_for_webhook,
            "suspended",
        );
    }

    Json(json!({
        "tenant_id": tenant_id,
        "session_id": session_id,
        "violations_in_window": violations_in_window,
        "suspended": suspended,
    }))
}

async fn record_activity(
    State(state): State<Arc<AppState>>,
    Path((tenant_id, session_id)): Path<(String, String)>,
) -> Json<Value> {
    let limit = current_rate_limit(&state, &tenant_id).await;
    let session = get_or_create_session(&state, &(tenant_id.clone(), session_id.clone()));
    let mut s = session.lock().await;
    let now = Instant::now();
    prune(&mut s.activity, Duration::from_secs(state.config.rate_limit_window_seconds), now);

    let rate_limited = s.activity.len() as u32 >= limit;
    if !rate_limited {
        s.activity.push(now);
    }

    Json(json!({
        "tenant_id": tenant_id,
        "session_id": session_id,
        "count_in_window": s.activity.len(),
        "limit": limit,
        "rate_limited": rate_limited,
    }))
}

/// Shared suspend-everything effect behind soft_pause/hard_suspend/
/// emergency_kill (gap-closing work, 2026-09-16 — mirrors
/// packages/circuit-breaker's suspend_directly(..., tier=...) exactly,
/// including the "already suspended keeps its original meta" behavior).
/// Returns whether this call newly suspended the session (false if it was
/// already suspended, in which case its original tier/reason are kept).
async fn suspend_with_tier(state: &AppState, tenant_id: &str, session_id: &str, reason: &str, tier: &str) -> bool {
    let session = get_or_create_session(state, &(tenant_id.to_string(), session_id.to_string()));
    let mut s = session.lock().await;
    let already_suspended = s.suspended;
    s.suspended = true;
    if !already_suspended {
        s.meta = Some(SuspensionMeta {
            reason: reason.to_string(),
            suspended_at: now_unix(),
            tier: tier.to_string(),
        });
    }
    !already_suspended
}

async fn suspend_directly(
    State(state): State<Arc<AppState>>,
    Path((tenant_id, session_id)): Path<(String, String)>,
    body: Bytes,
) -> Json<Value> {
    let reason = extract_reason(&body);
    let newly_suspended = suspend_with_tier(&state, &tenant_id, &session_id, &reason, "soft_pause").await;
    if newly_suspended {
        println!("[circuit-breaker-rs] WEBHOOK: tenant={tenant_id} session={session_id} suspended directly ({reason})");
        send_webhook(
            state.http.clone(),
            state.config.webhook_url.clone(),
            tenant_id.clone(),
            session_id.clone(),
            "soft_pause",
            reason.clone(),
            "suspended",
        );
    }
    Json(json!({"tenant_id": tenant_id, "session_id": session_id, "suspended": true, "reason": reason, "tier": "soft_pause"}))
}

/// Real forensic snapshot (proposal §3.2 Layer 5: "a snapshot of the
/// agent's state is captured for forensics") — mirrors
/// circuit_breaker.py's _fetch_audit_trail/_capture_snapshot exactly: the
/// session's actual audit trail, fetched live from packages/audit-logger,
/// not a placeholder. An unreachable audit-logger degrades to an empty
/// trail rather than failing the suspend/kill itself.
async fn fetch_audit_trail(http: &reqwest::Client, audit_url: &str, tenant_id: &str, session_id: &str) -> Vec<Value> {
    let url = format!("{audit_url}/events?tenant_id={tenant_id}&session_id={session_id}&limit=100");
    match http.get(&url).timeout(Duration::from_secs(2)).send().await {
        Ok(resp) => resp.json::<Vec<Value>>().await.unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

async fn capture_snapshot(state: &AppState, tenant_id: &str, session_id: &str, reason: &str, tier: &str) -> Value {
    let audit_trail = fetch_audit_trail(&state.http, &state.config.audit_url, tenant_id, session_id).await;
    let snapshot = json!({
        "tenant_id": tenant_id,
        "session_id": session_id,
        "tier": tier,
        "reason": reason,
        "captured_at": now_unix(),
        "audit_trail": audit_trail,
    });
    state.snapshots.insert((tenant_id.to_string(), session_id.to_string()), snapshot.clone());
    snapshot
}

async fn get_snapshot(
    State(state): State<Arc<AppState>>,
    Path((tenant_id, session_id)): Path<(String, String)>,
) -> Json<Value> {
    match state.snapshots.get(&(tenant_id.clone(), session_id.clone())) {
        Some(snapshot) => Json(snapshot.clone()),
        None => Json(json!({"tenant_id": tenant_id, "session_id": session_id, "error": "no snapshot captured for this session"})),
    }
}

/// Proposal §3.2 Layer 5, second level: "all agent processes are frozen,
/// network access is revoked, and a snapshot of the agent's state is
/// captured for forensics." Mirrors circuit_breaker.py's hard_suspend()
/// exactly — same suspend-everything effect as soft_pause, plus a real
/// forensic snapshot.
async fn hard_suspend(
    State(state): State<Arc<AppState>>,
    Path((tenant_id, session_id)): Path<(String, String)>,
    body: Bytes,
) -> Json<Value> {
    let reason = extract_reason(&body);
    let newly_suspended = suspend_with_tier(&state, &tenant_id, &session_id, &reason, "hard_suspend").await;
    let snapshot = capture_snapshot(&state, &tenant_id, &session_id, &reason, "hard_suspend").await;
    let actions_in_snapshot = snapshot["audit_trail"].as_array().map(Vec::len).unwrap_or(0);

    if newly_suspended {
        println!("[circuit-breaker-rs] WEBHOOK: tenant={tenant_id} session={session_id} hard-suspended ({reason})");
        send_webhook(
            state.http.clone(),
            state.config.webhook_url.clone(),
            tenant_id.clone(),
            session_id.clone(),
            "hard_suspend",
            reason.clone(),
            "suspended",
        );
    }

    Json(json!({
        "tenant_id": tenant_id,
        "session_id": session_id,
        "suspended": true,
        "reason": reason,
        "tier": "hard_suspend",
        "snapshot_captured": true,
        "actions_in_snapshot": actions_in_snapshot,
    }))
}

/// Best-effort real Docker container kill via the Docker Engine API
/// (bollard) — mirrors circuit_breaker.py's _kill_container exactly,
/// including reporting a genuine failure honestly rather than crashing
/// the request or claiming a false success.
async fn kill_container(docker: &Option<bollard::Docker>, container_id: &str) -> Value {
    let Some(docker) = docker else {
        return json!({"attempted": true, "success": false, "error": "docker client unavailable"});
    };
    match docker
        .kill_container(container_id, None::<bollard::container::KillContainerOptions<String>>)
        .await
    {
        Ok(()) => json!({"attempted": true, "success": true}),
        Err(err) => json!({"attempted": true, "success": false, "error": err.to_string()}),
    }
}

/// Proposal §3.2 Layer 5, third level: "the agent's entire runtime
/// environment is destroyed (container killed, VM terminated), with all
/// state preserved in the audit log." Mirrors circuit_breaker.py's
/// emergency_kill() exactly: does everything hard_suspend does (snapshot
/// captured before any kill attempt, so it survives regardless of
/// outcome), plus attempts a real kill of the registered container, if
/// any — reported honestly either way, never a false "success."
async fn emergency_kill(
    State(state): State<Arc<AppState>>,
    Path((tenant_id, session_id)): Path<(String, String)>,
    body: Bytes,
) -> Json<Value> {
    let reason = extract_reason(&body);
    let newly_suspended = suspend_with_tier(&state, &tenant_id, &session_id, &reason, "emergency_kill").await;
    let snapshot = capture_snapshot(&state, &tenant_id, &session_id, &reason, "emergency_kill").await;
    let actions_in_snapshot = snapshot["audit_trail"].as_array().map(Vec::len).unwrap_or(0);
    let _ = newly_suspended; // emergency_kill always attempts the kill and fires the webhook, unlike soft_pause/hard_suspend's "only on first suspend" gating — matches circuit_breaker.py exactly.

    let container_id = state
        .container_registry
        .get(&(tenant_id.clone(), session_id.clone()))
        .map(|entry| entry.clone());

    let kill_result = match &container_id {
        None => json!({"attempted": false, "success": false, "error": "no container registered for this session"}),
        Some(cid) => kill_container(&state.docker, cid).await,
    };

    println!(
        "[circuit-breaker-rs] WEBHOOK: tenant={tenant_id} session={session_id} emergency-kill container={container_id:?} result={kill_result}"
    );
    send_webhook(
        state.http.clone(),
        state.config.webhook_url.clone(),
        tenant_id.clone(),
        session_id.clone(),
        "emergency_kill",
        format!("{reason} (kill: {kill_result})"),
        "emergency-kill",
    );

    Json(json!({
        "tenant_id": tenant_id,
        "session_id": session_id,
        "suspended": true,
        "reason": reason,
        "tier": "emergency_kill",
        "snapshot_captured": true,
        "actions_in_snapshot": actions_in_snapshot,
        "kill": kill_result,
    }))
}

#[derive(Deserialize)]
struct RegisterBody {
    container_id: Option<String>,
}

/// An agent runtime opts in to being killable by reporting its own Docker
/// container id — mirrors circuit_breaker.py's register_container()
/// exactly, including the 400 on a missing container_id.
async fn register_container(
    State(state): State<Arc<AppState>>,
    Path((tenant_id, session_id)): Path<(String, String)>,
    body: Bytes,
) -> (StatusCode, Json<Value>) {
    let parsed: RegisterBody = serde_json::from_slice(&body).unwrap_or(RegisterBody { container_id: None });
    let Some(container_id) = parsed.container_id else {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "container_id is required"})));
    };
    state
        .container_registry
        .insert((tenant_id.clone(), session_id.clone()), container_id.clone());
    (
        StatusCode::OK,
        Json(json!({"tenant_id": tenant_id, "session_id": session_id, "container_id": container_id, "registered": true})),
    )
}

async fn terminate(
    State(state): State<Arc<AppState>>,
    Path((tenant_id, session_id)): Path<(String, String)>,
    body: Bytes,
) -> Json<Value> {
    let reason = extract_reason(&body);
    let session = get_or_create_session(&state, &(tenant_id.clone(), session_id.clone()));
    let mut s = session.lock().await;
    s.suspended = true;
    s.terminated = true;
    s.meta = Some(SuspensionMeta { reason: reason.clone(), suspended_at: now_unix(), tier: "terminated".to_string() });
    drop(s); // release the session lock before dispatching the webhook below
    println!("[circuit-breaker-rs] WEBHOOK: tenant={tenant_id} session={session_id} terminated permanently ({reason})");
    send_webhook(
        state.http.clone(),
        state.config.webhook_url.clone(),
        tenant_id.clone(),
        session_id.clone(),
        "terminated",
        reason.clone(),
        "terminated",
    );
    Json(json!({"tenant_id": tenant_id, "session_id": session_id, "terminated": true, "reason": reason}))
}

async fn get_status(
    State(state): State<Arc<AppState>>,
    Path((tenant_id, session_id)): Path<(String, String)>,
) -> Json<Value> {
    let key = (tenant_id.clone(), session_id.clone());
    let (violations_in_window, suspended, terminated) = match state.sessions.get(&key).map(|e| e.clone()) {
        Some(session) => {
            let s = session.lock().await;
            (s.violations.len(), s.suspended, s.terminated)
        }
        None => (0, false, false),
    };
    Json(json!({
        "tenant_id": tenant_id,
        "session_id": session_id,
        "violations_in_window": violations_in_window,
        "suspended": suspended,
        "terminated": terminated,
    }))
}

async fn resume(
    State(state): State<Arc<AppState>>,
    Path((tenant_id, session_id)): Path<(String, String)>,
) -> Json<Value> {
    let session = get_or_create_session(&state, &(tenant_id.clone(), session_id.clone()));
    let mut s = session.lock().await;
    if s.terminated {
        return Json(json!({
            "tenant_id": tenant_id,
            "session_id": session_id,
            "suspended": true,
            "error": "session was permanently terminated and cannot be resumed",
        }));
    }
    let was_suspended = s.suspended;
    s.suspended = false;
    s.violations.clear();
    s.activity.clear();
    s.meta = None;
    Json(json!({
        "tenant_id": tenant_id,
        "session_id": session_id,
        "suspended": false,
        "was_suspended": was_suspended,
    }))
}

#[derive(Deserialize)]
struct SuspendedQuery {
    tenant_id: Option<String>,
}

async fn list_suspended(
    State(state): State<Arc<AppState>>,
    Query(q): Query<SuspendedQuery>,
) -> Json<Value> {
    // Snapshot (key, Arc) pairs synchronously first — every DashMap guard
    // is dropped before any .await below, same reasoning as everywhere else
    // in this file.
    let snapshot: Vec<(Key, Arc<Mutex<SessionState>>)> =
        state.sessions.iter().map(|e| (e.key().clone(), e.value().clone())).collect();

    let mut results = Vec::new();
    for ((tenant_id, session_id), session) in snapshot {
        if let Some(filter) = &q.tenant_id {
            if &tenant_id != filter {
                continue;
            }
        }
        let s = session.lock().await;
        if s.suspended {
            // Gap-closing work (2026-09-16, see PROGRESS.md): a real
            // per-suspension tier now (SuspensionMeta.tier), not a
            // heuristic derived from s.terminated alone — mirrors
            // packages/circuit-breaker's list_suspended exactly.
            results.push(json!({
                "tenant_id": tenant_id,
                "session_id": session_id,
                "reason": s.meta.as_ref().map(|m| m.reason.clone()).unwrap_or_else(|| "unknown".to_string()),
                "suspended_at": s.meta.as_ref().map(|m| m.suspended_at),
                "tier": s.meta.as_ref().map(|m| m.tier.clone()).unwrap_or_else(|| "unknown".to_string()),
                "terminated": s.terminated,
            }));
        }
    }

    results.sort_by(|a, b| {
        let ak = (a["tenant_id"].as_str().unwrap_or(""), a["session_id"].as_str().unwrap_or(""));
        let bk = (b["tenant_id"].as_str().unwrap_or(""), b["session_id"].as_str().unwrap_or(""));
        ak.cmp(&bk)
    });

    Json(json!(results))
}

#[tokio::main]
async fn main() {
    let config = Config::from_env();
    let port = config.port;
    let violation_threshold = config.violation_threshold;
    let violation_window_seconds = config.violation_window_seconds;
    let default_rate_limit = config.default_rate_limit;
    let rate_limit_window_seconds = config.rate_limit_window_seconds;
    let policy_engine_url = config.policy_engine_url.clone();

    // Gap-closing work (2026-09-16, see PROGRESS.md): best-effort — a
    // missing/unreachable Docker socket degrades emergency_kill honestly
    // (see kill_container) rather than failing this service's startup.
    let docker = bollard::Docker::connect_with_local_defaults().ok();
    if docker.is_none() {
        println!("[circuit-breaker-rs] WARNING: Docker Engine API unreachable at startup — emergency_kill will report kill attempts as failed until this is fixed");
    }

    let state = Arc::new(AppState {
        sessions: DashMap::new(),
        rate_limits: DashMap::new(),
        http: reqwest::Client::new(),
        config,
        container_registry: DashMap::new(),
        snapshots: DashMap::new(),
        docker,
    });

    let app = Router::new()
        .route("/violation/:tenant_id/:session_id", post(record_violation))
        .route("/activity/:tenant_id/:session_id", post(record_activity))
        .route("/resume/:tenant_id/:session_id", post(resume))
        .route("/suspend/:tenant_id/:session_id", post(suspend_directly))
        .route("/terminate/:tenant_id/:session_id", post(terminate))
        .route("/hard-suspend/:tenant_id/:session_id", post(hard_suspend))
        .route("/emergency-kill/:tenant_id/:session_id", post(emergency_kill))
        .route("/register/:tenant_id/:session_id", post(register_container))
        .route("/status/:tenant_id/:session_id", get(get_status))
        .route("/snapshot/:tenant_id/:session_id", get(get_snapshot))
        .route("/suspended", get(list_suspended))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!(
        "AEGIS circuit-breaker-rs listening on {addr} (violation threshold={violation_threshold}/{violation_window_seconds}s, \
         rate limit default={default_rate_limit}/{rate_limit_window_seconds}s from {policy_engine_url})"
    );
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
