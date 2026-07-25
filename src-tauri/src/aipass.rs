use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use futures_util::StreamExt;
use rand::{rngs::OsRng, RngCore};
use reqwest::{redirect::Policy, Client, RequestBuilder, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    sync::Mutex as StdMutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tauri::{ipc::Channel, AppHandle, Emitter, State};
use tauri_plugin_opener::OpenerExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex as AsyncMutex,
    time::{timeout, Instant},
};
use tokio_util::sync::CancellationToken;
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const DISCOVERY_URL: &str = "https://aipass.one/.well-known/oauth-authorization-server";
const MODELS_URL: &str = "https://aipass.one/oauth2/v1/models?type=text&method=chat_completions";
const CHAT_URL: &str = "https://aipass.one/oauth2/v1/chat/completions";
const EXPECTED_ISSUER: &str = "https://aipass.one";
const KEYCHAIN_SERVICE: &str = "com.pathors.parley.aipass";
const KEYCHAIN_ACCOUNT: &str = "oauth-tokens-v1";
const STATUS_EVENT: &str = "aipass://status";
const REQUIRED_SCOPE: &str = "api:access profile:read";

const OAUTH_TIMEOUT: Duration = Duration::from_secs(180);
const HTTP_TIMEOUT: Duration = Duration::from_secs(20);
const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const STREAM_TOTAL_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_CALLBACK_BYTES: usize = 8 * 1024;
const MAX_METADATA_BYTES: usize = 64 * 1024;
const MAX_TOKEN_BYTES: usize = 64 * 1024;
const MAX_USERINFO_BYTES: usize = 64 * 1024;
const MAX_MODELS_BYTES: usize = 2 * 1024 * 1024;
const MAX_CHAT_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_CHAT_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
const MAX_ERROR_BYTES: usize = 64 * 1024;
const MAX_STREAM_CHUNK_BYTES: usize = 256 * 1024;
const MAX_MODELS: usize = 500;
const MAX_MODEL_ID_BYTES: usize = 256;
const MAX_ACTIVE_CHAT_REQUESTS: usize = 16;

pub struct AiPassState {
    client: Client,
    connect_lock: AsyncMutex<()>,
    refresh_lock: AsyncMutex<()>,
    active_chat: StdMutex<HashMap<String, CancellationToken>>,
}

impl Default for AiPassState {
    fn default() -> Self {
        let client = Client::builder()
            .https_only(true)
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(8))
            .user_agent(concat!("Parley/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("build AI Pass HTTP client");
        Self {
            client,
            connect_lock: AsyncMutex::new(()),
            refresh_lock: AsyncMutex::new(()),
            active_chat: StdMutex::new(HashMap::new()),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct Profile {
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    email: Option<String>,
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
struct TokenBundle {
    access_token: String,
    refresh_token: String,
    expires_at_epoch_seconds: u64,
    #[serde(default)]
    scope: Option<String>,
    #[zeroize(skip)]
    #[serde(default)]
    profile: Profile,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionStatus {
    configured: bool,
    connected: bool,
    display_name: Option<String>,
    email: Option<String>,
}

impl ConnectionStatus {
    fn disconnected() -> Self {
        Self {
            configured: client_id().is_some(),
            connected: false,
            display_name: None,
            email: None,
        }
    }

    fn connected(profile: Profile) -> Self {
        Self {
            configured: client_id().is_some(),
            connected: true,
            display_name: profile.display_name,
            email: profile.email,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct OAuthMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    revocation_endpoint: String,
}

#[derive(Debug, PartialEq)]
enum Callback {
    Code(String),
    Error(String),
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamMessage {
    Headers { status: u16, content_type: String },
    Data { data: String },
    Done,
    Error { message: String },
}

fn client_id() -> Option<&'static str> {
    option_env!("AIPASS_CLIENT_ID")
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn now_epoch_seconds() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "system clock is unavailable".into())
}

fn random_urlsafe(bytes: usize) -> String {
    let mut random = vec![0_u8; bytes];
    OsRng.fill_bytes(&mut random);
    let encoded = URL_SAFE_NO_PAD.encode(&random);
    random.zeroize();
    encoded
}

fn keychain_load() -> Result<Option<TokenBundle>, String> {
    let mut encoded = match security_framework::passwords::get_generic_password(
        KEYCHAIN_SERVICE,
        KEYCHAIN_ACCOUNT,
    ) {
        Ok(value) => value,
        Err(error) if error.code() == -25300 => return Ok(None), // errSecItemNotFound
        Err(_) => return Err("AI Pass credentials are unavailable in Keychain".into()),
    };
    if encoded.len() > MAX_TOKEN_BYTES {
        encoded.zeroize();
        return Err("AI Pass credentials in Keychain are invalid".into());
    }
    let parsed = serde_json::from_slice(&encoded)
        .map_err(|_| "AI Pass credentials in Keychain are invalid".to_string());
    encoded.zeroize();
    parsed.map(Some)
}

fn keychain_save(tokens: &TokenBundle) -> Result<(), String> {
    let mut encoded = serde_json::to_vec(tokens)
        .map_err(|_| "could not prepare AI Pass credentials for Keychain".to_string())?;
    if encoded.len() > MAX_TOKEN_BYTES {
        encoded.zeroize();
        return Err("AI Pass credentials are too large".into());
    }
    let result = security_framework::passwords::set_generic_password(
        KEYCHAIN_SERVICE,
        KEYCHAIN_ACCOUNT,
        &encoded,
    )
    .map_err(|_| "could not save AI Pass credentials in Keychain".to_string());
    encoded.zeroize();
    result
}

fn keychain_delete() -> Result<(), String> {
    match security_framework::passwords::delete_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
    {
        Ok(()) => Ok(()),
        Err(error) if error.code() == -25300 => Ok(()), // errSecItemNotFound
        Err(_) => Err("could not clear AI Pass credentials from Keychain".into()),
    }
}

fn endpoint_is_pinned_https(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str() == Some("aipass.one")
            && url.port().is_none()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
    })
}

fn array_contains(value: &Value, expected: &str) -> bool {
    value
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(expected)))
}

fn validate_metadata(value: &Value) -> Result<OAuthMetadata, String> {
    let metadata: OAuthMetadata = serde_json::from_value(value.clone())
        .map_err(|_| "AI Pass OAuth metadata is invalid".to_string())?;
    if metadata.issuer != EXPECTED_ISSUER
        || !endpoint_is_pinned_https(&metadata.authorization_endpoint)
        || !endpoint_is_pinned_https(&metadata.token_endpoint)
        || !endpoint_is_pinned_https(&metadata.userinfo_endpoint)
        || !endpoint_is_pinned_https(&metadata.revocation_endpoint)
        || !array_contains(&value["scopes_supported"], "api:access")
        || !array_contains(&value["scopes_supported"], "profile:read")
        || !array_contains(&value["response_types_supported"], "code")
        || !array_contains(&value["grant_types_supported"], "authorization_code")
        || !array_contains(&value["grant_types_supported"], "refresh_token")
        || !array_contains(&value["code_challenge_methods_supported"], "S256")
        || !array_contains(&value["token_endpoint_auth_methods_supported"], "none")
    {
        return Err("AI Pass OAuth metadata did not pass validation".into());
    }
    Ok(metadata)
}

async fn read_limited(
    response: Response,
    maximum: usize,
    total_timeout: Duration,
) -> Result<Vec<u8>, String> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err("AI Pass response exceeded the size limit".into());
    }
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    let deadline = Instant::now() + total_timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            body.zeroize();
            return Err("AI Pass response timed out".into());
        }
        let next = match timeout(remaining, stream.next()).await {
            Ok(next) => next,
            Err(_) => {
                body.zeroize();
                return Err("AI Pass response timed out".into());
            }
        };
        match next {
            Some(Ok(chunk)) => {
                if body.len().saturating_add(chunk.len()) > maximum {
                    body.zeroize();
                    return Err("AI Pass response exceeded the size limit".into());
                }
                body.extend_from_slice(&chunk);
            }
            Some(Err(_)) => {
                body.zeroize();
                return Err("AI Pass response could not be read".into());
            }
            None => return Ok(body),
        }
    }
}

async fn send_request(request: RequestBuilder, public_error: &str) -> Result<Response, String> {
    timeout(HTTP_TIMEOUT, request.send())
        .await
        .map_err(|_| public_error.to_owned())?
        .map_err(|_| public_error.to_owned())
}

async fn fetch_metadata(client: &Client) -> Result<OAuthMetadata, String> {
    let response = send_request(
        client.get(DISCOVERY_URL),
        "AI Pass OAuth metadata is unavailable",
    )
    .await?;
    if !response.status().is_success() {
        return Err("AI Pass OAuth metadata is unavailable".into());
    }
    let body = read_limited(response, MAX_METADATA_BYTES, Duration::from_secs(10)).await?;
    let value: Value = serde_json::from_slice(&body)
        .map_err(|_| "AI Pass OAuth metadata is invalid".to_string())?;
    validate_metadata(&value)
}

fn build_authorization_url(
    endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    code_challenge: &str,
    state: &str,
) -> Result<String, String> {
    if !endpoint_is_pinned_https(endpoint) {
        return Err("AI Pass authorization endpoint is invalid".into());
    }
    let mut url = Url::parse(endpoint)
        .map_err(|_| "AI Pass authorization endpoint is invalid".to_string())?;
    url.query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", REQUIRED_SCOPE)
        .append_pair("state", state)
        .append_pair("code_challenge", code_challenge)
        .append_pair("code_challenge_method", "S256");
    Ok(url.into())
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.as_bytes()
        .iter()
        .zip(right.as_bytes())
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn parse_callback_request(request: &str, expected_state: &str) -> Result<Callback, String> {
    if request.len() > MAX_CALLBACK_BYTES {
        return Err("OAuth callback request is too large".into());
    }
    let request_line = request
        .lines()
        .next()
        .ok_or_else(|| "OAuth callback request is invalid".to_string())?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || method != "GET"
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || !target.starts_with('/')
    {
        return Err("OAuth callback request is invalid".into());
    }
    let url = Url::parse(&format!("http://127.0.0.1{target}"))
        .map_err(|_| "OAuth callback request is invalid".to_string())?;
    if url.path() != "/oauth/callback" {
        return Err("OAuth callback path is invalid".into());
    }

    let mut states = Vec::new();
    let mut codes = Vec::new();
    let mut errors = Vec::new();
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "state" => states.push(value.into_owned()),
            "code" => codes.push(value.into_owned()),
            "error" => errors.push(value.into_owned()),
            _ => {}
        }
    }
    if states.len() != 1 || !constant_time_eq(&states[0], expected_state) {
        return Err("OAuth callback state did not match".into());
    }
    match (codes.as_slice(), errors.as_slice()) {
        ([code], []) if !code.is_empty() && code.len() <= 4096 => Ok(Callback::Code(code.clone())),
        ([], [error]) if !error.is_empty() && error.len() <= 256 => {
            Ok(Callback::Error(error.clone()))
        }
        _ => Err("OAuth callback response is invalid".into()),
    }
}

async fn read_callback_request(stream: &mut TcpStream) -> Result<String, String> {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = timeout(Duration::from_secs(2), stream.read(&mut chunk))
            .await
            .map_err(|_| "OAuth callback request timed out".to_string())?
            .map_err(|_| "OAuth callback request could not be read".to_string())?;
        if read == 0 {
            break;
        }
        if request.len().saturating_add(read) > MAX_CALLBACK_BYTES {
            return Err("OAuth callback request is too large".into());
        }
        request.extend_from_slice(&chunk[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8(request).map_err(|_| "OAuth callback request is invalid".into())
}

async fn write_callback_response(stream: &mut TcpStream, success: bool) {
    let (status, title, message) = if success {
        (
            "200 OK",
            "Return to Parley",
            "Authorization was received. Return to Parley to finish connecting AI Pass.",
        )
    } else {
        (
            "400 Bad Request",
            "Connection not completed",
            "Return to Parley and try connecting AI Pass again.",
        )
    };
    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\">\
         <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\
         <title>{title}</title><body style=\"font-family:system-ui;padding:3rem;text-align:center\">\
         <h1>{title}</h1><p>{message}</p></body>"
    );
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

async fn wait_for_callback(
    listener: TcpListener,
    expected_state: &str,
) -> Result<Callback, String> {
    let deadline = Instant::now() + OAUTH_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("AI Pass connection timed out".into());
        }
        let (mut stream, peer) = timeout(remaining, listener.accept())
            .await
            .map_err(|_| "AI Pass connection timed out".to_string())?
            .map_err(|_| "AI Pass callback listener failed".to_string())?;
        if !peer.ip().is_loopback() {
            write_callback_response(&mut stream, false).await;
            continue;
        }
        match read_callback_request(&mut stream)
            .await
            .and_then(|request| parse_callback_request(&request, expected_state))
        {
            Ok(callback) => {
                write_callback_response(&mut stream, matches!(callback, Callback::Code(_))).await;
                return Ok(callback);
            }
            Err(_) => {
                // Ignore malformed/local-CSRF attempts and keep the one-shot
                // listener alive for the real browser redirect.
                write_callback_response(&mut stream, false).await;
            }
        }
    }
}

#[derive(Default, Zeroize, ZeroizeOnDrop)]
struct TokenResponseSecrets {
    access_token: Option<String>,
    refresh_token: Option<String>,
    scope: Option<String>,
}

fn take_token_string(
    object: &mut serde_json::Map<String, Value>,
    field: &str,
) -> Result<Option<String>, String> {
    match object.remove(field) {
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err("AI Pass token response is invalid".into()),
        None => Ok(None),
    }
}

fn parse_token_response(
    value: &mut Value,
    previous_refresh_token: Option<&str>,
    previous_scope: Option<&str>,
) -> Result<TokenBundle, String> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| "AI Pass token response is invalid".to_string())?;
    // Populate sequentially so any later parse error drops and zeroizes fields
    // already removed from the generic JSON value.
    let mut secrets = TokenResponseSecrets::default();
    secrets.access_token = take_token_string(object, "access_token")?;
    secrets.refresh_token = take_token_string(object, "refresh_token")?;
    secrets.scope = take_token_string(object, "scope")?;
    if !secrets
        .access_token
        .as_deref()
        .is_some_and(|token| !token.is_empty() && token.len() <= 16 * 1024)
    {
        return Err("AI Pass returned an invalid access token".into());
    }
    if secrets
        .refresh_token
        .as_deref()
        .is_some_and(|token| token.is_empty() || token.len() > 16 * 1024)
    {
        return Err("AI Pass returned an invalid refresh token".into());
    }
    if secrets.refresh_token.is_none() && previous_refresh_token.is_none() {
        return Err("AI Pass did not return a refresh token".into());
    }
    if !value
        .get("token_type")
        .and_then(Value::as_str)
        .is_some_and(|token_type| token_type.eq_ignore_ascii_case("bearer"))
    {
        return Err("AI Pass returned an unsupported token type".into());
    }
    let expires_in = value
        .get("expires_in")
        .and_then(Value::as_u64)
        .filter(|seconds| *seconds > 0 && *seconds <= 31_536_000)
        .ok_or_else(|| "AI Pass returned an invalid token lifetime".to_string())?;
    let expires_at_epoch_seconds = now_epoch_seconds()?.saturating_add(expires_in);
    if secrets
        .scope
        .as_deref()
        .is_some_and(|scope| scope.is_empty() || scope.len() > 4096)
    {
        return Err("AI Pass token scope is invalid".into());
    }
    {
        let scope = secrets
            .scope
            .as_deref()
            .or(previous_scope)
            .ok_or_else(|| "AI Pass token scope is missing".to_string())?;
        let granted: HashSet<&str> = scope.split_ascii_whitespace().collect();
        if !granted.contains("api:access") || !granted.contains("profile:read") {
            return Err("AI Pass did not grant the required scopes".into());
        }
    }
    let access_token = secrets
        .access_token
        .take()
        .ok_or_else(|| "AI Pass returned an invalid access token".to_string())?;
    let refresh_token = secrets
        .refresh_token
        .take()
        .or_else(|| previous_refresh_token.map(str::to_owned))
        .ok_or_else(|| "AI Pass did not return a refresh token".to_string())?;
    let scope = secrets
        .scope
        .take()
        .or_else(|| previous_scope.map(str::to_owned))
        .ok_or_else(|| "AI Pass token scope is missing".to_string())?;
    Ok(TokenBundle {
        access_token,
        refresh_token,
        expires_at_epoch_seconds,
        scope: Some(scope),
        profile: Profile::default(),
    })
}

async fn exchange_code(
    client: &Client,
    metadata: &OAuthMetadata,
    client_id: &str,
    redirect_uri: &str,
    code: &str,
    verifier: &str,
) -> Result<TokenBundle, String> {
    let response = send_request(
        client.post(&metadata.token_endpoint).json(&json!({
            "grantType": "authorization_code",
            "code": code,
            "codeVerifier": verifier,
            "clientId": client_id,
            "redirectUri": redirect_uri,
        })),
        "AI Pass token exchange failed",
    )
    .await?;
    if !response.status().is_success() {
        return Err("AI Pass token exchange was rejected".into());
    }
    let body =
        Zeroizing::new(read_limited(response, MAX_TOKEN_BYTES, Duration::from_secs(10)).await?);
    let mut value: Value = serde_json::from_slice(&body)
        .map_err(|_| "AI Pass token response is invalid".to_string())?;
    parse_token_response(&mut value, None, Some(REQUIRED_SCOPE))
}

fn clipped_profile_field(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(256).collect())
}

fn parse_profile(value: &Value) -> Result<Profile, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "AI Pass user profile is invalid".to_string())?;
    let nested = object.get("user").and_then(Value::as_object);
    let find = |key: &str| {
        object.get(key).and_then(Value::as_str).or_else(|| {
            nested
                .and_then(|user| user.get(key))
                .and_then(Value::as_str)
        })
    };
    Ok(Profile {
        display_name: clipped_profile_field(find("name").or_else(|| find("display_name"))),
        email: clipped_profile_field(find("email")),
    })
}

async fn fetch_profile(
    client: &Client,
    metadata: &OAuthMetadata,
    access_token: &str,
) -> Result<Profile, String> {
    let response = send_request(
        client
            .get(&metadata.userinfo_endpoint)
            .bearer_auth(access_token),
        "AI Pass user profile is unavailable",
    )
    .await?;
    if !response.status().is_success() {
        return Err("AI Pass user profile request was rejected".into());
    }
    let body = read_limited(response, MAX_USERINFO_BYTES, Duration::from_secs(10)).await?;
    let value: Value =
        serde_json::from_slice(&body).map_err(|_| "AI Pass user profile is invalid".to_string())?;
    parse_profile(&value)
}

#[tauri::command]
pub async fn aipass_connect(
    app: AppHandle,
    state: State<'_, AiPassState>,
) -> Result<ConnectionStatus, String> {
    let _connect_guard = state.connect_lock.lock().await;
    let _credential_guard = state.refresh_lock.lock().await;
    if keychain_load()?.is_some() {
        return Err("AI Pass is already connected; disconnect it first".into());
    }
    let client_id =
        client_id().ok_or_else(|| "AI Pass is not configured in this build".to_string())?;
    let metadata = fetch_metadata(&state.client).await?;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| "could not start the local OAuth callback".to_string())?;
    let port = listener
        .local_addr()
        .map_err(|_| "could not inspect the local OAuth callback".to_string())?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/oauth/callback");

    let verifier = Zeroizing::new(random_urlsafe(64));
    let state_value = Zeroizing::new(random_urlsafe(32));
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let authorization_url = build_authorization_url(
        &metadata.authorization_endpoint,
        client_id,
        &redirect_uri,
        &challenge,
        &state_value,
    )?;
    app.opener()
        .open_url(authorization_url, None::<String>)
        .map_err(|_| "could not open the AI Pass authorization page".to_string())?;

    let code = match wait_for_callback(listener, &state_value).await? {
        Callback::Code(code) => Zeroizing::new(code),
        Callback::Error(_) => return Err("AI Pass authorization was not approved".into()),
    };
    let mut tokens = exchange_code(
        &state.client,
        &metadata,
        client_id,
        &redirect_uri,
        &code,
        &verifier,
    )
    .await?;
    tokens.profile = match fetch_profile(&state.client, &metadata, &tokens.access_token).await {
        Ok(profile) => profile,
        Err(error) => {
            revoke_token(
                &state.client,
                &metadata.revocation_endpoint,
                client_id,
                &tokens.refresh_token,
            )
            .await;
            revoke_token(
                &state.client,
                &metadata.revocation_endpoint,
                client_id,
                &tokens.access_token,
            )
            .await;
            return Err(error);
        }
    };
    if let Err(error) = keychain_save(&tokens) {
        revoke_token(
            &state.client,
            &metadata.revocation_endpoint,
            client_id,
            &tokens.refresh_token,
        )
        .await;
        revoke_token(
            &state.client,
            &metadata.revocation_endpoint,
            client_id,
            &tokens.access_token,
        )
        .await;
        return Err(error);
    }
    let status = ConnectionStatus::connected(tokens.profile.clone());
    let _ = app.emit(STATUS_EVENT, &status);
    Ok(status)
}

#[tauri::command]
pub fn aipass_status() -> Result<ConnectionStatus, String> {
    match keychain_load()? {
        Some(tokens) => Ok(ConnectionStatus::connected(tokens.profile.clone())),
        None => Ok(ConnectionStatus::disconnected()),
    }
}

fn clear_connection(app: &AppHandle, state: &AiPassState) -> Result<(), String> {
    cancel_all_chat(state);
    keychain_delete()?;
    let _ = app.emit(STATUS_EVENT, ConnectionStatus::disconnected());
    Ok(())
}

async fn refresh_access_token(
    state: &AiPassState,
    app: &AppHandle,
    force: bool,
) -> Result<Zeroizing<String>, String> {
    let _refresh_guard = state.refresh_lock.lock().await;
    let tokens = keychain_load()?.ok_or_else(|| "Connect AI Pass in Settings first".to_string())?;
    let now = now_epoch_seconds()?;
    if !force && tokens.expires_at_epoch_seconds > now.saturating_add(60) {
        return Ok(Zeroizing::new(tokens.access_token.clone()));
    }

    let client_id =
        client_id().ok_or_else(|| "AI Pass is not configured in this build".to_string())?;
    let metadata = fetch_metadata(&state.client).await?;
    let response = send_request(
        state.client.post(&metadata.token_endpoint).json(&json!({
            "grantType": "refresh_token",
            "refreshToken": tokens.refresh_token,
            "clientId": client_id,
        })),
        "AI Pass session refresh failed",
    )
    .await?;
    let status = response.status();
    if !status.is_success() {
        if matches!(status, StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED) {
            clear_connection(app, state)?;
            return Err("AI Pass connection expired; connect it again in Settings".into());
        }
        return Err("AI Pass session refresh failed".into());
    }
    let body = match read_limited(response, MAX_TOKEN_BYTES, Duration::from_secs(10)).await {
        Ok(body) => body,
        Err(error) => {
            let _ = clear_connection(app, state);
            return Err(error);
        }
    };
    let mut body = Zeroizing::new(body);
    let mut value: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => {
            body.zeroize();
            let _ = clear_connection(app, state);
            return Err("AI Pass token response is invalid".into());
        }
    };
    let mut rotated = match parse_token_response(
        &mut value,
        Some(&tokens.refresh_token),
        tokens.scope.as_deref(),
    ) {
        Ok(rotated) => rotated,
        Err(error) => {
            let _ = clear_connection(app, state);
            return Err(error);
        }
    };
    rotated.profile = tokens.profile.clone();
    // Security.framework performs SecItemUpdate atomically, so the new access
    // token and rotated refresh token replace the old bundle as one Keychain item.
    if let Err(error) = keychain_save(&rotated) {
        let _ = clear_connection(app, state);
        return Err(error);
    }
    Ok(Zeroizing::new(rotated.access_token.clone()))
}

fn parse_model_ids(value: &Value) -> Result<Vec<String>, String> {
    let (entries, openai_envelope) = match value {
        // Keep accepting the pre-OpenAI string-array migration shape, but
        // validate the default envelope against the standard model contract.
        Value::Array(entries) => (entries, false),
        Value::Object(object) if object.get("object").and_then(Value::as_str) == Some("list") => (
            object
                .get("data")
                .and_then(Value::as_array)
                .ok_or_else(|| "AI Pass model list is invalid".to_string())?,
            true,
        ),
        _ => return Err("AI Pass model list is invalid".into()),
    };
    if entries.len() > MAX_MODELS {
        return Err("AI Pass returned too many models".into());
    }

    let mut seen = HashSet::new();
    let mut models = Vec::new();
    for entry in entries {
        let id = match (openai_envelope, entry) {
            (true, Value::Object(model)) => {
                if model.get("object").and_then(Value::as_str) != Some("model")
                    || model.get("created").and_then(Value::as_u64).is_none()
                    || model
                        .get("owned_by")
                        .and_then(Value::as_str)
                        .is_none_or(str::is_empty)
                {
                    return Err("AI Pass model entry is invalid".into());
                }
                model
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "AI Pass model entry is invalid".to_string())?
            }
            (false, Value::String(id)) => id,
            _ => return Err("AI Pass model entry is invalid".into()),
        };
        if id.is_empty() || id.len() > MAX_MODEL_ID_BYTES || id.chars().any(char::is_control) {
            return Err("AI Pass model id is invalid".into());
        }
        if seen.insert(id.to_owned()) {
            models.push(id.to_owned());
        }
    }
    if models.is_empty() {
        return Err("AI Pass returned no models".into());
    }
    Ok(models)
}

async fn authenticated_models_request(
    state: &AiPassState,
    app: &AppHandle,
    force_refresh: bool,
) -> Result<Response, String> {
    let access_token = refresh_access_token(state, app, force_refresh).await?;
    send_request(
        state.client.get(MODELS_URL).bearer_auth(&*access_token),
        "AI Pass model discovery failed",
    )
    .await
}

#[tauri::command]
pub async fn aipass_models(
    app: AppHandle,
    state: State<'_, AiPassState>,
) -> Result<Vec<String>, String> {
    let mut response = authenticated_models_request(&state, &app, false).await?;
    if response.status() == StatusCode::UNAUTHORIZED {
        response = authenticated_models_request(&state, &app, true).await?;
        if response.status() == StatusCode::UNAUTHORIZED {
            clear_connection(&app, &state)?;
        }
    }
    if !response.status().is_success() {
        return Err("AI Pass model discovery was rejected".into());
    }
    let body = read_limited(response, MAX_MODELS_BYTES, Duration::from_secs(15)).await?;
    let value: Value =
        serde_json::from_slice(&body).map_err(|_| "AI Pass model list is invalid".to_string())?;
    parse_model_ids(&value)
}

async fn revoke_token(client: &Client, endpoint: &str, client_id: &str, token: &str) {
    let _ = send_request(
        client
            .post(endpoint)
            .form(&[("token", token), ("client_id", client_id)]),
        "AI Pass revocation failed",
    )
    .await;
}

#[tauri::command]
pub async fn aipass_disconnect(
    app: AppHandle,
    state: State<'_, AiPassState>,
) -> Result<ConnectionStatus, String> {
    // Cancel before waiting for a refresh holder. Otherwise an in-flight chat
    // can finish refreshing and begin billable work while disconnect is queued
    // on the credential mutex.
    cancel_all_chat(&state);
    let _connect_guard = state.connect_lock.lock().await;
    let _credential_guard = state.refresh_lock.lock().await;
    // Cover work registered while the async locks were being acquired.
    cancel_all_chat(&state);
    let tokens = keychain_load()?;
    // Clear local authority first. Revocation is best-effort so an unavailable
    // network can never leave the account connected on this device.
    let clear_result = clear_connection(&app, &state);
    if let (Some(tokens), Some(client_id)) = (tokens, client_id()) {
        if let Ok(metadata) = fetch_metadata(&state.client).await {
            revoke_token(
                &state.client,
                &metadata.revocation_endpoint,
                client_id,
                &tokens.refresh_token,
            )
            .await;
            revoke_token(
                &state.client,
                &metadata.revocation_endpoint,
                client_id,
                &tokens.access_token,
            )
            .await;
        }
    }
    clear_result?;
    Ok(ConnectionStatus::disconnected())
}

fn validate_chat_request(body: &str) -> Result<(), String> {
    if body.is_empty() || body.len() > MAX_CHAT_REQUEST_BYTES {
        return Err("AI Pass chat request exceeded the size limit".into());
    }
    let value: Value =
        serde_json::from_str(body).map_err(|_| "AI Pass chat request is invalid".to_string())?;
    let object = value
        .as_object()
        .ok_or_else(|| "AI Pass chat request is invalid".to_string())?;
    if !object
        .get("model")
        .and_then(Value::as_str)
        .is_some_and(|model| !model.is_empty() && model.len() <= MAX_MODEL_ID_BYTES)
        || !object.get("messages").is_some_and(Value::is_array)
    {
        return Err("AI Pass chat request is invalid".into());
    }
    Ok(())
}

async fn authenticated_chat_request(
    state: &AiPassState,
    app: &AppHandle,
    body: &str,
    force_refresh: bool,
    cancellation: &CancellationToken,
) -> Result<Response, String> {
    let access_token = refresh_access_token(state, app, force_refresh).await?;
    tokio::select! {
        _ = cancellation.cancelled() => Err("AI Pass request cancelled".into()),
        response = send_request(
            state
                .client
                .post(CHAT_URL)
                .bearer_auth(&*access_token)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_owned()),
            "AI Pass chat request failed",
        ) => response,
    }
}

fn clipped_error_message(value: &Value, status: StatusCode) -> String {
    let candidate = value
        .pointer("/error/message")
        .and_then(Value::as_str)
        .or_else(|| value.get("message").and_then(Value::as_str));
    let cleaned = candidate
        .map(|message| {
            message
                .chars()
                .filter(|character| !character.is_control())
                .take(512)
                .collect::<String>()
        })
        .filter(|message| {
            if message.is_empty() {
                return false;
            }
            let lowered = message.to_ascii_lowercase();
            if ["authorization", "bearer ", "access_token", "refresh_token"]
                .iter()
                .any(|marker| lowered.contains(marker))
            {
                return false;
            }
            !message
                .split_whitespace()
                .any(|word| word.len() > 128 && word.is_ascii())
        });
    cleaned.unwrap_or_else(|| format!("AI Pass request failed ({})", status.as_u16()))
}

async fn send_bounded_error(
    response: Response,
    events: &Channel<StreamMessage>,
) -> Result<(), String> {
    let status = response.status();
    let body = read_limited(response, MAX_ERROR_BYTES, Duration::from_secs(10)).await?;
    let value: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let message = clipped_error_message(&value, status);
    let sanitized = serde_json::to_vec(&json!({
        "error": {
            "message": message,
            "type": "aipass_error",
            "code": status.as_u16(),
        }
    }))
    .map_err(|_| "could not prepare the AI Pass error response".to_string())?;
    events
        .send(StreamMessage::Headers {
            status: status.as_u16(),
            content_type: "application/json".into(),
        })
        .map_err(|_| "AI Pass response consumer closed".to_string())?;
    events
        .send(StreamMessage::Data {
            data: STANDARD.encode(sanitized),
        })
        .map_err(|_| "AI Pass response consumer closed".to_string())?;
    events
        .send(StreamMessage::Done)
        .map_err(|_| "AI Pass response consumer closed".to_string())
}

async fn stream_chat_response(
    response: Response,
    events: &Channel<StreamMessage>,
    cancellation: &CancellationToken,
) -> Result<(), String> {
    if !response.status().is_success() {
        return send_bounded_error(response, events).await;
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_CHAT_RESPONSE_BYTES as u64)
    {
        return Err("AI Pass response exceeded the size limit".into());
    }
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= 256)
        .unwrap_or("application/octet-stream")
        .to_owned();
    events
        .send(StreamMessage::Headers {
            status,
            content_type,
        })
        .map_err(|_| "AI Pass response consumer closed".to_string())?;

    let transfer = async {
        let mut stream = response.bytes_stream();
        let mut total = 0_usize;
        loop {
            let next = tokio::select! {
                _ = cancellation.cancelled() => return Err("AI Pass request cancelled".into()),
                next = timeout(STREAM_IDLE_TIMEOUT, stream.next()) => {
                    next.map_err(|_| "AI Pass response timed out".to_string())?
                }
            };
            let Some(chunk) = next else {
                break;
            };
            let chunk = chunk.map_err(|_| "AI Pass response stream failed".to_string())?;
            total = total.saturating_add(chunk.len());
            if total > MAX_CHAT_RESPONSE_BYTES {
                return Err("AI Pass response exceeded the size limit".into());
            }
            for piece in chunk.chunks(MAX_STREAM_CHUNK_BYTES) {
                events
                    .send(StreamMessage::Data {
                        data: STANDARD.encode(piece),
                    })
                    .map_err(|_| "AI Pass response consumer closed".to_string())?;
            }
        }
        Ok::<(), String>(())
    };
    timeout(STREAM_TOTAL_TIMEOUT, transfer)
        .await
        .map_err(|_| "AI Pass response exceeded the time limit".to_string())??;
    events
        .send(StreamMessage::Done)
        .map_err(|_| "AI Pass response consumer closed".to_string())
}

async fn run_chat(
    state: &AiPassState,
    app: &AppHandle,
    body: &str,
    events: &Channel<StreamMessage>,
    cancellation: &CancellationToken,
) -> Result<(), String> {
    let mut response = authenticated_chat_request(state, app, body, false, cancellation).await?;
    if response.status() == StatusCode::UNAUTHORIZED {
        response = authenticated_chat_request(state, app, body, true, cancellation).await?;
        if response.status() == StatusCode::UNAUTHORIZED {
            clear_connection(app, state)?;
        }
    }
    stream_chat_response(response, events, cancellation).await
}

#[tauri::command]
pub async fn aipass_chat(
    app: AppHandle,
    body: String,
    request_id: String,
    on_event: Channel<StreamMessage>,
    state: State<'_, AiPassState>,
) -> Result<(), String> {
    validate_chat_request(&body)?;
    if request_id.is_empty()
        || request_id.len() > 64
        || !request_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("AI Pass request id is invalid".into());
    }
    let cancellation = CancellationToken::new();
    {
        let mut active = state.active_chat.lock().unwrap();
        if active.contains_key(&request_id) {
            return Err("AI Pass request id is already active".into());
        }
        if active.len() >= MAX_ACTIVE_CHAT_REQUESTS {
            return Err("Too many AI Pass requests are active".into());
        }
        active.insert(request_id.clone(), cancellation.clone());
    }
    let result = run_chat(&state, &app, &body, &on_event, &cancellation).await;
    state.active_chat.lock().unwrap().remove(&request_id);
    if let Err(message) = &result {
        let _ = on_event.send(StreamMessage::Error {
            message: message.clone(),
        });
    }
    result
}

#[tauri::command]
pub async fn aipass_cancel_chat(
    request_id: String,
    state: State<'_, AiPassState>,
) -> Result<(), String> {
    if request_id.len() > 64 {
        return Err("AI Pass request id is invalid".into());
    }
    if let Some(cancellation) = state.active_chat.lock().unwrap().get(&request_id) {
        cancellation.cancel();
    }
    Ok(())
}

pub fn cancel_all_chat(state: &AiPassState) {
    let active = state.active_chat.lock().unwrap();
    for cancellation in active.values() {
        cancellation.cancel();
    }
}

#[tauri::command]
pub async fn aipass_cancel_all_chat(state: State<'_, AiPassState>) -> Result<(), String> {
    cancel_all_chat(&state);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn authorization_url_uses_code_pkce_s256_and_strong_state() {
        let url = build_authorization_url(
            "https://aipass.one/oauth2/authorize",
            "public-client",
            "http://127.0.0.1:49152/oauth/callback",
            "challenge-value",
            "state-value",
        )
        .expect("authorization URL");

        assert!(url.starts_with("https://aipass.one/oauth2/authorize?"));
        assert!(url.contains("client_id=public-client"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("code_challenge=challenge-value"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("state=state-value"));
        assert!(url.contains("scope=api%3Aaccess+profile%3Aread"));
        assert!(!url.contains("client_secret"));

        let state = random_urlsafe(32);
        let verifier = random_urlsafe(64);
        assert!(state.len() >= 43);
        assert!((43..=128).contains(&verifier.len()));
        assert_ne!(state, random_urlsafe(32));
    }

    #[test]
    fn callback_requires_exact_path_and_matching_state() {
        let request =
            "GET /oauth/callback?code=auth-code&state=expected HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        assert_eq!(
            parse_callback_request(request, "expected").expect("valid callback"),
            Callback::Code("auth-code".into())
        );

        assert!(parse_callback_request(
            "GET /other?code=auth-code&state=expected HTTP/1.1\r\n\r\n",
            "expected"
        )
        .is_err());
        assert!(parse_callback_request(
            "GET /oauth/callback?code=auth-code&state=wrong HTTP/1.1\r\n\r\n",
            "expected"
        )
        .is_err());
    }

    #[test]
    fn model_discovery_uses_openai_contract_and_server_side_chat_filters() {
        assert_eq!(
            MODELS_URL,
            "https://aipass.one/oauth2/v1/models?type=text&method=chat_completions"
        );

        let openai = json!({
            "object": "list",
            "data": [
                {
                    "id": "provider/new-chat-model",
                    "object": "model",
                    "created": 1_753_000_000_u64,
                    "owned_by": "provider",
                    "future_additive_field": {"nested": true}
                },
                {
                    "id": "another-provider/model:version",
                    "object": "model",
                    "created": 1_753_000_001_u64,
                    "owned_by": "another-provider"
                }
            ]
        });
        assert_eq!(
            parse_model_ids(&openai).expect("OpenAI-compatible models"),
            vec!["provider/new-chat-model", "another-provider/model:version"]
        );

        for missing in ["object", "created", "owned_by"] {
            let mut malformed = openai.clone();
            malformed["data"][0]
                .as_object_mut()
                .expect("model object")
                .remove(missing);
            assert!(
                parse_model_ids(&malformed).is_err(),
                "canonical model missing {missing} must be rejected"
            );
        }
    }

    #[test]
    fn model_discovery_accepts_legacy_string_arrays_for_migration() {
        let legacy = json!(["future/model-a", "future/model-b", "future/model-a"]);
        assert_eq!(
            parse_model_ids(&legacy).expect("legacy models"),
            vec!["future/model-a", "future/model-b"]
        );
        assert!(parse_model_ids(&json!([{"id": "legacy/object-model"}])).is_err());
    }

    #[test]
    fn model_discovery_rejects_unbounded_or_malformed_payloads() {
        assert!(parse_model_ids(&json!({"object": "list", "data": "bad"})).is_err());
        assert!(parse_model_ids(&json!([7, "valid"])).is_err());
        assert!(parse_model_ids(&json!([""])).is_err());
        assert!(parse_model_ids(&json!(["x".repeat(MAX_MODEL_ID_BYTES + 1)])).is_err());
    }

    #[test]
    fn oauth_metadata_must_match_the_pinned_issuer_and_secure_endpoints() {
        let metadata = json!({
            "issuer": "https://aipass.one",
            "authorization_endpoint": "https://aipass.one/oauth2/authorize",
            "token_endpoint": "https://aipass.one/oauth2/token",
            "userinfo_endpoint": "https://aipass.one/oauth2/userinfo",
            "revocation_endpoint": "https://aipass.one/oauth2/revoke",
            "scopes_supported": ["api:access", "profile:read"],
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"]
        });
        validate_metadata(&metadata).expect("valid metadata");

        let mut wrong_host = metadata;
        wrong_host["token_endpoint"] = json!("https://attacker.example/oauth2/token");
        assert!(validate_metadata(&wrong_host).is_err());

        let mut missing_scope = wrong_host;
        missing_scope["token_endpoint"] = json!("https://aipass.one/oauth2/token");
        missing_scope["scopes_supported"] = json!(["profile:read"]);
        assert!(validate_metadata(&missing_scope).is_err());
    }

    #[test]
    fn token_rotation_requires_bearer_and_preserves_required_scope() {
        let mut initial = json!({
            "access_token": "access-1",
            "refresh_token": "refresh-1",
            "expires_in": 3600,
            "token_type": "Bearer",
            "scope": "api:access profile:read"
        });
        let tokens = parse_token_response(&mut initial, None, None).expect("initial tokens");
        assert_eq!(tokens.refresh_token, "refresh-1");

        let mut rotated = json!({
            "access_token": "access-2",
            "expires_in": 3600,
            "token_type": "bearer"
        });
        let next = parse_token_response(
            &mut rotated,
            Some(&tokens.refresh_token),
            tokens.scope.as_deref(),
        )
        .expect("rotated tokens");
        assert_eq!(next.refresh_token, "refresh-1");
        assert_eq!(next.scope.as_deref(), Some("api:access profile:read"));

        let mut malformed_rotation = json!({
            "access_token": "access-3",
            "refresh_token": "",
            "expires_in": 3600,
            "token_type": "Bearer"
        });
        assert!(parse_token_response(
            &mut malformed_rotation,
            Some(&tokens.refresh_token),
            tokens.scope.as_deref(),
        )
        .is_err());

        let mut insufficient = json!({
            "access_token": "access",
            "refresh_token": "refresh",
            "expires_in": 3600,
            "token_type": "Bearer",
            "scope": "profile:read"
        });
        assert!(parse_token_response(&mut insufficient, None, None).is_err());
    }

    #[test]
    fn upstream_errors_cannot_echo_credentials() {
        let safe = json!({"error": {"message": "Shared wallet balance is too low"}});
        assert_eq!(
            clipped_error_message(&safe, StatusCode::PAYMENT_REQUIRED),
            "Shared wallet balance is too low"
        );

        let unsafe_message =
            json!({"error": {"message": "Authorization: Bearer should-never-surface"}});
        assert_eq!(
            clipped_error_message(&unsafe_message, StatusCode::UNAUTHORIZED),
            "AI Pass request failed (401)"
        );
    }
}
