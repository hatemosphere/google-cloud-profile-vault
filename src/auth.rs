use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use oauth2::basic::BasicClient;
use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use serde::Deserialize;
use url::Url;

use crate::secret::SecretString;

// gcloud's public installed-application OAuth client. The client secret is
// public by design and is embedded in gcloud-generated authorized-user ADC.
pub const CLIENT_ID: &str =
    "764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com";
pub const CLIENT_SECRET: &str = "d-FL95Q19q7MQmFpd7hHD0Ty";

const AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const USERINFO_ENDPOINT: &str = "https://openidconnect.googleapis.com/v1/userinfo";
const LOGIN_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_REQUEST_LINE: u64 = 8 * 1024;

const IDENTITY_SCOPES: &[&str] = &["openid", "https://www.googleapis.com/auth/userinfo.email"];
const DEFAULT_API_SCOPES: &[&str] = &[
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/sqlservice.login",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
    pub subject: String,
    pub email: String,
}

#[derive(Debug)]
pub struct Login {
    pub refresh_token: SecretString,
    pub identity: Identity,
}

/// Returns API scopes plus the identity scopes required to bind credentials to
/// the intended Google account.
pub fn effective_scopes(configured: Option<&[String]>) -> Vec<String> {
    let mut scopes: Vec<String> = IDENTITY_SCOPES
        .iter()
        .map(|scope| (*scope).to_owned())
        .collect();
    let api_scopes: Vec<String> = configured.map_or_else(
        || {
            DEFAULT_API_SCOPES
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect()
        },
        <[String]>::to_vec,
    );
    for scope in api_scopes {
        if !scopes.contains(&scope) {
            scopes.push(scope);
        }
    }
    scopes
}

pub async fn login(
    login_hint: Option<&str>,
    scopes: &[String],
    chrome_profile: Option<&str>,
) -> Result<Login> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).context("binding loopback listener")?;
    let redirect_uri = format!("http://127.0.0.1:{}/", listener.local_addr()?.port());

    let client = BasicClient::new(ClientId::new(CLIENT_ID.into()))
        .set_client_secret(ClientSecret::new(CLIENT_SECRET.into()))
        .set_auth_uri(AuthUrl::new(AUTH_ENDPOINT.into())?)
        .set_token_uri(TokenUrl::new(TOKEN_ENDPOINT.into())?)
        .set_redirect_uri(RedirectUrl::new(redirect_uri)?)
        .set_auth_type(AuthType::RequestBody);

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let mut request = client
        .authorize_url(CsrfToken::new_random)
        .add_scopes(scopes.iter().cloned().map(Scope::new))
        .add_extra_param("access_type", "offline")
        .add_extra_param("prompt", "consent")
        .set_pkce_challenge(pkce_challenge);
    if let Some(hint) = login_hint {
        request = request.add_extra_param("login_hint", hint);
    }
    let (auth_url, csrf_state) = request.url();

    eprintln!("Opening browser for Google sign-in; if nothing happens, open:\n\n  {auth_url}\n");
    if let Some(directory) = chrome_profile {
        eprintln!("(using Chrome profile '{directory}')");
        crate::chrome::open_in_profile(auth_url.as_str(), directory)?;
    } else {
        crate::chrome::open_default(auth_url.as_str());
    }

    let code = tokio::task::spawn_blocking(move || {
        wait_for_code(listener, csrf_state.secret(), LOGIN_TIMEOUT)
    })
    .await
    .context("OAuth callback task failed")??;
    crate::diagnostics::debug(format_args!(
        "OAuth callback accepted; exchanging authorization code"
    ));

    let http = oauth2::reqwest::ClientBuilder::new()
        .redirect(oauth2::reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()?;
    let token = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(pkce_verifier)
        .request_async(&http)
        .await
        .map_err(|error| anyhow!("token exchange failed: {error:?}"))?;

    let refresh_token = token
        .refresh_token()
        .ok_or_else(|| anyhow!("Google returned no refresh token"))?;
    let identity = fetch_identity(&http, token.access_token().secret()).await?;
    crate::diagnostics::debug(format_args!(
        "token exchange and Google identity verification succeeded"
    ));

    Ok(Login {
        refresh_token: SecretString::new(refresh_token.secret()),
        identity,
    })
}

async fn fetch_identity(http: &oauth2::reqwest::Client, access_token: &str) -> Result<Identity> {
    #[derive(Deserialize)]
    struct UserInfo {
        sub: String,
        email: String,
        email_verified: bool,
    }

    let response = http
        .get(USERINFO_ENDPOINT)
        .bearer_auth(access_token)
        .send()
        .await
        .context("requesting Google account identity")?
        .error_for_status()
        .context("Google account identity request failed")?;
    let body = response
        .text()
        .await
        .context("reading Google account identity")?;
    let user: UserInfo = serde_json::from_str(&body).context("parsing Google account identity")?;
    if !user.email_verified {
        bail!("Google did not return a verified account email");
    }
    if user.sub.is_empty() || user.email.is_empty() {
        bail!("Google returned an incomplete account identity");
    }
    Ok(Identity {
        subject: user.sub,
        email: user.email,
    })
}

#[derive(Debug, Eq, PartialEq)]
enum Callback {
    Continue,
    Code(String),
    Denied(String),
}

fn wait_for_code(listener: TcpListener, expected_state: &str, timeout: Duration) -> Result<String> {
    listener
        .set_nonblocking(true)
        .context("configuring OAuth callback listener")?;
    let deadline = Instant::now() + timeout;

    loop {
        if Instant::now() >= deadline {
            bail!("timed out waiting for the OAuth callback");
        }
        match listener.accept() {
            Ok((stream, _)) => match handle_connection(stream, expected_state) {
                Ok(Callback::Code(code)) => return Ok(code),
                Ok(Callback::Denied(error)) => bail!("authorization failed: {error}"),
                Ok(Callback::Continue) | Err(_) => {}
            },
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error).context("accepting OAuth callback"),
        }
    }
}

fn handle_connection(mut stream: TcpStream, expected_state: &str) -> Result<Callback> {
    // Accepted sockets inherit O_NONBLOCK on BSD-derived systems. Switch back
    // to blocking mode so the read timeout below governs slow connections.
    stream
        .set_nonblocking(false)
        .context("configuring OAuth callback connection")?;
    stream
        .set_read_timeout(Some(CONNECTION_TIMEOUT))
        .context("configuring OAuth callback connection")?;
    let mut line = String::new();
    {
        let mut reader = BufReader::new(&stream).take(MAX_REQUEST_LINE + 1);
        reader
            .read_line(&mut line)
            .context("reading OAuth callback request")?;
    }
    if line.len() as u64 > MAX_REQUEST_LINE {
        respond(&mut stream, "414 URI Too Long", "request too long");
        return Ok(Callback::Continue);
    }

    let mut request = line.split_whitespace();
    if request.next() != Some("GET") {
        respond(&mut stream, "405 Method Not Allowed", "method not allowed");
        return Ok(Callback::Continue);
    }
    let Some(path) = request.next().filter(|path| path.starts_with('/')) else {
        respond(&mut stream, "400 Bad Request", "invalid request");
        return Ok(Callback::Continue);
    };
    let url = match Url::parse(&format!("http://127.0.0.1{path}")) {
        Ok(url) => url,
        Err(_) => {
            respond(&mut stream, "400 Bad Request", "invalid callback URL");
            return Ok(Callback::Continue);
        }
    };

    let mut code = None;
    let mut state = None;
    let mut error = None;
    for (key, value) in url.query_pairs() {
        let slot = match key.as_ref() {
            "code" => &mut code,
            "state" => &mut state,
            "error" => &mut error,
            _ => continue,
        };
        if slot.replace(value.into_owned()).is_some() {
            respond(
                &mut stream,
                "400 Bad Request",
                "duplicate callback parameter",
            );
            return Ok(Callback::Continue);
        }
    }

    if state.as_deref() != Some(expected_state) {
        respond(&mut stream, "400 Bad Request", "state mismatch");
        return Ok(Callback::Continue);
    }
    if let Some(error) = error {
        respond(
            &mut stream,
            "200 OK",
            "gcpv: sign-in failed, you can close this tab.",
        );
        return Ok(Callback::Denied(error));
    }
    let Some(code) = code else {
        respond(&mut stream, "404 Not Found", "not found");
        return Ok(Callback::Continue);
    };

    respond(
        &mut stream,
        "200 OK",
        "gcpv: sign-in complete, you can close this tab.",
    );
    Ok(Callback::Code(code))
}

fn respond(stream: &mut TcpStream, status: &str, body: &str) {
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    fn listen() -> (TcpListener, u16) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        (listener, port)
    }

    fn request(port: u16, path: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(stream, "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    #[test]
    fn effective_scopes_always_include_identity_and_deduplicate() {
        let configured = vec![
            "https://www.googleapis.com/auth/bigquery.readonly".into(),
            "openid".into(),
        ];
        let scopes = effective_scopes(Some(&configured));
        assert!(scopes.iter().any(|scope| scope == "openid"));
        assert!(
            scopes
                .iter()
                .any(|scope| scope.ends_with("/auth/userinfo.email"))
        );
        assert!(
            scopes
                .iter()
                .any(|scope| scope.ends_with("bigquery.readonly"))
        );
        assert_eq!(scopes.iter().filter(|scope| *scope == "openid").count(), 1);
        assert!(!scopes.iter().any(|scope| scope.ends_with("cloud-platform")));
    }

    #[test]
    fn accepts_matching_state_and_decodes_the_code() {
        let (listener, port) = listen();
        let handle =
            thread::spawn(move || wait_for_code(listener, "st4te", Duration::from_secs(1)));
        assert!(request(port, "/favicon.ico").contains("400"));
        assert!(request(port, "/?code=4%2Fabc&state=st4te").contains("200"));
        assert_eq!(handle.join().unwrap().unwrap(), "4/abc");
    }

    #[test]
    fn wrong_state_does_not_consume_the_legitimate_flow() {
        let (listener, port) = listen();
        let handle =
            thread::spawn(move || wait_for_code(listener, "expected", Duration::from_secs(1)));
        assert!(request(port, "/?code=forged&state=wrong").contains("400"));
        assert!(request(port, "/?code=real&state=expected").contains("200"));
        assert_eq!(handle.join().unwrap().unwrap(), "real");
    }

    #[test]
    fn accepted_connection_waits_for_request_bytes() {
        let (listener, port) = listen();
        listener.set_nonblocking(true).unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::yield_now();
                }
                Err(error) => panic!("accepting test connection: {error}"),
            }
        };

        let handle = thread::spawn(move || handle_connection(stream, "expected"));
        thread::sleep(Duration::from_millis(20));
        write!(
            client,
            "GET /?code=real&state=expected HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();

        assert!(response.contains("200 OK"));
        assert_eq!(
            handle.join().unwrap().unwrap(),
            Callback::Code("real".into())
        );
    }

    #[test]
    fn untrusted_error_cannot_abort_the_flow() {
        let (listener, port) = listen();
        let handle =
            thread::spawn(move || wait_for_code(listener, "expected", Duration::from_secs(1)));
        assert!(request(port, "/?error=access_denied&state=wrong").contains("400"));
        request(port, "/?code=real&state=expected");
        assert_eq!(handle.join().unwrap().unwrap(), "real");
    }

    #[test]
    fn surfaces_provider_error_after_state_validation() {
        let (listener, port) = listen();
        let handle = thread::spawn(move || wait_for_code(listener, "s", Duration::from_secs(1)));
        request(port, "/?error=access_denied&state=s");
        let error = handle.join().unwrap().unwrap_err();
        assert!(error.to_string().contains("access_denied"));
    }

    #[test]
    fn callback_wait_has_a_deadline() {
        let (listener, _port) = listen();
        let started = Instant::now();
        let error = wait_for_code(listener, "s", Duration::from_millis(30)).unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
