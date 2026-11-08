//! PLAN.md 5.7: the base layout for a visitor and for a signed-in user, login and logout over 5.4's
//! service with the CSRF check, the security headers, the embedded assets, escaping, and the theme. The
//! Done check, that a template using a missing field fails the build, is `templates`' doctests.
//!
//! PLAN.md 5.8: the alert view, drawn by its view function from a fixture tree and through the service
//! from Postgres, with the Splunk module's result showing ace3's display types; the live stream that
//! pushes a result as it lands, ends with the session, is bounded, and leaves nothing when its client
//! goes; and the section pins. The browser's half of the Done check is `tests/e2e/run`'s.

use std::collections::BTreeSet;
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use ace_core::eligibility::Catalog;
use ace_core::modes::Modes;
use ace_core::orchestrator::Orchestrator;
use ace_core::testing::TestDb;
use ace_gui::alert::{AlertPage, AlertTreeFragment, tree_view};
use ace_gui::templates::{ErrorPage, HomePage, Layout, LoginPage};
use ace_gui::{Gui, LiveLimits, asset_named};
use ace_service::{
    Actor, Addition, Alert, AlertDetection, AlertFile, AlertObservable, AlertSummary, AlertTree,
    AnalysisState, CommentAuthor, Component, Effect, Holder, ModuleResult, ObservableComment,
    Password, PermissionPattern, Profile, RecordedActor, Service, ServiceError, Theme, Transport,
    Username,
};
use askama::Template;
use reqwest::StatusCode;
use reqwest::header::{HeaderMap, LOCATION, SET_COOKIE};
use sha2::{Digest, Sha256};

const PASSWORD: &str = "correct horse battery staple";

struct Stack {
    test_db: TestDb,
    service: Service,
    gui: Gui,
    url: String,
    http: reqwest::Client,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Stack {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn stack() -> Stack {
    stack_with(LiveLimits::default()).await
}

async fn stack_with(limits: LiveLimits) -> Stack {
    let test_db = TestDb::new().await;
    let orchestrator = Orchestrator::new(Catalog::new(vec![]), Modes::ace3());
    let service = Service::new(test_db.db().clone(), orchestrator);
    let gui = Gui::with_limits(service.clone(), Transport::Plain, limits);
    let router = gui.router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds");
    let url = format!("http://{}", listener.local_addr().expect("an address"));
    let task = tokio::spawn(async move {
        let served = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
        if let Err(e) = served {
            eprintln!("the GUI stopped: {e}");
        }
    });
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("a client");
    Stack {
        test_db,
        service,
        gui,
        url,
        http,
        task,
    }
}

fn bootstrap() -> Actor {
    Actor::Internal {
        id: Component::new("bootstrap").expect("a valid name"),
    }
}

async fn user(stack: &Stack, name: &str) -> Actor {
    let id = stack
        .service
        .create_user(
            &bootstrap(),
            &Username::new(name).expect("a name"),
            Password::new(PASSWORD),
            &Profile::default(),
        )
        .await
        .expect("makes a user");
    Actor::User {
        id,
        name: name.to_owned(),
    }
}

impl Stack {
    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.http.get(format!("{}{path}", self.url))
    }

    /// A form post from this site's own page, as a browser sends it.
    fn post(&self, path: &str, form: &[(&str, &str)]) -> reqwest::RequestBuilder {
        self.http
            .post(format!("{}{path}", self.url))
            .header("origin", &self.url)
            .form(form)
    }

    async fn log_in(&self, name: &str, password: &str) -> reqwest::Response {
        self.post("/login", &[("username", name), ("password", password)])
            .send()
            .await
            .expect("answered")
    }

    async fn audit_count(&self) -> i64 {
        sqlx_count(&self.test_db, "SELECT count(*) FROM service.audit").await
    }

    async fn session_count(&self) -> i64 {
        sqlx_count(&self.test_db, "SELECT count(*) FROM service.sessions").await
    }
}

async fn sqlx_count(test_db: &TestDb, query: &'static str) -> i64 {
    sqlx::query_scalar(query)
        .fetch_one(test_db.db().pool())
        .await
        .expect("counts")
}

/// The session token a response's `Set-Cookie` sets, or None for one that clears it or sets none.
fn session_set(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(SET_COOKIE)?.to_str().expect("text");
    let value = cookie.strip_prefix("ace4_session=")?.split(';').next()?;
    (!value.is_empty()).then(|| value.to_owned())
}

fn cookie(token: &str) -> String {
    format!("ace4_session={token}")
}

fn location(response: &reqwest::Response) -> &str {
    response.headers()[LOCATION].to_str().expect("text")
}

/// PLAN.md 5.7: the base layout for a visitor who isn't signed in and for a user who is, through the
/// view functions and through the server.
#[tokio::test]
async fn the_base_layout_renders_for_a_visitor_and_a_user() {
    // The view functions, directly.
    let visitor = LoginPage {
        layout: Layout::signed_out("n0nce"),
        next: None,
        failed: false,
    }
    .render()
    .expect("renders");
    assert!(visitor.starts_with("<!DOCTYPE html>"), "{visitor}");
    assert!(
        visitor.contains(r#"<html lang="en" data-theme="system" data-nonce="n0nce">"#),
        "{visitor}"
    );
    assert!(visitor.contains(r#"<form method="post" action="/login">"#));
    assert!(!visitor.contains("/logout"), "no account menu: {visitor}");
    assert!(!visitor.contains("/preferences/theme"));

    let signed_in = HomePage {
        layout: Layout::new("n0nce", Theme::Dark, Some("alice".to_owned()), "/"),
    }
    .render()
    .expect("renders");
    assert!(signed_in.contains(r#"data-theme="dark""#), "{signed_in}");
    assert!(signed_in.contains(r#"<span class="user" id="username">alice</span>"#));
    assert!(signed_in.contains(r#"<form method="post" action="/logout">"#));
    assert!(signed_in.contains(r#"<option value="dark" selected>Dark</option>"#));
    assert!(signed_in.contains(r#"<option value="halloween">Halloween</option>"#));
    assert!(signed_in.contains("Logged in as alice."));
    for page in [&visitor, &signed_in] {
        let datastar = asset_named(
            page.split("src=\"/static/")
                .nth(1)
                .and_then(|rest| rest.split('"').next())
                .expect("Datastar's script"),
        )
        .expect("an embedded asset");
        assert!(datastar.name.starts_with("datastar-1.0.4."));
        assert!(page.contains(&format!(
            r#"<script type="module" nonce="n0nce" src="{}"></script>"#,
            datastar.url()
        )));
    }

    // Through the server.
    let stack = stack().await;
    let home = stack.get("/").send().await.expect("answered");
    assert_eq!(home.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&home), "/login");
    let datastar = stack
        .get("/")
        .header("datastar-request", "true")
        .send()
        .await
        .expect("answered");
    assert_eq!(
        datastar.status(),
        StatusCode::UNAUTHORIZED,
        "Datastar isn't sent a login page to morph in"
    );
    let page = stack
        .get("/login")
        .send()
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(page.contains(r#"data-theme="system""#));
    assert!(!page.contains("/logout"));

    user(&stack, "alice").await;
    let response = stack.log_in("alice", PASSWORD).await;
    let token = session_set(response.headers()).expect("a session");
    let home = stack
        .get("/")
        .header("cookie", cookie(&token))
        .send()
        .await
        .expect("answered");
    assert_eq!(home.status(), StatusCode::OK);
    let page = home.text().await.expect("a page");
    assert!(
        page.contains(r#"<span class="user" id="username">alice</span>"#),
        "{page}"
    );
    assert!(page.contains(r#"<form method="post" action="/logout">"#));
    assert!(page.contains(r#"data-theme="system""#));

    // An API key opens no page: the GUI judges only the session cookie.
    let key = stack
        .service
        .create_api_key(&bootstrap(), "a key", None, &[])
        .await
        .expect("a key");
    let with_key = stack
        .get("/")
        .bearer_auth(key.token.expose())
        .send()
        .await
        .expect("answered");
    assert_eq!(with_key.status(), StatusCode::SEE_OTHER);
}

/// 5.4's login and logout through the GUI: a login sets a cookie for a new session, replacing the one
/// it came with; a failed one says the same thing for every cause and sets nothing; a logout clears the
/// cookie and ends the session.
#[tokio::test]
async fn logging_in_rotates_the_session_and_logging_out_ends_it() {
    let stack = stack().await;
    let alice = user(&stack, "alice").await;

    let response = stack.log_in("alice", PASSWORD).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&response), "/");
    let set = response.headers()[SET_COOKIE].to_str().expect("text");
    assert!(
        set.ends_with("; Max-Age=43200; Path=/; HttpOnly; SameSite=Lax"),
        "{set}"
    );
    let first = session_set(response.headers()).expect("a session");
    assert_eq!(
        stack
            .service
            .authenticate_session(&first)
            .await
            .expect("live"),
        alice
    );

    // A second login with the first cookie replaces it.
    let response = stack
        .post(
            "/login",
            &[
                ("username", "alice"),
                ("password", PASSWORD),
                ("next", "/x?y=1"),
            ],
        )
        .header("cookie", cookie(&first))
        .send()
        .await
        .expect("answered");
    assert_eq!(location(&response), "/x?y=1", "back where it was going");
    let second = session_set(response.headers()).expect("a session");
    assert_ne!(first, second);
    assert!(matches!(
        stack.service.authenticate_session(&first).await,
        Err(ServiceError::NotAuthenticated)
    ));
    stack
        .service
        .authenticate_session(&second)
        .await
        .expect("live");

    // Every failure is the same page and sets no cookie.
    let sessions = stack.session_count().await;
    for (name, password) in [
        ("alice", "the wrong password"),
        ("nobody", PASSWORD),
        ("not a valid name!", PASSWORD),
        ("alice", ""),
    ] {
        let response = stack.log_in(name, password).await;
        assert_eq!(response.status(), StatusCode::OK, "{name}");
        assert!(response.headers().get(SET_COOKIE).is_none(), "{name}");
        let page = response.text().await.expect("a page");
        assert!(
            page.contains("Invalid username or password."),
            "{name}: {page}"
        );
        assert!(!page.contains(password) || password.is_empty(), "{name}");
    }
    let incomplete = stack
        .post("/login", &[("username", "alice")])
        .send()
        .await
        .expect("answered");
    assert_eq!(incomplete.status(), StatusCode::BAD_REQUEST);
    assert_eq!(stack.session_count().await, sessions);

    // A logout ends the session and clears the cookie, and a second one only clears it again.
    let audits = stack.audit_count().await;
    let response = stack
        .post("/logout", &[])
        .header("cookie", cookie(&second))
        .send()
        .await
        .expect("answered");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&response), "/login");
    assert_eq!(
        response.headers()[SET_COOKIE],
        "ace4_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"
    );
    assert!(matches!(
        stack.service.authenticate_session(&second).await,
        Err(ServiceError::NotAuthenticated)
    ));
    assert_eq!(stack.audit_count().await, audits + 1, "the logout's row");
    let again = stack
        .post("/logout", &[])
        .header("cookie", cookie(&second))
        .send()
        .await
        .expect("answered");
    assert_eq!(again.status(), StatusCode::SEE_OTHER);
    assert_eq!(stack.audit_count().await, audits + 1);
    let home = stack
        .get("/")
        .header("cookie", cookie(&second))
        .send()
        .await
        .expect("answered");
    assert_eq!(home.status(), StatusCode::SEE_OTHER, "signed out");
}

/// The cookie follows the site's transport: under TLS it's `Secure` with the `__Host-` name.
#[tokio::test]
async fn under_tls_the_cookie_is_secure() {
    let stack = stack().await;
    user(&stack, "alice").await;
    let router = Gui::new(stack.service.clone(), Transport::Tls).router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds");
    let url = format!("http://{}", listener.local_addr().expect("an address"));
    let task = tokio::spawn(async move {
        let _served = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    let response = stack
        .http
        .post(format!("{url}/login"))
        .header("origin", &url)
        .form(&[("username", "alice"), ("password", PASSWORD)])
        .send()
        .await
        .expect("answered");
    task.abort();
    let set = response.headers()[SET_COOKIE].to_str().expect("text");
    assert!(set.starts_with("__Host-ace4_session=ace4s_"), "{set}");
    assert!(
        set.ends_with("; Path=/; HttpOnly; SameSite=Lax; Secure"),
        "{set}"
    );
}

/// CSRF: a login or a logout another site's page posts is refused before it does anything, and so is a
/// post that says nothing of where it came from. The answer is the same for a same-origin post by
/// `Sec-Fetch-Site` or by `Origin`.
#[tokio::test]
async fn a_login_or_logout_from_another_site_is_refused() {
    let stack = stack().await;
    user(&stack, "alice").await;
    let form = [("username", "alice"), ("password", PASSWORD)];
    let post = |path: &str| stack.http.post(format!("{}{path}", stack.url)).form(&form);
    let sessions = stack.session_count().await;
    for (what, request) in [
        (
            "another origin",
            post("/login").header("origin", "https://evil.example"),
        ),
        (
            "another port",
            post("/login").header("origin", "http://127.0.0.1:1"),
        ),
        (
            "cross-site",
            post("/login").header("sec-fetch-site", "cross-site"),
        ),
        (
            "same-site",
            post("/login").header("sec-fetch-site", "same-site"),
        ),
        ("neither header", post("/login")),
        ("a null origin", post("/login").header("origin", "null")),
    ] {
        let response = request.send().await.expect("answered");
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{what}");
        assert!(response.headers().get(SET_COOKIE).is_none(), "{what}");
        let page = response.text().await.expect("a page");
        assert!(page.contains("This form came from another site."), "{what}");
    }
    assert_eq!(stack.session_count().await, sessions, "no login happened");

    for (what, request) in [
        (
            "by Sec-Fetch-Site",
            post("/login").header("sec-fetch-site", "same-origin"),
        ),
        ("by Origin", post("/login").header("origin", &stack.url)),
    ] {
        let response = request.send().await.expect("answered");
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{what}");
    }

    let token = session_set(stack.log_in("alice", PASSWORD).await.headers()).expect("a session");
    let refused = stack
        .http
        .post(format!("{}/logout", stack.url))
        .header("cookie", cookie(&token))
        .header("origin", "https://evil.example")
        .send()
        .await
        .expect("answered");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert!(refused.headers().get(SET_COOKIE).is_none());
    stack
        .service
        .authenticate_session(&token)
        .await
        .expect("still live");
    let refused = stack
        .http
        .post(format!("{}/preferences/theme", stack.url))
        .header("cookie", cookie(&token))
        .header("sec-fetch-site", "cross-site")
        .form(&[("mode", "dark")])
        .send()
        .await
        .expect("answered");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let page = refused.text().await.expect("a page");
    assert!(
        page.contains("this request came from another site"),
        "{page}"
    );
}

/// `next` is a path on this site, or the login goes home.
#[tokio::test]
async fn a_login_goes_on_only_to_a_path_on_this_site() {
    let stack = stack().await;
    user(&stack, "alice").await;
    for (next, to) in [
        ("/alerts?page=2", "/alerts?page=2"),
        ("//evil.example/", "/"),
        ("/\\evil.example", "/"),
        ("https://evil.example/", "/"),
        ("javascript:alert(1)", "/"),
        ("evil", "/"),
        ("/a\tb", "/"),
        ("/é", "/"),
    ] {
        let response = stack
            .post(
                "/login",
                &[
                    ("username", "alice"),
                    ("password", PASSWORD),
                    ("next", next),
                ],
            )
            .send()
            .await
            .expect("answered");
        assert_eq!(location(&response), to, "{next}");
    }
    let page = stack
        .get("/login?next=//evil.example/")
        .send()
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(!page.contains("name=\"next\""), "{page}");
    let response = stack.get("/?a=1").send().await.expect("answered");
    assert_eq!(location(&response), "/login?next=%2F%3Fa%3D1");
}

/// Every GUI response has the security headers, and a page's CSP nonce is its own, the one Datastar's
/// script and `<html data-nonce>` carry.
#[tokio::test]
async fn every_response_has_the_security_headers() {
    let stack = stack().await;
    let datastar = asset_named(&datastar_name()).expect("an asset");
    let mut nonces = BTreeSet::new();
    for (path, status) in [
        ("/login", StatusCode::OK),
        ("/", StatusCode::SEE_OTHER),
        (datastar.url().as_str(), StatusCode::OK),
        ("/static/nothing.js", StatusCode::NOT_FOUND),
    ] {
        let response = stack.get(path).send().await.expect("answered");
        assert_eq!(response.status(), status, "{path}");
        let headers = response.headers().clone();
        let header = |name: &str| headers[name].to_str().expect("text").to_owned();
        assert_eq!(header("x-content-type-options"), "nosniff", "{path}");
        assert_eq!(header("x-frame-options"), "DENY", "{path}");
        assert_eq!(header("referrer-policy"), "same-origin", "{path}");
        assert_eq!(
            header("cross-origin-opener-policy"),
            "same-origin",
            "{path}"
        );
        let policy = header("content-security-policy");
        let nonce = policy
            .split("'nonce-")
            .nth(1)
            .and_then(|rest| rest.split('\'').next())
            .expect("a nonce")
            .to_owned();
        assert_eq!(nonce.len(), 32, "128 bits: {nonce}");
        assert_eq!(policy, ace_gui::content_security_policy(&nonce));
        assert!(!policy.contains("unsafe"), "{policy}");
        for part in [
            "default-src 'none'",
            "frame-ancestors 'none'",
            "form-action 'self'",
            "base-uri 'none'",
        ] {
            assert!(policy.contains(part), "{policy}");
        }
        if path == "/login" {
            assert_eq!(header("cache-control"), "no-store");
            let page = response.text().await.expect("a page");
            assert!(page.contains(&format!(r#"data-nonce="{nonce}""#)), "{page}");
            assert!(page.contains(&format!(r#"<script type="module" nonce="{nonce}" src="#)));
        }
        nonces.insert(nonce);
    }
    assert_eq!(nonces.len(), 4, "a new nonce each time");
}

fn datastar_name() -> String {
    let page = LoginPage {
        layout: Layout::signed_out("x"),
        next: None,
        failed: false,
    }
    .render()
    .expect("renders");
    page.split("src=\"/static/")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("Datastar's script")
        .to_owned()
}

/// Datastar and the stylesheet come from the binary, under a hash of their bytes, cached for a year.
/// Datastar's bytes are the release `vendor/README.md` records, by its hash.
#[tokio::test]
async fn assets_are_embedded_hashed_and_cached() {
    let readme = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vendor/README.md"),
    )
    .expect("reads the README");
    let section = readme
        .split("## datastar")
        .nth(1)
        .expect("Datastar's section");
    let recorded = section
        .split('`')
        .find(|part| part.len() == 64 && part.bytes().all(|b| b.is_ascii_hexdigit()))
        .expect("a SHA-256");
    assert_eq!(
        recorded, "727844adfc825ee651fb93c544a2a739986f9a21820a94524b35f0cac470cf91",
        "the hash ace3's docs/GUI_DATASTAR.md records for its copy"
    );

    let stack = stack().await;
    let page = stack
        .get("/login")
        .send()
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    for (link, content_type) in [
        (
            "<link rel=\"stylesheet\" href=\"",
            "text/css; charset=utf-8",
        ),
        ("src=\"", "text/javascript; charset=utf-8"),
    ] {
        let url = page
            .split(link)
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("a link");
        let name = url.strip_prefix("/static/").expect("a static path");
        let asset = asset_named(name).expect("embedded");
        let response = stack.get(url).send().await.expect("answered");
        assert_eq!(response.status(), StatusCode::OK, "{url}");
        assert_eq!(response.headers()["content-type"], content_type);
        assert_eq!(
            response.headers()["cache-control"],
            "public, max-age=31536000, immutable"
        );
        let bytes = response.bytes().await.expect("bytes");
        assert_eq!(bytes, asset.bytes);
        let hash = hex::encode(Sha256::digest(&bytes));
        assert!(name.contains(&format!(".{}.", &hash[..16])), "{name}");
        if name.starts_with("datastar-") {
            assert_eq!(
                hash, recorded,
                "Datastar is the release vendor/README.md records"
            );
            assert!(bytes.starts_with(b"// Datastar v1.0.4\n"));
        }
        // An old hash, or none, isn't served.
        for stale in [
            name.replace(&hash[..16], "0000000000000000"),
            name.replace(&format!(".{}", &hash[..16]), ""),
        ] {
            let response = stack
                .get(&format!("/static/{stale}"))
                .send()
                .await
                .expect("answered");
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{stale}");
        }
    }
}

const HOSTILE: &str = r#""><script>alert('x')</script><img src=x onerror=alert(1)>&amp;"#;

/// Text a page shows is text: askama's escaper writes each of `&<>"'` as an entity, in an element and in
/// an attribute, so none of it can open a tag, close an attribute or add one.
#[tokio::test]
async fn hostile_text_is_escaped() {
    let escaped = "&#34;&#62;&#60;script&#62;alert(&#39;x&#39;)&#60;/script&#62;&#60;img src=x \
                   onerror=alert(1)&#62;&#38;amp;";
    let page = ErrorPage {
        layout: Layout::new(HOSTILE, Theme::Halloween, Some(HOSTILE.to_owned()), HOSTILE),
        status: 400,
        message: HOSTILE.to_owned(),
    }
    .render()
    .expect("renders");
    assert!(!page.contains("<script>alert"), "{page}");
    assert!(!page.contains("<img"), "{page}");
    assert!(!page.contains("onerror=alert(1)>"), "{page}");
    assert_eq!(page.matches(escaped).count(), 5, "{page}");
    assert!(page.contains(&format!("<p>{escaped}</p>")));
    assert!(page.contains(&format!(r#"data-nonce="{escaped}""#)));
    assert!(page.contains(&format!(
        r#"<input type="hidden" name="next" value="{escaped}">"#
    )));
    assert!(page.contains(&format!(r#"id="username">{escaped}</span>"#)));

    // Through the server, `next` is the outside value a page shows. A path has no spaces.
    let stack = stack().await;
    let next = r#"/"><script>alert('x')</script>"#;
    let escaped = "/&#34;&#62;&#60;script&#62;alert(&#39;x&#39;)&#60;/script&#62;";
    let encoded = next_query(next);
    let page = stack
        .get(&format!("/login?{encoded}"))
        .send()
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(
        page.contains(&format!(r#"name="next" value="{escaped}">"#)),
        "{page}"
    );
    assert!(!page.contains("<script>alert"), "{page}");
}

fn next_query(next: &str) -> String {
    reqwest::Url::parse_with_params("http://x/", [("next", next)])
        .expect("a URL")
        .query()
        .expect("a query")
        .to_owned()
}

/// askama escapes for HTML by a template's extension, so every template is `.html`, none turns escaping
/// off, and no `askama.toml` changes the escapers. A page that ever needs raw HTML has to change this
/// test, which is where that's decided.
#[test]
fn every_template_escapes_html() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(!root.join("askama.toml").exists());
    assert!(!root.join("../../askama.toml").exists());
    let mut templates = Vec::new();
    for entry in std::fs::read_dir(root.join("templates")).expect("reads the templates") {
        let path = entry.expect("an entry").path();
        assert_eq!(
            path.extension().and_then(|e| e.to_str()),
            Some("html"),
            "{}",
            path.display()
        );
        let text = std::fs::read_to_string(&path).expect("reads a template");
        for off in ["|safe", "| safe", "escape", "autoescape"] {
            assert!(!text.contains(off), "{} has {off}", path.display());
        }
        templates.push(path);
    }
    assert!(templates.len() >= 4);
    let source = std::fs::read_to_string(root.join("src/templates.rs")).expect("reads the source");
    let code: String = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect();
    assert!(!code.contains("escape"), "no template sets its escaper");
    assert!(
        !code.contains("ext ="),
        "no template picks another extension"
    );
}

/// A user's theme draws their pages, and the base layout's menu sets it through the service, coming back
/// to the page it was on.
#[tokio::test]
async fn the_theme_menu_sets_the_user_s_theme() {
    let stack = stack().await;
    let alice = user(&stack, "alice").await;
    let token = session_set(stack.log_in("alice", PASSWORD).await.headers()).expect("a session");
    let audits = stack.audit_count().await;
    let response = stack
        .post(
            "/preferences/theme",
            &[("mode", "halloween"), ("next", "/login")],
        )
        .header("cookie", cookie(&token))
        .send()
        .await
        .expect("answered");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&response), "/login");
    assert_eq!(stack.audit_count().await, audits + 1, "a set has a row");
    assert_eq!(
        stack.service.theme(&alice).await.expect("reads"),
        Theme::Halloween
    );
    let page = stack
        .get("/")
        .header("cookie", cookie(&token))
        .send()
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(page.contains(r#"data-theme="halloween""#), "{page}");
    assert!(page.contains(r#"<option value="halloween" selected>Halloween</option>"#));
    // The menu comes back to the page it's on.
    assert!(page.contains(r#"<input type="hidden" name="next" value="/">"#));

    let refused = stack
        .post("/preferences/theme", &[("mode", "neon")])
        .header("cookie", cookie(&token))
        .send()
        .await
        .expect("answered");
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    let signed_out = stack
        .post("/preferences/theme", &[("mode", "dark")])
        .send()
        .await
        .expect("answered");
    assert_eq!(signed_out.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&signed_out), "/login");
    assert_eq!(
        stack.service.theme(&alice).await.expect("reads"),
        Theme::Halloween
    );
    // A visitor's page is in the default theme.
    let page = stack
        .get("/login")
        .send()
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(page.contains(r#"data-theme="system""#));
}

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("a lock").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl tracing_subscriber::fmt::MakeWriter<'_> for Captured {
    type Writer = Captured;

    fn make_writer(&self) -> Captured {
        self.clone()
    }
}

/// 5.4's `no_credential_reaches_the_log`, through the routes: everything at TRACE, sqlx's statements and
/// axum's included, while logins fail and succeed, a session is used and a logout ends it, with no
/// password and no session secret in it. The subscriber is global for the reason 5.4's test gives, so
/// this binary has no other test that sets one.
#[tokio::test]
async fn no_credential_reaches_the_log_through_the_routes() {
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(captured.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("the only global subscriber here");

    let stack = stack().await;
    user(&stack, "alice").await;
    let wrong = "a-wrong-password-for-alice";
    let in_the_wrong_box = "my-password-in-the-username-box";
    stack.log_in("alice", wrong).await;
    stack.log_in(in_the_wrong_box, wrong).await;
    let first = session_set(stack.log_in("alice", PASSWORD).await.headers()).expect("a session");
    let second = session_set(
        stack
            .post("/login", &[("username", "alice"), ("password", PASSWORD)])
            .header("cookie", cookie(&first))
            .send()
            .await
            .expect("answered")
            .headers(),
    )
    .expect("a session");
    stack
        .get("/")
        .header("cookie", cookie(&second))
        .send()
        .await
        .expect("answered");
    stack
        .post("/preferences/theme", &[("mode", "dark")])
        .header("cookie", cookie(&second))
        .send()
        .await
        .expect("answered");
    stack
        .post("/logout", &[])
        .header("cookie", cookie(&second))
        .send()
        .await
        .expect("answered");
    stack
        .http
        .post(format!("{}/login", stack.url))
        .header("origin", "https://evil.example")
        .form(&[("username", "alice"), ("password", PASSWORD)])
        .send()
        .await
        .expect("answered");

    let log = String::from_utf8(captured.0.lock().expect("a lock").clone()).expect("text");
    // It really was listening.
    for heard in [
        "a GUI login failed",
        "a GUI login",
        "a cross-site login was refused",
        "AUDIT",
        "service.sessions",
        "127.0.0.1",
    ] {
        assert!(log.contains(heard), "{heard}: {log}");
    }
    let secret = |token: &str| token.rsplit('_').next().expect("a secret").to_owned();
    for credential in [
        PASSWORD.to_owned(),
        "correct+horse".to_owned(),
        wrong.to_owned(),
        in_the_wrong_box.to_owned(),
        secret(&first),
        secret(&second),
    ] {
        assert!(!log.contains(&credential), "{credential} is in the log");
    }
}

// ---- PLAN.md 5.8: the alert view ----

fn summary(id: uuid::Uuid, title: &str) -> AlertSummary {
    let at = chrono::DateTime::from_timestamp(1_793_000_000, 0).expect("a time");
    AlertSummary {
        id,
        title: title.to_owned(),
        analysis_mode: "correlation".to_owned(),
        event_time: Some(at),
        event_time_source: "event".to_owned(),
        created_at: at,
        alerted_at: at,
        disposition: None,
        dispositioned_at: None,
        dispositioned_by: None,
        submitted_by: Some(RecordedActor {
            kind: "api_key".to_owned(),
            id: "k".to_owned(),
            name: Some("<the submitter>".to_owned()),
        }),
        analysis: AnalysisState::Running,
    }
}

fn observable(id: i64, kind: &str, value: &str) -> AlertObservable {
    AlertObservable {
        id,
        kind: kind.to_owned(),
        value: value.to_owned(),
        time: None,
        tags: Vec::new(),
        directives: Vec::new(),
        exclude_modules: Vec::new(),
        redirection: None,
        display_type: None,
        files: Vec::new(),
        relationships: Vec::new(),
        results: Vec::new(),
        detections: Vec::new(),
    }
}

fn module_result(id: i64, module: &str, summary: Option<&str>) -> ModuleResult {
    ModuleResult {
        id,
        module: module.to_owned(),
        analysis_type: format!("{module}_analysis"),
        schema_version: 1,
        summary: summary.map(str::to_owned),
        tags: Vec::new(),
        details: serde_json::json!({}),
        created_at: chrono::DateTime::from_timestamp(1_793_000_000, 0).expect("a time"),
    }
}

/// A tree with a loop and a repeat in it, and hostile text everywhere a module can put text.
fn fixture_tree() -> (AlertTree, Vec<ObservableComment>) {
    let id = uuid::Uuid::from_u128(0x5800);
    let mut email = observable(
        1,
        "file",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    email.files.push(AlertFile {
        path: "email.rfc822".to_owned(),
        yara_meta: Vec::new(),
    });
    let mut parsed = module_result(10, "email_analyzer", Some("Email <b>Analysis</b>"));
    parsed.tags = vec!["x\"onmouseover=\"y".to_owned()];
    email.results.push(parsed);
    let mut sender = observable(2, "email_from", "a@example.com");
    sender.tags = vec!["<script>alert(1)</script>".to_owned()];
    sender.detections.push(AlertDetection {
        description: "a known <bad> sender".to_owned(),
        details: None,
        module: Some("email_analyzer".to_owned()),
    });
    let mut ip = observable(3, "ip", "192.0.2.10");
    ip.display_type = Some("Source IP".to_owned());
    ip.results.push(module_result(11, "rdap_analyzer", None));
    let fqdn = observable(4, "fqdn", "evil.example.com'><img src=x>");
    let tree = AlertTree {
        alert: Alert {
            summary: summary(id, "<i>Phish</i>"),
            observables: 4,
            files: 1,
            detections: 1,
        },
        observables: vec![email, sender, ip, fqdn],
        top: vec![1],
        additions: [
            (10, 2),
            (10, 3),
            // the email's own result names it again, so the walk meets it twice
            (10, 1),
            (11, 4),
            (11, 2),
        ]
        .into_iter()
        .map(|(result, observable)| Addition { result, observable })
        .collect(),
        truncated: false,
    };
    let comments = vec![ObservableComment {
        id: 1,
        kind: "ip".to_owned(),
        value: "192.0.2.10".to_owned(),
        author: CommentAuthor {
            id: ace_service::UserId(uuid::Uuid::from_u128(1)),
            username: "alice".to_owned(),
            display_name: Some("Alice <A>".to_owned()),
        },
        created_by: RecordedActor {
            kind: "user".to_owned(),
            id: "1".to_owned(),
            name: Some("alice".to_owned()),
        },
        comment: "seen </li><li>before".to_owned(),
        created_at: chrono::DateTime::from_timestamp(1_793_000_000, 0).expect("a time"),
        edited_at: None,
    }];
    (tree, comments)
}

/// PLAN.md 5.8's Done check, its first part: the view function, called directly, draws a fixture tree as
/// ace3's walk does, with each module's text escaped and a display type in place of the type's name.
#[test]
fn the_view_function_draws_a_fixture_tree() {
    let (tree, comments) = fixture_tree();
    let view = tree_view(&tree, &comments);
    let html = AlertTreeFragment { tree: view.clone() }
        .render()
        .expect("renders");
    let compact: String = html.lines().map(str::trim).collect();
    // the shape: the email at the top, its result, what that added, a jump back to the email, and the
    // IP's result with the fqdn and a reference to the sender, which has no analysis to jump to
    let order = [
        r#"<div id="alert-tree" class="tree">"#,
        r#"<li class="observable" id="o1"><b class="type">file</b> : <span class="value">email.rfc822</span>"#,
        r#"<li class="result" id="r10" data-module="email_analyzer"><span class="summary" title="email_analyzer">Email &#60;b&#62;Analysis&#60;/b&#62;</span> <span class="tag">x&#34;onmouseover=&#34;y</span>"#,
        r#"<li class="observable" id="o2"><b class="type">Mail From (email_from)</b> : <span class="value">a@example.com</span> <span class="detection" title="a known &#60;bad&#62; sender">detection: a known &#60;bad&#62; sender</span> <span class="tag">&#60;script&#62;alert(1)&#60;/script&#62;</span></li>"#,
        r#"<li class="observable" id="o3"><b class="type">Source IP (ip)</b> : <span class="value">192.0.2.10</span>"#,
        r#"<li class="comment"><span class="author">Alice &#60;A&#62;</span> <span class="time">2026-10-26 07:33:20 UTC</span>: seen &#60;/li&#62;&#60;li&#62;before</li>"#,
        r#"<li class="result" id="r11" data-module="rdap_analyzer"><span class="summary" title="rdap_analyzer">rdap_analyzer</span>"#,
        r#"<li class="observable" id="o4"><b class="type">fqdn</b> : <span class="value">evil.example.com&#39;&#62;&#60;img src=x&#62;</span></li>"#,
        r#"<li class="observable"><b class="type">Mail From (email_from)</b> : <span class="value">a@example.com</span>"#,
        r##"<li class="observable"><b class="type">file</b> : <span class="value">email.rfc822</span><ul><li class="jump"><a href="#o1">Jump To Analysis</a></li></ul></li>"##,
    ];
    let mut at = 0;
    for part in order {
        let found = compact[at..]
            .find(part)
            .unwrap_or_else(|| panic!("{part}\nisn't after byte {at} of\n{compact}"));
        at += found + part.len();
    }
    assert_eq!(
        compact.matches(r#"id="o1""#).count(),
        1,
        "one place in full"
    );
    assert_eq!(
        compact.matches("<li").count(),
        compact.matches("</li>").count()
    );
    assert_eq!(
        compact.matches("<ul").count(),
        compact.matches("</ul>").count()
    );
    for raw in [
        "<b>Analysis",
        "<script>",
        "<img",
        "<bad>",
        "</li><li>before",
        "<A>",
    ] {
        assert!(!html.contains(raw), "{raw} unescaped in {html}");
    }

    // The page around it, with its details, its section and the stream it starts.
    let open = AlertPage::new(
        Layout::new("n0nce", Theme::Light, Some("alice".to_owned()), "/alerts/x"),
        &tree,
        &comments,
        &std::collections::BTreeMap::new(),
    )
    .expect("a page");
    let version = open.version.clone();
    assert_eq!(version.len(), 16);
    assert_eq!(
        AlertTreeFragment { tree: view }
            .render_versioned()
            .expect("renders")
            .1,
        version,
        "the page's version is its tree's"
    );
    let page = open.render().expect("renders");
    assert!(page.contains(&format!(
        r#"<section class="alert" data-init="@get('/alerts/{}/live?v={version}')">"#,
        tree.alert.summary.id
    )));
    assert!(
        page.contains("<h1>&#60;i&#62;Phish&#60;/i&#62;</h1>"),
        "{page}"
    );
    assert!(page.contains(r#"<details class="section" data-section-id="alert_details" open>"#));
    assert!(page.contains("<th>Submitted by</th><td>&#60;the submitter&#62;</td>"));
    assert!(page.contains(r#"<div id="alert-tree" class="tree">"#));
    assert!(
        !page.contains("style="),
        "no inline style, which the policy refuses"
    );
    assert!(!page.contains("<script>"), "no inline script");
    let closed = AlertPage::new(
        Layout::new("n0nce", Theme::Light, Some("alice".to_owned()), "/alerts/x"),
        &tree,
        &comments,
        &[("alert_details".to_owned(), false)].into_iter().collect(),
    )
    .expect("a page")
    .render()
    .expect("renders");
    assert!(closed.contains(r#"<details class="section" data-section-id="alert_details">"#));
    assert!(closed.contains("Collapsed by default"));
}

fn grant_alert_read(stack: &Stack, actor: &Actor) -> impl std::future::Future<Output = ()> {
    let Actor::User { id, .. } = actor else {
        panic!("a user");
    };
    let (service, holder) = (stack.service.clone(), Holder::User(*id));
    async move {
        service
            .grant(
                &bootstrap(),
                &holder,
                &PermissionPattern::new("alert", "read").expect("a pattern"),
                Effect::Allow,
            )
            .await
            .expect("grants");
    }
}

/// What a module's result adds, landed as the orchestrator lands it.
async fn land(
    stack: &Stack,
    root: uuid::Uuid,
    on: ace_core::tree::ObservableId,
    module: &str,
    result: &ace_results::ResultEnvelope<serde_json::Value>,
) {
    let db = stack.test_db.db();
    let mut tx = db.begin().await.expect("begins");
    let id = ace_core::tree::insert_result(&mut tx, root, on, module, result)
        .await
        .expect("stores the result");
    for observable in &result.observables {
        let added = ace_core::tree::upsert_observable(&mut tx, root, observable)
            .await
            .expect("adds")
            .id;
        ace_core::tree::add_result_addition(&mut tx, root, id, added, None)
            .await
            .expect("records the addition");
    }
    tx.commit().await.expect("commits");
}

fn stub_result(
    analysis_type: &str,
    summary: &str,
) -> ace_results::ResultEnvelope<serde_json::Value> {
    serde_json::from_value(serde_json::json!({
        "analysis_type": analysis_type,
        "schema_version": 1,
        "details": {},
        "summary": summary,
    }))
    .expect("a result")
}

/// An alert on `www.example.com` holding what the Splunk module wrote for ace3's reference search
/// (`crates/ace-mod-splunk/tests/reference.rs` keeps the fixture its result), and its fqdn's row.
async fn splunk_alert(stack: &Stack) -> (uuid::Uuid, ace_core::tree::ObservableId) {
    let root = ace_core::tree::NewRoot {
        description: "Proxy <correlation>".to_owned(),
        ..ace_core::tree::NewRoot::new("correlation")
    };
    let db = stack.test_db.db();
    let mut tx = db.begin().await.expect("begins");
    ace_core::tree::create_root(&mut tx, &root)
        .await
        .expect("creates");
    let fqdn = ace_core::tree::upsert_observable(
        &mut tx,
        root.id,
        &ace_results::NewObservable::new(ace_results::ObservableKind::Fqdn, "www.example.com"),
    )
    .await
    .expect("adds")
    .id;
    tx.commit().await.expect("commits");
    sqlx::query("UPDATE analysis.roots SET alerted_at = now() WHERE id = $1")
        .bind(root.id)
        .execute(db.pool())
        .await
        .expect("an alert");
    let fixture: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/splunk_proxy_domain_lookup.json"),
        )
        .expect("the fixture reads"),
    )
    .expect("JSON");
    let result = serde_json::from_value(fixture).expect("a result envelope");
    land(stack, root.id, fqdn, "proxy_domain_lookup", &result).await;
    (root.id, fqdn)
}

async fn session_of(stack: &Stack, name: &str) -> String {
    let response = stack.log_in(name, PASSWORD).await;
    session_set(response.headers()).expect("a session")
}

/// PLAN.md 5.8: the page reads its tree from Postgres through the service, under `alert:read`, and the
/// Splunk module's IP observables read as ace3's do, `Source IP` and `Destination IP`, by the labels in
/// ace3's own reference dump of the same search.
#[tokio::test]
async fn the_alert_page_draws_the_tree_from_postgres_with_ace3_s_display_types() {
    let stack = stack().await;
    let alice = user(&stack, "alice").await;
    grant_alert_read(&stack, &alice).await;
    let _bob = user(&stack, "bob").await;
    let (root, _) = splunk_alert(&stack).await;
    let path = format!("/alerts/{root}");

    let alice_session = session_of(&stack, "alice").await;
    let response = stack
        .get(&path)
        .header("cookie", cookie(&alice_session))
        .send()
        .await
        .expect("answered");
    assert_eq!(response.status(), StatusCode::OK);
    let policy = response.headers()["content-security-policy"]
        .to_str()
        .expect("text")
        .to_owned();
    let page = response.text().await.expect("a page");
    assert!(policy.contains("script-src 'self' 'nonce-"), "{policy}");
    assert!(
        page.contains("<h1>Proxy &#60;correlation&#62;</h1>"),
        "{page}"
    );
    assert!(
        page.contains(r#"<b class="type">fqdn</b> : <span class="value">www.example.com</span>"#)
    );
    assert!(page.contains(r#"data-module="proxy_domain_lookup""#));
    assert!(page.contains("Proxy correlation: (3 results)"));

    // Every IP observable ace3's dump labels, labelled the same, and none of them without.
    let dump: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../tools/ace3/dumps/reference/proxy_domain_lookup/fqdn_www.example.com.json",
        ))
        .expect("ace3's dump reads"),
    )
    .expect("JSON");
    let mut labelled = 0;
    for observable in dump["analyses"][0]["observables"]
        .as_array()
        .expect("a list")
    {
        let (kind, value) = (
            observable["type"].as_str().expect("a type"),
            observable["value"].as_str().expect("a value"),
        );
        // ace3's Observable.display_type: "<label> (<type>)", or the type alone
        let label = match observable["display_type"].as_str() {
            Some(label) => {
                labelled += 1;
                format!("{label} ({kind})")
            }
            None => kind.to_owned(),
        };
        let drawn = format!(r#"<b class="type">{label}</b> : <span class="value">{value}</span>"#);
        assert!(page.contains(&drawn), "{drawn} isn't in {page}");
    }
    assert_eq!(labelled, 6, "the dump's six addresses");
    for label in ["Source IP (ip)", "Destination IP (ip)"] {
        assert!(page.contains(label));
    }

    // No alert:read, no such alert, not an id, and no session.
    let bob_session = session_of(&stack, "bob").await;
    let refused = stack
        .get(&path)
        .header("cookie", cookie(&bob_session))
        .send()
        .await
        .expect("answered");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert!(
        !refused
            .text()
            .await
            .expect("a page")
            .contains("www.example.com")
    );
    for missing in [
        format!("/alerts/{}", uuid::Uuid::nil()),
        "/alerts/x".to_owned(),
    ] {
        let response = stack
            .get(&missing)
            .header("cookie", cookie(&alice_session))
            .send()
            .await
            .expect("answered");
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{missing}");
    }
    let anonymous = stack.get(&path).send().await.expect("answered");
    assert_eq!(anonymous.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&anonymous),
        format!("/login?next=%2Falerts%2F{root}")
    );
}

/// Reads a stream's body until `done` says what it has so far is enough, or `within` passes. Returns
/// the text, and whether the stream ended.
async fn read_stream(
    response: &mut reqwest::Response,
    within: std::time::Duration,
    done: impl Fn(&str) -> bool,
) -> (String, bool) {
    let mut text = String::new();
    let deadline = tokio::time::Instant::now() + within;
    loop {
        if done(&text) {
            return (text, false);
        }
        match tokio::time::timeout_at(deadline, response.chunk()).await {
            Err(_) => return (text, false),
            Ok(Ok(Some(chunk))) => text.push_str(&String::from_utf8_lossy(&chunk)),
            Ok(Ok(None)) => return (text, true),
            Ok(Err(error)) => panic!("the stream failed: {error}"),
        }
    }
}

impl Stack {
    async fn open_stream(&self, path: &str, session: &str) -> reqwest::Response {
        self.get(path)
            .header("cookie", cookie(session))
            .header("datastar-request", "true")
            .send()
            .await
            .expect("answered")
    }

    async fn page_version(&self, root: uuid::Uuid, session: &str) -> String {
        let page = self
            .get(&format!("/alerts/{root}"))
            .header("cookie", cookie(session))
            .send()
            .await
            .expect("answered")
            .text()
            .await
            .expect("a page");
        page.split("/live?v=")
            .nth(1)
            .and_then(|rest| rest.split('\'').next())
            .expect("the stream's URL")
            .to_owned()
    }

    /// Waits until nothing watches and no stream is open.
    async fn wait_until_closed(&self) {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while self.service.watching() != (0, false) || self.gui.open_streams() != 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "still watching {:?} with {} streams open",
                self.service.watching(),
                self.gui.open_streams()
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
}

/// PLAN.md 5.8: when Postgres notifies of a new result, the open page's stream sends the tree with it as
/// a Datastar fragment; a stream that opens behind the page catches up; and when the client goes, its
/// watch, its place and the listener go too.
#[tokio::test]
async fn a_result_that_lands_is_pushed_to_an_open_stream() {
    let stack = stack_with(LiveLimits {
        heartbeat: std::time::Duration::from_secs(60),
        ..LiveLimits::default()
    })
    .await;
    let alice = user(&stack, "alice").await;
    grant_alert_read(&stack, &alice).await;
    let (root, fqdn) = splunk_alert(&stack).await;
    let session = session_of(&stack, "alice").await;
    let version = stack.page_version(root, &session).await;
    assert_eq!(
        stack.service.watching(),
        (0, false),
        "a page alone watches nothing"
    );

    let mut stream = stack
        .open_stream(&format!("/alerts/{root}/live?v={version}"), &session)
        .await;
    assert_eq!(stream.status(), StatusCode::OK);
    assert_eq!(
        stream.headers()["content-type"].to_str().expect("text"),
        "text/event-stream"
    );
    assert!(stream.headers().contains_key("content-security-policy"));
    // the page has this version, so there's nothing to send yet
    let (quiet, _) = read_stream(&mut stream, std::time::Duration::from_millis(600), |_| {
        false
    })
    .await;
    assert_eq!(quiet, "", "nothing changed");
    assert_eq!(stack.service.watching(), (1, true));
    assert_eq!(stack.gui.open_streams(), 1);

    land(
        &stack,
        root,
        fqdn,
        "rdap_analyzer",
        &stub_result("rdap_analysis", "RDAP <lookup>"),
    )
    .await;
    let (pushed, ended) = read_stream(&mut stream, std::time::Duration::from_secs(10), |text| {
        text.contains("\n\n")
    })
    .await;
    assert!(!ended);
    assert!(
        pushed.starts_with("event: datastar-patch-elements\n"),
        "{pushed}"
    );
    assert!(
        pushed.contains(r#"data: elements <div id="alert-tree" class="tree">"#),
        "{pushed}"
    );
    assert!(
        pushed.contains(r#"data-module="rdap_analyzer""#),
        "{pushed}"
    );
    assert!(
        pushed.contains("RDAP &#60;lookup&#62;"),
        "escaped: {pushed}"
    );
    assert!(pushed.contains("Source IP (ip)"));
    let pushed_version = pushed
        .lines()
        .find_map(|line| line.strip_prefix("id: "))
        .expect("an id")
        .to_owned();
    assert_ne!(pushed_version, version);
    assert_eq!(
        stack.page_version(root, &session).await,
        pushed_version,
        "a reload draws what the stream sent"
    );

    // A stream behind the page, as after a landing it missed, sends the tree at once; one that says it
    // has the current version by Last-Event-ID, as Datastar's reconnect does, sends nothing.
    let mut behind = stack
        .open_stream(&format!("/alerts/{root}/live?v={version}"), &session)
        .await;
    let (caught_up, _) = read_stream(&mut behind, std::time::Duration::from_secs(10), |text| {
        text.contains("\n\n")
    })
    .await;
    assert!(
        caught_up.contains(&format!("id: {pushed_version}\n")),
        "{caught_up}"
    );
    let mut current = stack
        .get(&format!("/alerts/{root}/live?v={version}"))
        .header("cookie", cookie(&session))
        .header("last-event-id", &pushed_version)
        .send()
        .await
        .expect("answered");
    let (nothing, _) = read_stream(&mut current, std::time::Duration::from_millis(600), |_| {
        false
    })
    .await;
    assert_eq!(nothing, "");
    assert_eq!(
        stack.service.watching(),
        (1, true),
        "three streams, one alert"
    );
    assert_eq!(stack.gui.open_streams(), 3);

    drop((stream, behind, current));
    stack.wait_until_closed().await;
}

/// The stream checks its session at each heartbeat, so a logout ends it; and it refuses a visitor, an
/// actor without `alert:read` and an alert that isn't one.
#[tokio::test]
async fn a_stream_ends_with_its_session_and_checks_its_reader() {
    let stack = stack_with(LiveLimits {
        heartbeat: std::time::Duration::from_millis(200),
        ..LiveLimits::default()
    })
    .await;
    let alice = user(&stack, "alice").await;
    grant_alert_read(&stack, &alice).await;
    let _bob = user(&stack, "bob").await;
    let (root, _) = splunk_alert(&stack).await;
    let session = session_of(&stack, "alice").await;
    let version = stack.page_version(root, &session).await;
    let live = format!("/alerts/{root}/live?v={version}");

    let mut stream = stack.open_stream(&live, &session).await;
    let (beats, ended) = read_stream(&mut stream, std::time::Duration::from_secs(5), |text| {
        text.matches(": heartbeat\n").count() >= 2
    })
    .await;
    assert!(!ended, "{beats}");
    let logout = stack
        .post("/logout", &[])
        .header("cookie", cookie(&session))
        .send()
        .await
        .expect("answered");
    assert_eq!(logout.status(), StatusCode::SEE_OTHER);
    let (_, ended) = read_stream(&mut stream, std::time::Duration::from_secs(5), |_| false).await;
    assert!(ended, "the stream ended with the session");
    stack.wait_until_closed().await;

    let anonymous = stack
        .get(&live)
        .header("datastar-request", "true")
        .send()
        .await
        .expect("answered");
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    let bob = session_of(&stack, "bob").await;
    assert_eq!(
        stack.open_stream(&live, &bob).await.status(),
        StatusCode::FORBIDDEN
    );
    let alice_again = session_of(&stack, "alice").await;
    for missing in [
        format!("/alerts/{}/live", uuid::Uuid::nil()),
        "/alerts/x/live".to_owned(),
    ] {
        assert_eq!(
            stack.open_stream(&missing, &alice_again).await.status(),
            StatusCode::NOT_FOUND,
            "{missing}"
        );
    }
    stack.wait_until_closed().await;
}

/// At most `per_user` streams for one user and `streams` in all; past either, 503, and a stream that
/// goes gives its place back.
#[tokio::test]
async fn streams_are_bounded_per_user_and_in_all() {
    let stack = stack_with(LiveLimits {
        streams: 2,
        per_user: 1,
        heartbeat: std::time::Duration::from_secs(60),
    })
    .await;
    let mut sessions = Vec::new();
    for name in ["alice", "bob", "carol"] {
        let actor = user(&stack, name).await;
        grant_alert_read(&stack, &actor).await;
        sessions.push(session_of(&stack, name).await);
    }
    let (root, _) = splunk_alert(&stack).await;
    let version = stack.page_version(root, &sessions[0]).await;
    let live = format!("/alerts/{root}/live?v={version}");

    let alice = stack.open_stream(&live, &sessions[0]).await;
    assert_eq!(alice.status(), StatusCode::OK);
    assert_eq!(
        stack.open_stream(&live, &sessions[0]).await.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "one each"
    );
    let bob = stack.open_stream(&live, &sessions[1]).await;
    assert_eq!(bob.status(), StatusCode::OK);
    assert_eq!(
        stack.open_stream(&live, &sessions[2]).await.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "two in all"
    );
    drop(alice);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let carol = loop {
        let carol = stack.open_stream(&live, &sessions[2]).await;
        if carol.status() == StatusCode::OK {
            break carol;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "alice's place never came back"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    drop((bob, carol));
    stack.wait_until_closed().await;
}

/// The section pin sets the viewer's `alert_sections` through the service, with an audit row, and the
/// page starts the section that way.
#[tokio::test]
async fn a_section_pin_sets_how_it_starts() {
    let stack = stack().await;
    let alice = user(&stack, "alice").await;
    grant_alert_read(&stack, &alice).await;
    let (root, _) = splunk_alert(&stack).await;
    let session = session_of(&stack, "alice").await;
    let path = format!("/alerts/{root}");
    let page = |stack: &Stack| {
        let request = stack.get(&path).header("cookie", cookie(&session));
        async move {
            request
                .send()
                .await
                .expect("answered")
                .text()
                .await
                .expect("a page")
        }
    };
    assert!(
        page(&stack)
            .await
            .contains(r#"data-section-id="alert_details" open>"#)
    );

    let audits = stack.audit_count().await;
    let pin = stack
        .post(
            "/preferences/alert-section",
            &[
                ("section", "alert_details"),
                ("open", "false"),
                ("next", &path),
            ],
        )
        .header("cookie", cookie(&session))
        .send()
        .await
        .expect("answered");
    assert_eq!(pin.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&pin), path);
    assert_eq!(stack.audit_count().await, audits + 1);
    assert!(
        page(&stack)
            .await
            .contains(r#"data-section-id="alert_details">"#)
    );
    assert_eq!(
        stack.service.alert_sections(&alice).await.expect("reads"),
        [("alert_details".to_owned(), false)].into_iter().collect()
    );

    for form in [
        [("section", "Alert Details"), ("open", "true")],
        [("section", "alert_details"), ("open", "yes")],
    ] {
        let refused = stack
            .post("/preferences/alert-section", &form)
            .header("cookie", cookie(&session))
            .send()
            .await
            .expect("answered");
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "{form:?}");
    }
    let cross_site = stack
        .http
        .post(format!("{}/preferences/alert-section", stack.url))
        .header("cookie", cookie(&session))
        .header("origin", "http://evil.example")
        .form(&[("section", "alert_details"), ("open", "true")])
        .send()
        .await
        .expect("answered");
    assert_eq!(cross_site.status(), StatusCode::FORBIDDEN);
    assert_eq!(stack.audit_count().await, audits + 1);
}
