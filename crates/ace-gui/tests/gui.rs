//! PLAN.md 5.7: the base layout for a visitor and for a signed-in user, login and logout over 5.4's
//! service with the CSRF check, the security headers, the embedded assets, escaping, and the theme. The
//! Done check, that a template using a missing field fails the build, is `templates`' doctests.
//!
//! PLAN.md 5.8: the alert view, drawn by its view function from a fixture tree and through the service
//! from Postgres, with the Splunk module's result showing ace3's display types; the live stream that
//! pushes a result as it lands, ends with the session, is bounded, and leaves nothing when its client
//! goes; and the section pins. The browser's half of the Done check is `tests/e2e/run`'s.
//!
//! PLAN.md 5.9: each ported module's analysis view draws the module's own result, escaped and bounded,
//! a type with no view draws as JSON, and a result's page draws its view under `alert:read`.
//!
//! PLAN.md 5.11's preferences area: the page's views directly, and its profile and own API keys through
//! the server, each write with its audit row and each refusal changing nothing.
//!
//! PLAN.md 5.11's saved_filters area: the manage page and the rename page drawn directly, and the moves and
//! renames through the server, each write with its audit row and each refusal changing nothing.
//!
//! PLAN.md 5.11's admin area: the hub, Users & Roles, a user's and a group's pages, the grant confirm, a
//! key's edit and the page showing a secret once, drawn directly, and through the server under
//! `admin:read` and each page's own permission, each write with its audit row, each refusal changing
//! nothing, and the self-harm the service refuses shown.
//!
//! PLAN.md 5.11's signatures area: the hub, the YARA QA list, a rule's page, a match's page, the purge's
//! confirm and its answer, drawn directly with a rule's and a file's hostile text, and through the server
//! under `signature:read`, `signature:download` and `signature:qa_purge`, the purge from this site only
//! with its audit row, and each refusal changing nothing.
//!
//! PLAN.md 5.11's events area (6b): the add-to-event page, with the ticked alerts and as Create Event, and
//! its answer, drawn directly with an event's hostile text, and through the server under `event:read` and
//! `event:write`, each add one audited write, gone alerts said, and each refusal changing nothing.
//!
//! PLAN.md 5.11's events area (6c): the event list, an event's page and the Close Event confirm, drawn
//! directly with an event's hostile text, and through the server under `event:read` and `event:write`:
//! the list's filters, sorts and pages by its URL, the export sent on to the API's, and Close Event from
//! this site only with its audit row, each refusal changing nothing.
//!
//! PLAN.md 5.12: Administration's CLI, the console and a run's page and fragment, drawn directly with a
//! run's hostile command and output, and through the server under `admin:read` and `cli:execute`: a start
//! and a cancel from this site only, each with its audit row, the fragment's poll that stops once a run
//! has ended, and each refusal changing nothing. The command's own run is ace-pool's `hung_tasks` test.

use std::collections::BTreeSet;
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use ace_core::eligibility::Catalog;
use ace_core::modes::Modes;
use ace_core::orchestrator::Orchestrator;
use ace_core::testing::TestDb;
use ace_gui::alert::{AlertPage, AlertTreeFragment, GraphPage, tree_view};
use ace_gui::list::{ListPage, ListQuery, list_view};
use ace_gui::templates::{ChangePasswordPage, ErrorPage, Layout, LoginPage};
use ace_gui::{Gui, LiveLimits, ObservableActions, Views, asset_named};
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
    stack_from(|service| Gui::with_limits(service, Transport::Plain, limits)).await
}

async fn stack_from(build: impl FnOnce(Service) -> Gui) -> Stack {
    let test_db = TestDb::new().await;
    let orchestrator = Orchestrator::new(Catalog::new(vec![]), Modes::ace3());
    let service = Service::new(test_db.db().clone(), orchestrator);
    let gui = build(service.clone());
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
        password_changed: false,
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

    let view = list_view(
        &ace_service::AlertPage {
            alerts: Vec::new(),
            next: None,
            total: 0,
        },
        &ListQuery::default(),
        &ace_service::ManageColumnsPreference::default(),
        &[],
        &std::collections::HashMap::new(),
        chrono_tz::Tz::UTC,
        Vec::new(),
        None,
    );
    let signed_in = ListPage {
        layout: Layout::new("n0nce", Theme::Dark, Some("alice".to_owned()), "/"),
        list: view.list.clone(),
        view,
    }
    .render()
    .expect("renders");
    assert!(signed_in.contains(r#"data-theme="dark""#), "{signed_in}");
    assert!(signed_in.contains(r#"<span class="user" id="username">alice</span>"#));
    assert!(signed_in.contains(r#"<form method="post" action="/logout">"#));
    assert!(signed_in.contains(r#"<option value="dark" selected>Dark</option>"#));
    assert!(signed_in.contains(r#"<option value="halloween">Halloween</option>"#));
    assert!(signed_in.contains("No alerts match these filters."));
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

    let alice = user(&stack, "alice").await;
    grant_alert_read(&stack, &alice).await;
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

// ---- PLAN.md 5.11's auth area: the password change ----

/// ace3's `/login/change` drawn directly: the form, the service's rules, and a problem as text.
#[test]
fn the_password_change_view_draws_its_form_and_rules() {
    let page = ChangePasswordPage::new(
        Layout::new(
            "n0nce",
            Theme::Dark,
            Some("alice".to_owned()),
            "/login/change",
        ),
        None,
    )
    .render()
    .expect("renders");
    assert!(
        page.contains(r#"<form method="post" action="/login/change">"#),
        "{page}"
    );
    for field in ["current_password", "new_password", "confirm"] {
        assert!(
            page.contains(&format!(r#"name="{field}""#)),
            "{field}: {page}"
        );
    }
    assert!(page.contains(&format!(
        "At least {} characters, and at most {} bytes",
        ace_service::MIN_PASSWORD_CHARS,
        ace_service::MAX_PASSWORD_BYTES
    )));
    assert!(page.contains(r#"<a href="/login/change">Change Password</a>"#));
    assert!(!page.contains(r#"role="alert""#), "no problem yet: {page}");
    assert!(inline_free(&page), "{page}");

    let page = ChangePasswordPage::new(
        Layout::new(
            "n0nce",
            Theme::Dark,
            Some(HOSTILE.to_owned()),
            "/login/change",
        ),
        Some(HOSTILE.to_owned()),
    )
    .render()
    .expect("renders");
    let escaped = "&#34;&#62;&#60;script&#62;alert(&#39;x&#39;)&#60;/script&#62;&#60;img src=x \
                   onerror=alert(1)&#62;&#38;amp;";
    assert!(
        page.contains(&format!(r#"<p class="error" role="alert">{escaped}</p>"#)),
        "{page}"
    );
    assert!(!page.contains("<script>alert"), "{page}");
    assert!(!page.contains("<img"), "{page}");
}

/// The password change through the server: signed out goes to the login, a cross-site post and each form
/// ace3 refuses change nothing, and a change ends every session of the user's, clears the cookie and says
/// so at the login, with its audit row.
#[tokio::test]
async fn a_password_change_changes_it_and_ends_every_session() {
    let stack = stack().await;
    user(&stack, "alice").await;
    let new = "a new password for alice";

    // Signed out.
    let page = stack.get("/login/change").send().await.expect("answered");
    assert_eq!(page.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&page), "/login?next=%2Flogin%2Fchange");
    let post = stack
        .post(
            "/login/change",
            &[
                ("current_password", PASSWORD),
                ("new_password", new),
                ("confirm", new),
            ],
        )
        .send()
        .await
        .expect("answered");
    assert_eq!(post.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&post), "/login");

    let first = session_set(stack.log_in("alice", PASSWORD).await.headers()).expect("a session");
    let second = session_set(stack.log_in("alice", PASSWORD).await.headers()).expect("a session");
    let page = stack
        .get("/login/change")
        .header("cookie", cookie(&first))
        .send()
        .await
        .expect("answered");
    assert_eq!(page.status(), StatusCode::OK);
    let page = page.text().await.expect("a page");
    assert!(
        page.contains(r#"<form method="post" action="/login/change">"#),
        "{page}"
    );
    assert!(page.contains(r#"<span class="user" id="username">alice</span>"#));

    let audit = stack.audit_count().await;
    let change = |form: Vec<(&'static str, String)>| {
        stack
            .http
            .post(format!("{}/login/change", stack.url))
            .header("origin", &stack.url)
            .header("cookie", cookie(&first))
            .form(&form)
    };
    let full = |current: &str, new: &str, confirm: &str| {
        vec![
            ("current_password", current.to_owned()),
            ("new_password", new.to_owned()),
            ("confirm", confirm.to_owned()),
        ]
    };
    for (what, request, status, says) in [
        (
            "two new passwords that differ",
            change(full(PASSWORD, new, "a different new password")),
            StatusCode::BAD_REQUEST,
            "The new passwords don&#39;t match.",
        ),
        (
            "a new password too short",
            change(full(PASSWORD, "short", "short")),
            StatusCode::BAD_REQUEST,
            "The new password is refused: a password has to be at least 12 characters",
        ),
        (
            "a wrong current password",
            change(full("not alice's password", new, new)),
            StatusCode::FORBIDDEN,
            "Current password is incorrect.",
        ),
        (
            "an incomplete form",
            change(vec![("current_password", PASSWORD.to_owned())]),
            StatusCode::BAD_REQUEST,
            "The form wasn&#39;t complete.",
        ),
        (
            "a post from another site",
            stack
                .http
                .post(format!("{}/login/change", stack.url))
                .header("origin", "https://evil.example")
                .header("cookie", cookie(&first))
                .form(&full(PASSWORD, new, new)),
            StatusCode::FORBIDDEN,
            "this request came from another site",
        ),
    ] {
        let response = request.send().await.expect("answered");
        assert_eq!(response.status(), status, "{what}");
        assert!(response.headers().get(SET_COOKIE).is_none(), "{what}");
        let page = response.text().await.expect("a page");
        assert!(page.contains(says), "{what}: {page}");
    }
    assert_eq!(stack.audit_count().await, audit, "nothing changed");
    for token in [&first, &second] {
        stack
            .service
            .authenticate_session(token)
            .await
            .expect("still live");
    }

    let changed = change(full(PASSWORD, new, new))
        .send()
        .await
        .expect("answered");
    assert_eq!(changed.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&changed), "/login?changed=password");
    let cleared = changed.headers()[SET_COOKIE].to_str().expect("text");
    assert!(cleared.starts_with("ace4_session=;"), "{cleared}");
    for token in [&first, &second] {
        assert!(matches!(
            stack.service.authenticate_session(token).await,
            Err(ServiceError::NotAuthenticated)
        ));
    }
    let action: String =
        sqlx::query_scalar("SELECT action FROM service.audit ORDER BY id DESC LIMIT 1")
            .fetch_one(stack.test_db.db().pool())
            .await
            .expect("a row");
    assert_eq!(action, "change_own_password");
    assert_eq!(stack.audit_count().await, audit + 1);

    let login = stack
        .get("/login?changed=password")
        .send()
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(
        login.contains("Your password is changed. Log in with the new one."),
        "{login}"
    );
    let plain = stack
        .get("/login")
        .send()
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(!plain.contains("Your password is changed"));
    assert!(session_set(stack.log_in("alice", PASSWORD).await.headers()).is_none());
    assert!(session_set(stack.log_in("alice", new).await.headers()).is_some());
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
        password_changed: false,
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

/// Whether HTML has no inline style and no event handler: no `style` attribute or element, and no
/// ` on<name>=` attribute.
fn inline_free(html: &str) -> bool {
    let handler = html.match_indices(" on").any(|(at, _)| {
        let rest = &html[at + 3..];
        let name = rest.len()
            - rest
                .trim_start_matches(|c: char| c.is_ascii_lowercase())
                .len();
        name > 0 && rest[name..].starts_with('=')
    });
    !handler && !html.contains("style=") && !html.contains("<style")
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
    let mut dirs = vec![root.join("templates")];
    let mut files = Vec::new();
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("reads the templates") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                dirs.push(path);
            } else {
                files.push(path);
            }
        }
    }
    for path in files {
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
        // the page's policy refuses inline styles and scripts, which is what a handler is
        assert!(
            inline_free(&text),
            "{} has an inline style or script",
            path.display()
        );
        if !path.ends_with("base.html") {
            assert!(!text.contains("<script"), "{} has a script", path.display());
        }
        templates.push(path);
    }
    assert!(templates.len() >= 18);
    // The one value askama doesn't escape is a view's HTML, which only `Views::draw` makes from a
    // template's output (src/analysis.rs).
    let mut safe = 0;
    for entry in std::fs::read_dir(root.join("src")).expect("reads the source") {
        let source = std::fs::read_to_string(entry.expect("an entry").path()).expect("reads");
        safe += source.matches("HtmlSafe for").count();
    }
    assert_eq!(safe, 1, "one type is marked as already escaped");
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
    grant_alert_read(&stack, &alice).await;
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
/// axum's included, while logins fail and succeed, a session is used, a key is made on the preferences
/// page, an administrator makes and resets a password and makes a key, and a logout ends it, with no
/// password, no session secret and no key's secret in it. The subscriber is global for the reason 5.4's test gives, so
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
    let alice = user(&stack, "alice").await;
    grant_to(&stack, &alice, "user", "self").await;
    grant_to(&stack, &alice, "alert", "read").await;
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
    let made = stack
        .post(
            "/preferences/keys",
            &[("name", "for the log"), ("scope", "alert:read")],
        )
        .header("cookie", cookie(&second))
        .send()
        .await
        .expect("answered");
    assert_eq!(made.status(), StatusCode::CREATED);
    let page = made.text().await.expect("a page");
    let key_token = page
        .split(r#"class="token" type="text" value=""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("the token")
        .to_owned();
    // an administrator's forms: a made password, a reset one, a typed one and a key's token
    grant_to(&stack, &alice, "admin", "read").await;
    grant_to(&stack, &alice, "user", "*").await;
    let made = stack
        .post(
            "/admin/users",
            &[("username", "carol"), ("password", ""), ("timezone", "UTC")],
        )
        .header("cookie", cookie(&second))
        .send()
        .await
        .expect("answered");
    assert_eq!(made.status(), StatusCode::CREATED);
    let made_password = shown_secret(&made.text().await.expect("a page"));
    let carol = stack
        .service
        .users(&alice, true)
        .await
        .expect("reads")
        .into_iter()
        .find(|user| user.username == "carol")
        .expect("carol")
        .id
        .0;
    let reset = stack
        .post(
            &format!("/admin/users/{carol}/password"),
            &[("password", "")],
        )
        .header("cookie", cookie(&second))
        .send()
        .await
        .expect("answered");
    assert_eq!(reset.status(), StatusCode::OK);
    let reset_password = shown_secret(&reset.text().await.expect("a page"));
    let typed = "carol-s-typed-password";
    stack
        .post(
            &format!("/admin/users/{carol}/password"),
            &[("password", typed)],
        )
        .header("cookie", cookie(&second))
        .send()
        .await
        .expect("answered");
    let carols_key = stack
        .post(
            &format!("/admin/users/{carol}/keys"),
            &[("name", "carol's"), ("mode", "inherit")],
        )
        .header("cookie", cookie(&second))
        .send()
        .await
        .expect("answered");
    assert_eq!(carols_key.status(), StatusCode::CREATED);
    let carols_key = shown_secret(&carols_key.text().await.expect("a page"));
    let changed_to = "alice-s-changed-password";
    stack
        .post(
            "/login/change",
            &[
                ("current_password", PASSWORD),
                ("new_password", changed_to),
                ("confirm", changed_to),
            ],
        )
        .header("cookie", cookie(&second))
        .send()
        .await
        .expect("answered");
    let third = session_set(stack.log_in("alice", changed_to).await.headers()).expect("a session");
    stack
        .post("/logout", &[])
        .header("cookie", cookie(&third))
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
        "a GUI password change",
        "create_own_api_key",
        "create_user",
        "reset_password",
        "create_api_key",
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
        changed_to.to_owned(),
        secret(&first),
        secret(&second),
        secret(&third),
        secret(&key_token),
        made_password,
        reset_password,
        typed.to_owned(),
        secret(&carols_key),
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
    let view = tree_view(&tree, &comments, &ObservableActions::empty());
    let html = AlertTreeFragment { tree: view.clone() }
        .render()
        .expect("renders");
    let compact: String = html.lines().map(str::trim).collect();
    // the shape: the email at the top, its result, what that added, a jump back to the email, and the
    // IP's result with the fqdn and a reference to the sender, which has no analysis to jump to
    let order = [
        r#"<div id="alert-tree" class="tree">"#,
        r#"<li class="observable" id="o1"><b class="type">file</b> : <span class="value">email.rfc822</span>"#,
        r#"<li class="result" id="r10" data-module="email_analyzer"><a class="summary" href="/alerts/00000000-0000-0000-0000-000000005800/results/10" title="email_analyzer">Email &#60;b&#62;Analysis&#60;/b&#62;</a> <span class="tag">x&#34;onmouseover=&#34;y</span>"#,
        r#"<li class="observable" id="o2"><b class="type">Mail From (email_from)</b> : <span class="value">a@example.com</span> <span class="detection" title="a known &#60;bad&#62; sender">detection: a known &#60;bad&#62; sender</span> <span class="tag">&#60;script&#62;alert(1)&#60;/script&#62;</span></li>"#,
        r#"<li class="observable" id="o3"><b class="type">Source IP (ip)</b> : <span class="value">192.0.2.10</span>"#,
        r#"<li class="comment"><span class="author">Alice &#60;A&#62;</span> <span class="time">2026-10-26 07:33:20 UTC</span>: seen &#60;/li&#62;&#60;li&#62;before</li>"#,
        r#"<li class="result" id="r11" data-module="rdap_analyzer"><a class="summary" href="/alerts/00000000-0000-0000-0000-000000005800/results/11" title="rdap_analyzer">rdap_analyzer</a>"#,
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
        &ObservableActions::empty(),
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
        &ObservableActions::empty(),
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

// ---- PLAN.md 5.9: analysis views ----

/// A module's result, as its own test wrote it (`ace_testkit::check_view_fixture`).
fn view_fixture(name: &str) -> ace_results::ResultEnvelope<serde_json::Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/fixtures/{name}.json"));
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{} reads: {e}", path.display()));
    serde_json::from_str(&text).expect("a result envelope")
}

/// A result's details drawn by its type's view, which has to be its own and keep the page's policy.
fn drawn(views: &Views, result: &ace_results::ResultEnvelope<serde_json::Value>) -> String {
    let version = i32::try_from(result.schema_version()).expect("a version");
    let drawn = views.draw(result.analysis_type(), version, &result.details);
    assert_eq!(drawn.fallback, None, "{}", result.analysis_type());
    let html = drawn.html.as_str().to_owned();
    assert!(inline_free(&html), "{html}");
    assert!(!html.contains("<script"), "{html}");
    assert_eq!(html.matches("<pre").count(), html.matches("</pre>").count());
    assert_eq!(
        html.matches("<details").count(),
        html.matches("</details>").count()
    );
    assert_eq!(
        html.matches("<table").count(),
        html.matches("</table>").count()
    );
    html
}

fn contains_all(html: &str, parts: &[&str]) {
    for part in parts {
        assert!(html.contains(part), "{part}\nisn't in\n{html}");
    }
}

/// PLAN.md 5.9's Done check: each ported module's view draws the module's own result, which its tests
/// keep as a fixture from a reference dump or a sample, with the content that matters in it.
#[test]
fn each_module_s_view_draws_its_fixture() {
    let views = Views::builtin();
    let fixtures = [
        "email_pdf_attachment",
        "archive_test_zip",
        "yara_test_zip_attachment",
        "rdap_fqdn_example_com",
        "dns_fqdn_example_com",
        "snort_sig_9000001",
        "brocess_frequent_conversation",
        "brocess_email_thread",
        "nrd_fqdn_ace4_fresh_com",
        "user_jdoe",
        "splunk_clicker_click_example_com",
        "splunk_proxy_domain_lookup",
        "olevba_receipt_doc",
        "rtfole_objects_rtf",
        "msoffice_encrypted_agile_docx",
        "xlm_obfuscated_xlsm",
        "pcode_receipt_doc",
        "pdf_encrypted_aes_128",
        "urls_page_html",
        "iocs_report_txt",
        "file_type_script_js",
        "file_hash_notes_zip",
        "binary_nul_rtf",
        "lnk_shortcut",
        "x509_cert_pem",
        "dhash_brand_jpg",
        "command_line_encoded_short",
        "file_path_user_path",
        "file_location_windows",
        "network_two_networks",
        "parse_url_full",
        "idna_unicode",
        "email_address_fqdn_plain",
        "protected_url_safelinks",
        "protected_url_one_drive",
        "html_data_url_page",
        "mhtml_page",
        "html_js_scripts",
        "har_session",
        "onenote_two_files",
        "active_mime_ole",
        "hidden_mime_bin",
        "xml_binary_flat",
        "xml_plain_text_document",
        "office_xml_rel_external",
        "officeparser_native",
        "extracted_ole_payload",
        "mse_invoice_vbe",
        "extracted_rtf_payload",
        "vbscript_many_same",
        "nowhitespace_spaced",
        "zip_encryption_aes256",
        "rar_encryption_rar5_headers",
        "pdf_encryption_aes_256",
        "lure_url_button",
        "mailbox_lure_button",
        "attachment_macro_attachment",
        "link_lure_button",
        "email_archive_o365_journaled",
        "encrypted_archive_sealed_v0",
        "url_pivot_shared",
        "message_id_archived_2",
    ];
    let mut types = BTreeSet::new();
    for name in fixtures {
        let result = view_fixture(name);
        types.insert((result.analysis_type().to_owned(), result.schema_version()));
        let html = drawn(&views, &result);
        match name {
            "email_pdf_attachment" => contains_all(
                &html,
                &[
                    "<h3>Email Summary</h3>",
                    "<tr><th>From</th><td>John Davison &#60;unixfreak0037@gmail.com&#62;</td></tr>",
                    "<tr><th>To</th><td>jwdavison@company.com</td></tr>",
                    "<tr><th>Subject (Decoded)</th><td>canary #1</td></tr>",
                    "<tr><th>Message ID</th><td>&#60;CANTOGZuWahvYOEr0NwPELF5ASriGNWjfVsWhMSE_ekiSVw1RbA@mail.gmail.com&#62;</td></tr>",
                    "<td>spectre.pdf</td><td>application/pdf</td><td>131872</td>",
                    "<summary>Raw Email Headers</summary>",
                    "Received: from CY4PR20CA0037.namprd20.prod.outlook.com",
                ],
            ),
            "archive_test_zip" => contains_all(
                &html,
                &[
                    "<tr><th>file_count</th><td>1</td></tr>",
                    "<li>Faktura.FS.17.9.20_2018_2_13_AI02668779.pdf.js</li>",
                ],
            ),
            "yara_test_zip_attachment" => {
                contains_all(
                    &html,
                    &[
                        "<h3>ace4_fixture_zip_attachment</h3>",
                        "<h3>ace4_fixture_zip_any</h3>",
                        "<code>test.zip</code>",
                        "string <b>$local_file_header</b> value <b class=\"yara-value\">PK<span class=\"yara-ws\">\u{2403}</span><span class=\"yara-ws\">\u{2404}</span></b>",
                        // the match marked in both columns of its dump, as ace3's
                        "00000000  <mark>50 4b 03 04</mark> 14 00",
                        "|<mark>PK..</mark>.......3.5.Z|",
                        "<span class=\"yara-meta-line\">    &#34;meta_tags&#34;: &#34;type=email.attachment&#34;,</span>",
                    ],
                );
            }
            "rdap_fqdn_example_com" => contains_all(
                &html,
                &[
                    "<tr><th>domain_name</th><td>EXAMPLE.COM</td></tr>",
                    "<tr><th>datetime_created</th><td>1995-08-14 04:00:00+00:00</td></tr>",
                    "<tr><th>datetime_expiration</th><td>2027-08-13 04:00:00+00:00</td></tr>",
                    "<tr><th>datetime_of_last_update</th><td>2026-08-14 08:01:43+00:00</td></tr>",
                    "<tr><th>name_servers</th><td>ELLIOTT.NS.CLOUDFLARE.COM, HERA.NS.CLOUDFLARE.COM</td></tr>",
                    "<summary>rdap_raw_json</summary>",
                    "&#34;ldhName&#34;: &#34;EXAMPLE.COM&#34;",
                ],
            ),
            "dns_fqdn_example_com" => contains_all(
                &html,
                &[
                    "<tr><th>status</th><td>ok</td></tr>",
                    "<tr><th>ip_address</th><td>192.0.2.10</td></tr>",
                    "<tr><th>all_resolutions</th><td>192.0.2.10, 192.0.2.2</td></tr>",
                    "<tr><th>mx</th><td>backup.example.com, mail.example.com</td></tr>",
                    "<tr><th>wildcard_dns</th><td>false</td></tr>",
                ],
            ),
            "snort_sig_9000001" => contains_all(
                &html,
                &[
                    "<tr><th>signature_id</th><td>9000001 rev 3</td></tr>",
                    "<pre class=\"wrap\">alert http $HOME_NET any -&#62; $EXTERNAL_NET any (msg:&#34;ACE4 TEST fixture beacon&#34;;",
                ],
            ),
            "nrd_fqdn_ace4_fresh_com" => contains_all(
                &html,
                &[
                    "<tr><th>is_nrd</th><td>true</td></tr>",
                    "<tr><th>datetime_created</th><td>2026-11-01 12:30:00+00:00</td></tr>",
                    "<tr><th>age_created_in_days</th><td>7</td></tr>",
                    "<tr><th>lookup_protocol</th><td>rdap</td></tr>",
                ],
            ),
            "splunk_clicker_click_example_com" => contains_all(
                &html,
                &[
                    "rel=\"noopener noreferrer\">Open in Splunk</a>",
                    "<strong>Did anyone click this URL or visit this domain?</strong>",
                    "<td>2026-11-08T10:00:00.1234567Z</td><td>alice@example.com</td><td>ClickAllowed</td>",
                    "<td>splunk:proxy</td>",
                ],
            ),
            "user_jdoe" => contains_all(
                &html,
                &[
                    "<tr><th>Name</th><td>Doe, John</td></tr>",
                    "<tr><th>Email</th><td><a href=\"mailto:John.Doe@company.example\">John.Doe@company.example</a></td></tr>",
                    "<tr><th>Password Last Set</th><td>2022-06-18 04:26:40+00:00</td></tr>",
                    "<tr><th>Manager</th><td>Smith, Alice</td></tr>",
                    "<tr><td>VPN Users</td><td>Groups</td><td>company.example</td></tr>",
                    "&#34;objectSid&#34;: &#34;S-1-5-21-67305985-134678021-202050057-1105&#34;",
                ],
            ),
            "brocess_frequent_conversation" => contains_all(
                &html,
                &[
                    "<tr><th>source_count</th><td>10</td></tr>",
                    "<tr><th>dest_count</th><td>7</td></tr>",
                ],
            ),
            "brocess_email_thread" => contains_all(
                &html,
                &[
                    "<tr><th>Subject</th><td>quarterly invoice</td></tr>",
                    "In-Reply-To / References:",
                    "<h3>Email conversation</h3>",
                    "**examp1e.com** (looks like example.com)",
                    "<code>examp1e.com</code> looks like <code>example.com</code>",
                    "Jaro-Winkler 0.9636, visually confusable",
                    "<code>alice@examp1e.com</code> &rarr; <code>alice@example.com</code> (identical local part)",
                    "<td>3 &larr;</td>",
                    "<mark><code>alice@examp1e.com</code></mark>",
                    "reply-to:</span> <mark><code>alice.vendor@ex\u{430}mple.com</code></mark>",
                    "not attributable to a specific message: <code>accounts@example.com</code>",
                ],
            ),
            "splunk_proxy_domain_lookup" => contains_all(
                &html,
                &[
                    "<strong>Was this domain seen in proxy logs?</strong>",
                    "<summary>Show Query</summary>",
                    "hostname=&#34;www.example.com&#34;",
                    "<th>src_ip</th>",
                    "<td title=\"192.0.2.10\">192.0.2.10</td>",
                    "<td title=\"https://www.example.com/login\">https://www.example.com/login</td>",
                    "<summary>Raw Details</summary>",
                ],
            ),
            "olevba_receipt_doc" => contains_all(
                &html,
                &[
                    "<tr><th>type</th><td>OLE</td></tr>",
                    "autoexec=1, base64 string=1, hex string=1, suspicious=1",
                    "<h3>ThisDocument.cls</h3>",
                    "<tr><th>stream_path</th><td>Macros/VBA/ThisDocument</td></tr>",
                    "Private Sub Document_Open()",
                    "<h3>mirtans.bas</h3>",
                ],
            ),
            "rtfole_objects_rtf" => contains_all(
                &html,
                &[
                    "<tr><th>return_code</th><td>0</td></tr>",
                    "<li>objects.rtf.rtfobj/objects.rtf_payload.exe</li>",
                    "<li>objects.rtf.rtfobj/objects.rtf_café.txt</li>",
                    "<summary>stdout</summary>",
                    "URL extracted: http://example.com/a.hta",
                ],
            ),
            "msoffice_encrypted_agile_docx" => contains_all(
                &html,
                &[
                    "<tr><th>password</th><td><code>Secr3tPw</code></td></tr>",
                    "<tr><th>email</th><td>true</td></tr>",
                    "VelvetSweatshop\n",
                    "The password is Secr3tPw",
                ],
            ),
            "xlm_obfuscated_xlsm" => {
                contains_all(&html, &["<tr><th>cell_count</th><td>13</td></tr>"]);
            }
            "pcode_receipt_doc" => {
                contains_all(&html, &["<tr><th>line_count</th><td>1578</td></tr>"]);
            }
            "pdf_encrypted_aes_128" => contains_all(
                &html,
                &[
                    "<tr><th>filter</th><td>/Standard</td></tr>",
                    "<tr><th>method</th><td>aes</td></tr>",
                    "<tr><th>bits</th><td>128</td></tr>",
                    "<tr><th>modify_assembly</th><td>false</td></tr>",
                ],
            ),
            "urls_page_html" => contains_all(
                &html,
                &[
                    "<tr><th>urls</th><td>10</td></tr>",
                    "<li>https://visible.example.org/page</li>",
                    "<summary>example.com (8)</summary>",
                    "<li>https://base.example.com/dir/login.php?u=1</li>",
                ],
            ),
            "iocs_report_txt" => contains_all(
                &html,
                &[
                    "<tr><th>total_count</th><td>15</td></tr>",
                    "<h3>cve</h3>",
                    "<li>198.51.100.23</li>",
                    "<h3>ignored</h3>",
                ],
            ),
            "file_type_script_js" => contains_all(
                &html,
                &[
                    "<tr><th>mime</th><td>text/plain</td></tr>",
                    "<tr><th>is_zip_file</th><td>false</td></tr>",
                ],
            ),
            "file_hash_notes_zip" => contains_all(&html, &["<tr><th>sha256</th><td>"]),
            "binary_nul_rtf" => contains_all(&html, &["No details"]),
            "lnk_shortcut" => contains_all(&html, &["<tr><th>target</th><td>"]),
            "x509_cert_pem" => contains_all(
                &html,
                &[
                    "<tr><th>common_name</th><td>*.login.example.com</td></tr>",
                    "<tr><th>san_ip_addresses</th><td>192.0.2.10</td></tr>",
                ],
            ),
            "dhash_brand_jpg" => contains_all(
                &html,
                &["<tr><th>score</th><td>brand.png: 98.24% of 90.00%</td></tr>"],
            ),
            "command_line_encoded_short" => contains_all(
                &html,
                &["<tr><th>base64_payloads</th><td>command_line_base64_payload.bin</td></tr>"],
            ),
            "file_path_user_path" => contains_all(
                &html,
                &[
                    "<tr><th>file_name</th><td>evil.exe</td></tr>",
                    "<tr><th>user_name</th><td>alice</td></tr>",
                ],
            ),
            "file_location_windows" => {
                contains_all(&html, &["<tr><th>hostname</th><td>WS-0042</td></tr>"])
            }
            "network_two_networks" => contains_all(
                &html,
                &[
                    "<tr><th>network</th><td>corporate</td></tr>",
                    "<tr><th>network</th><td>lab</td></tr>",
                ],
            ),
            "parse_url_full" => contains_all(
                &html,
                &[
                    "<tr><th>netloc</th><td>www.example.com</td></tr>",
                    "<tr><th>query</th><td>a=1&#38;b=%20x+y</td></tr>",
                ],
            ),
            "idna_unicode" => {
                contains_all(&html, &["<tr><th>idna</th><td>xn--mnchen-3ya.de</td></tr>"])
            }
            "email_address_fqdn_plain" => {
                contains_all(&html, &["<tr><th>domain</th><td>example.com</td></tr>"])
            }
            "protected_url_safelinks" => contains_all(
                &html,
                &[
                    "<tr><th>protection_type</th><td>safelinks_outlook</td></tr>",
                    "<tr><th>extracted_url</th><td>https://evil.example.com/page</td></tr>",
                ],
            ),
            "protected_url_one_drive" => contains_all(
                &html,
                &["<tr><th>protection_type</th><td>one_drive</td></tr>"],
            ),
            "html_data_url_page" => contains_all(&html, &["<tr><th>count</th><td>6</td></tr>"]),
            "mhtml_page" => contains_all(
                &html,
                &[
                    "<tr><th>extracted_file</th><td>50e0640b44315641c34a09463dd53e2dc0f4e808446ffb4e2422646faa82ad30</td></tr>",
                ],
            ),
            "html_js_scripts" => contains_all(
                &html,
                &[
                    "<tr><th>script_count</th><td>13</td></tr>",
                    "<tr><th>extracted_url</th><td>https://cdn.example.com/lib/jquery.min.js</td></tr>",
                ],
            ),
            "har_session" => contains_all(
                &html,
                &[
                    "<tr><th>creator</th><td>WebInspector 537.36</td></tr>",
                    "<tr><th>entry_count</th><td>19</td></tr>",
                ],
            ),
            "onenote_two_files" => contains_all(
                &html,
                &[
                    "<tr><th>extracted_file</th><td>e9b4ff075e05eb59b9ff8037003dbf17321d0eb75b9a56b738c6789fee69ee5b</td></tr>",
                ],
            ),
            "active_mime_ole" => contains_all(
                &html,
                &["<tr><th>extracted_file</th><td>ole.mso.activemime</td></tr>"],
            ),
            "hidden_mime_bin" => contains_all(
                &html,
                &["<tr><th>extracted_file</th><td>hidden.bin.mime/extracted-1</td></tr>"],
            ),
            "xml_binary_flat" => contains_all(
                &html,
                &[
                    "<tr><th>extracted_file</th><td>files/flat.xml.xml/word/media/image1.png</td></tr>",
                ],
            ),
            "xml_plain_text_document" => contains_all(
                &html,
                &[
                    "<tr><th>xml_plain_text</th><td>invoice.docx.extracted/word/document.xml.noxml</td></tr>",
                ],
            ),
            "office_xml_rel_external" => contains_all(
                &html,
                &["<tr><th>url</th><td>file:///C:/Users/Public/evil.hta</td></tr>"],
            ),
            "officeparser_native" => contains_all(
                &html,
                &[
                    "<tr><th>extracted_file</th><td>payload.vbs</td></tr>",
                    "<tr><th>extracted_file</th><td>Module1.bas</td></tr>",
                ],
            ),
            "extracted_ole_payload" => contains_all(
                &html,
                &["<tr><th>suspect_file</th><td>native.doc.officeparser/payload.vbs</td></tr>"],
            ),
            "mse_invoice_vbe" => contains_all(
                &html,
                &["<tr><th>analysis_output</th><td>invoice.vbe.decrypted.vbs</td></tr>"],
            ),
            "extracted_rtf_payload" => contains_all(&html, &["No details"]),
            "vbscript_many_same" => contains_all(
                &html,
                &[
                    "<tr><th>total_hex_strings</th><td>101</td></tr>",
                    "<tr><th>largest_hex_string</th><td>60</td></tr>",
                    "<tr><th>percentage_of_hex_strings</th><td>87.48451053283766</td></tr>",
                ],
            ),
            "nowhitespace_spaced" => contains_all(&html, &["<tr><th>count</th><td>16</td></tr>"]),
            "zip_encryption_aes256" => contains_all(
                &html,
                &[
                    "<tr><th>password</th><td><code>Aes256Pw</code></td></tr>",
                    "<tr><th>email</th><td>true</td></tr>",
                    "The password for the attached file is Aes256Pw",
                ],
            ),
            "rar_encryption_rar5_headers" => contains_all(
                &html,
                &[
                    "<tr><th>password</th><td><code>Rar5Head</code></td></tr>",
                    "Rar5Head\n",
                ],
            ),
            "pdf_encryption_aes_256" => contains_all(
                &html,
                &[
                    "<tr><th>password</th><td><code>Aes256Us</code></td></tr>",
                    "<summary>word_list (52)</summary>",
                ],
            ),
            "lure_url_button" => contains_all(
                &html,
                &[
                    "<tr><th>email</th><td>Action required: verify your mailbox</td></tr>",
                    "<code>https://login.lure-example.net/verify?id=7</code> <span class=\"muted\">(80)</span>",
                    "clickable link with text &#39;<b>Verify your mailbox</b>&#39;; styled as a button",
                    "other candidates</summary>",
                    "carries 1 URL: <b>docs.lure-example.net/open?d=1</b>",
                ],
            ),
            "mailbox_lure_button"
            | "attachment_macro_attachment"
            | "link_lure_button"
            | "message_id_archived_2" => contains_all(&html, &["No details"]),
            "email_archive_o365_journaled" => contains_all(
                &html,
                &[
                    "<tr><th>archive_path</th><td>archive/email/c0/c09769d5f85a2ad6ec1e1cc8196b0c413fa45",
                    "<tr><th>hash</th><td>c09769d5f85a2ad6ec1e1cc8196b0c413fa45",
                ],
            ),
            "encrypted_archive_sealed_v0" => contains_all(
                &html,
                &["<tr><th>decrypted_file</th><td>files/sealed_v0.rfc822</td></tr>"],
            ),
            "url_pivot_shared" => contains_all(&html, &["<tr><th>count</th><td>3</td></tr>"]),
            other => panic!("no checks for {other}"),
        }
    }
    let with_views: BTreeSet<(String, u32)> = views
        .types()
        .map(|(name, v)| (name.to_owned(), v))
        .collect();
    assert_eq!(
        types, with_views,
        "a fixture for each view, and a view for each fixture"
    );
}

/// A module's text is escaped wherever a view puts it, bytes read as ace3 shows them, and what's large is
/// cut with a note.
#[test]
fn a_view_escapes_bytes_and_bounds_what_a_module_wrote() {
    use ace_gui::analysis::{MAX_HIGHLIGHTED_MATCHES, MAX_MATCHES, MAX_TEXT};
    use base64::Engine as _;
    let views = Views::builtin();
    let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    let hostile = "<script>alert(1)</script>\"'&";
    let matches = MAX_MATCHES + 5;
    let context: Vec<serde_json::Value> = (0..matches)
        .map(|i| serde_json::json!([i, "$s<b>", {"base64": b64(b" \n\x00\xff<i>")}, "00000000  <dump>"]))
        .collect();
    let match_context: Vec<serde_json::Value> = (0..matches)
        .map(|_| serde_json::json!({"data": {"base64": b64(b"ab <i>\x00")}, "match_offset": 2, "match_length": 3}))
        .collect();
    let yara = serde_json::json!({"scan_results": [{
        "rule": hostile, "namespace": hostile, "meta": {"k": hostile}, "tags": [hostile],
        "commit": null, "target": hostile,
        "strings": [[0, "$s<b>", {"base64": b64(b"x")}]],
        "context": context, "match_context": match_context,
    }]});
    let html = drawn(
        &views,
        &serde_json::from_value(serde_json::json!({
            "analysis_type": "yara_scan_results", "schema_version": 1, "details": yara,
        }))
        .expect("a result"),
    );
    assert!(
        !html.contains("<script>")
            && !html.contains("$s<b>")
            && !html.contains("<i>")
            && !html.contains("<dump>")
    );
    assert!(html.contains("<h3>&#60;script&#62;alert(1)&#60;/script&#62;&#34;&#39;&#38;</h3>"));
    // a space, a newline, a NUL, 0xff and markup, as ace3 draws them
    assert!(html.contains(
        "<span class=\"yara-sp\"> </span><span class=\"yara-ws\">\u{240a}</span><span class=\"yara-ws\">\u{2400}</span>\u{ff}&#60;i&#62;"
    ));
    assert!(html.contains("|ab<mark> &#60;i</mark>&#62;.|"));
    assert_eq!(
        html.matches("<pre class=\"yara-hexdump\">").count(),
        MAX_MATCHES
    );
    assert_eq!(html.matches("<mark>").count(), MAX_HIGHLIGHTED_MATCHES * 2);
    assert!(
        html.contains("00000000  &#60;dump&#62;"),
        "past the highlighted ones, the dump as stored"
    );
    assert!(html.contains("5 more matches not shown."));

    let long = "x".repeat(MAX_TEXT + 10);
    let olevba = serde_json::json!({"type": hostile, "keyword_summary": {hostile: 1}, "macros": [{
        "file_name": {"base64": b64(b"a\xffb")}, "stream_path": hostile, "vba_filename": hostile,
        "vba_code": format!("{hostile}{long}"), "local_path": "0".repeat(64),
    }]});
    let html = drawn(
        &views,
        &serde_json::from_value(serde_json::json!({
            "analysis_type": "olevba_analysis", "schema_version": 1, "details": olevba,
        }))
        .expect("a result"),
    );
    assert!(!html.contains("<script>"));
    assert!(
        html.contains("<tr><th>file_name</th><td>a\\xffb</td></tr>"),
        "{html}"
    );
    assert!(html.contains("38 more bytes of code not shown."), "{html}");
    assert!(html.len() < MAX_TEXT + 4096);

    let email = view_fixture("email_pdf_attachment");
    let mut details = email.details.clone();
    details["email"]["subject"] = serde_json::json!(hostile);
    details["email"]["decoded_subject"] = serde_json::json!(hostile);
    details["email"]["headers"] = serde_json::json!([["X-<b>", hostile]]);
    details["email"]["log_entry"]["attachment_names"] = serde_json::json!([hostile]);
    let version = i32::try_from(email.schema_version()).expect("a version");
    let html = views
        .draw("email_analysis", version, &details)
        .html
        .as_str()
        .to_owned();
    assert!(
        !html.contains("<script>") && !html.contains("X-<b>"),
        "{html}"
    );
    assert!(html.contains("X-&#60;b&#62;: &#60;script&#62;"));
}

/// A type with no view, or details its view can't read, is its details as JSON, as ace3's default
/// template prints them, escaped and bounded, and says why.
#[test]
fn a_result_with_no_view_is_its_details_as_json() {
    use ace_gui::analysis::MAX_JSON;
    let views = Views::builtin();
    let details = serde_json::json!({"b": "<script>x</script>", "a": "y".repeat(MAX_JSON)});
    let drawn = views.draw("site_thing", 1, &details);
    let why = drawn.fallback.expect("a fallback");
    assert!(why.contains("site_thing version 1 has no view"), "{why}");
    let html = drawn.html.as_str();
    assert!(
        html.starts_with("<pre class=\"json\">{\n    &#34;a&#34;: &#34;yyy"),
        "{}",
        &html[..80]
    );
    assert!(!html.contains("<script>"));
    assert!(html.contains("more bytes of details not shown."));
    assert!(html.len() < MAX_JSON + 1024);

    let unreadable = views.draw(
        "pcode_analysis",
        1,
        &serde_json::json!({"line_count": "many"}),
    );
    assert!(
        unreadable
            .fallback
            .expect("a fallback")
            .contains("couldn't draw this result")
    );
    assert!(
        views
            .draw("pcode_analysis", 2, &serde_json::json!({}))
            .fallback
            .is_some()
    );
    assert!(
        views
            .draw("pcode_analysis", -1, &serde_json::json!({}))
            .fallback
            .is_some()
    );
}

#[test]
fn the_views_helpers_read_bytes_as_ace3_does() {
    use ace_gui::analysis::{Glyph, bytes_text, clip, hexdump, visible};
    assert_eq!(clip("aé", 2).text, "a");
    assert_eq!(clip("aé", 2).more, 2);
    assert_eq!(clip("abc", 3).more, 0);
    assert_eq!(bytes_text(b"a\xffb\xc3\xa9"), "a\\xffbé");
    assert_eq!(
        visible(b"a b\n\x7f\x85\xe9"),
        [
            Glyph::Text("a".to_owned()),
            Glyph::Space,
            Glyph::Text("b".to_owned()),
            Glyph::Symbol("\u{240a}".to_owned()),
            Glyph::Symbol("\u{2421}".to_owned()),
            Glyph::Symbol("\\x85".to_owned()),
            Glyph::Text("é".to_owned()),
        ]
    );
    let lines = hexdump(b"PK\x03\x04rest", 0..4);
    let first: String = lines[0]
        .iter()
        .map(|s| {
            if s.marked {
                format!("<{}>", s.text)
            } else {
                s.text.clone()
            }
        })
        .collect();
    // hexdump -C's columns, padded where the line is short
    assert_eq!(
        first,
        format!(
            "00000000  <50 4b 03 04> 72 65 73 74{}  |<PK..>rest|",
            " ".repeat(25)
        )
    );
    assert_eq!(lines[1][0].text, "00000008");
}

/// A result's page: its summary in the tree links to it, and it draws the result with its type's view under
/// `alert:read`, with what the result added.
#[tokio::test]
async fn a_result_s_page_draws_it_with_its_view() {
    let stack = stack().await;
    let alice = user(&stack, "alice").await;
    grant_alert_read(&stack, &alice).await;
    let _bob = user(&stack, "bob").await;
    let (root, _) = splunk_alert(&stack).await;
    let alice_session = session_of(&stack, "alice").await;
    let alert = stack
        .get(&format!("/alerts/{root}"))
        .header("cookie", cookie(&alice_session))
        .send()
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    let start = alert
        .find(&format!("href=\"/alerts/{root}/results/"))
        .expect("a link to the result")
        + 6;
    let path = &alert[start..start + alert[start..].find('"').expect("its end")];

    let response = stack
        .get(path)
        .header("cookie", cookie(&alice_session))
        .send()
        .await
        .expect("answered");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()["content-security-policy"]
            .to_str()
            .expect("text")
            .contains("style-src 'self';")
    );
    let page = response.text().await.expect("a page");
    assert!(inline_free(&page), "{page}");
    contains_all(
        &page,
        &[
            &format!("<a href=\"/alerts/{root}\">Back to Alert</a>"),
            "<h1>Proxy &#60;correlation&#62;</h1>",
            "<b class=\"type\">fqdn</b> : <span class=\"value\">www.example.com</span>",
            "<h3>Proxy correlation: (3 results)</h3>",
            "proxy_domain_lookup · splunk_api_analysis version 1",
            "<div class=\"analysis-view\">",
            "<summary>Show Query</summary>",
            "<td title=\"192.0.2.10\">192.0.2.10</td>",
            "<h2>Observables this result added</h2>",
            "<b class=\"type\">Source IP (ip)</b> : 192.0.2.10</a>",
        ],
    );
    assert!(!page.contains("has no view"));

    // No alert:read; no such result, in this alert or at all; and no session.
    let bob_session = session_of(&stack, "bob").await;
    let refused = stack
        .get(path)
        .header("cookie", cookie(&bob_session))
        .send()
        .await
        .expect("answered");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert!(!refused.text().await.expect("a page").contains("192.0.2.10"));
    for missing in [
        format!("/alerts/{root}/results/999999"),
        format!("/alerts/{root}/results/x"),
        format!("/alerts/{}/results/1", uuid::Uuid::nil()),
    ] {
        let response = stack
            .get(&missing)
            .header("cookie", cookie(&alice_session))
            .send()
            .await
            .expect("answered");
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{missing}");
    }
    let anonymous = stack.get(path).send().await.expect("answered");
    assert_eq!(anonymous.status(), StatusCode::SEE_OTHER);
}

/// The `<script>` tags of a page, as written.
fn script_tags(page: &str) -> Vec<&str> {
    page.match_indices("<script")
        .map(|(at, _)| &page[at..at + page[at..].find('>').expect("the tag's end") + 1])
        .collect()
}

/// PLAN.md 5.13: the graph's page, called directly and through the server. It holds the alert's title,
/// escaped, and an empty `#graph` naming the JSON API's route, and loads vis.js and its own script with the
/// response's nonce, so it has no inline script or style. It's refused as the alert's page is. vis.js is
/// the release `vendor/README.md` records, by its hash.
#[tokio::test]
async fn the_graph_page_loads_vis_and_its_script_with_the_nonce() {
    let id = uuid::Uuid::from_u128(0x513);
    let alert = Alert {
        summary: summary(id, HOSTILE),
        observables: 0,
        files: 0,
        detections: 0,
    };
    let page = GraphPage::new(
        Layout::new(
            "n0nce",
            Theme::Light,
            Some("alice".to_owned()),
            "/alerts/x/graph",
        ),
        &alert,
    )
    .render()
    .expect("renders");
    let escaped = "&#34;&#62;&#60;script&#62;alert(&#39;x&#39;)&#60;/script&#62;&#60;img src=x \
                   onerror=alert(1)&#62;&#38;amp;";
    contains_all(
        &page,
        &[
            &format!("<h1>{escaped}</h1>"),
            &format!("<a href=\"/alerts/{id}\">Back to Alert</a>"),
            &format!(
                r#"<div id="graph" class="graph" data-source="/api/alerts/v1/alerts/{id}/graph"></div>"#
            ),
            r#"<p id="graph-status" class="muted" role="status">"#,
        ],
    );
    assert!(!page.contains(HOSTILE));
    // the title's escaped text reads as a handler to inline_free, which looks for ` on<name>=` anywhere
    assert!(inline_free(&page.replace(escaped, "")), "{page}");
    let scripts = script_tags(&page);
    assert_eq!(
        scripts.len(),
        3,
        "Datastar, vis and the graph's: {scripts:?}"
    );
    let mut names = Vec::new();
    for tag in &scripts {
        assert!(tag.contains(r#" nonce="n0nce" src="/static/"#), "{tag}");
        let name = tag
            .split("src=\"/static/")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("a source");
        names.push(asset_named(name).expect("an embedded asset").name.clone());
    }
    assert!(names[0].starts_with("datastar-1.0.4."));
    assert!(names[1].starts_with("vis-4.1.0."), "{names:?}");
    assert!(names[2].starts_with("graph."), "{names:?}");
    // no other page loads vis
    let alert_page = AlertPage::new(
        Layout::new("n0nce", Theme::Light, Some("alice".to_owned()), "/alerts/x"),
        &fixture_tree().0,
        &[],
        &ObservableActions::empty(),
        &std::collections::BTreeMap::new(),
    )
    .expect("a page")
    .render()
    .expect("renders");
    assert_eq!(script_tags(&alert_page).len(), 1);
    assert!(
        alert_page
            .contains(r#"<a href="/alerts/00000000-0000-0000-0000-000000005800/graph">Graph</a>"#)
    );

    // vis.js is the release the README records, served as the other assets are.
    let readme = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vendor/README.md"),
    )
    .expect("reads the README");
    let recorded = readme
        .split("## vis")
        .nth(1)
        .expect("vis's section")
        .split('`')
        .find(|part| part.len() == 64 && part.bytes().all(|b| b.is_ascii_hexdigit()))
        .expect("a SHA-256");
    assert_eq!(
        recorded, "46976445f2254ccba5803dd9d9725fb5fccda2c88b381340046fc8cd1a225ee6",
        "dist/vis.js of npm's vis 4.1.0, whose tarball's integrity npm records"
    );

    // Through the server.
    let stack = stack().await;
    let alice = user(&stack, "alice").await;
    grant_alert_read(&stack, &alice).await;
    let _bob = user(&stack, "bob").await;
    let (root, _) = splunk_alert(&stack).await;
    let path = format!("/alerts/{root}/graph");
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
    assert!(!policy.contains("unsafe"), "{policy}");
    let page = response.text().await.expect("a page");
    let nonce = page
        .split("data-nonce=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("the nonce");
    assert!(policy.contains(&format!("script-src 'self' 'nonce-{nonce}';")));
    assert!(inline_free(&page), "{page}");
    contains_all(
        &page,
        &[
            "<h1>Proxy &#60;correlation&#62;</h1>",
            &format!(r#"data-source="/api/alerts/v1/alerts/{root}/graph""#),
        ],
    );
    for tag in script_tags(&page) {
        assert!(
            tag.contains(&format!(" nonce=\"{nonce}\" src=\"/static/")),
            "{tag}"
        );
        let url = tag
            .split("src=\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("a source");
        let served = stack.get(url).send().await.expect("answered");
        assert_eq!(served.status(), StatusCode::OK, "{url}");
        assert_eq!(
            served.headers()["content-type"],
            "text/javascript; charset=utf-8"
        );
        assert_eq!(
            served.headers()["cache-control"],
            "public, max-age=31536000, immutable"
        );
        let bytes = served.bytes().await.expect("bytes");
        if url.starts_with("/static/vis-") {
            assert_eq!(hex::encode(Sha256::digest(&bytes)), recorded);
            assert!(bytes.starts_with(b"/**\n * vis.js\n"));
        }
    }

    // No alert:read; no such alert; and no session.
    let bob_session = session_of(&stack, "bob").await;
    let refused = stack
        .get(&path)
        .header("cookie", cookie(&bob_session))
        .send()
        .await
        .expect("answered");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert!(!refused.text().await.expect("a page").contains("Proxy"));
    for missing in [
        "/alerts/x/graph".to_owned(),
        format!("/alerts/{}/graph", uuid::Uuid::nil()),
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
        format!("/login?{}", next_query(&path))
    );
}

/// The open-source observable actions (PLAN.md 5.9, #1032): Add Comment on every observable the tree draws
/// in full, and Download File As ZIP on a file with bytes, as links, which a reference doesn't repeat.
#[test]
fn the_tree_offers_each_observable_its_actions() {
    let (tree, comments) = fixture_tree();
    let html = AlertTreeFragment {
        tree: tree_view(&tree, &comments, &ObservableActions::builtin()),
    }
    .render()
    .expect("renders");
    assert!(inline_free(&html));
    let alert = "00000000-0000-0000-0000-000000005800";
    for (observable, count) in [(1, 1), (2, 1), (3, 1), (4, 1)] {
        let comment = format!(
            r#"<li><a href="/alerts/{alert}/observables/{observable}/comment">Add Comment</a></li>"#
        );
        assert_eq!(html.matches(&comment).count(), count, "{comment}\n{html}");
    }
    assert_eq!(
        html.matches(&format!(
            r#"<a href="/api/alerts/v1/alerts/{alert}/observables/1/file">Download File As ZIP</a>"#
        ))
        .count(),
        1
    );
    assert_eq!(
        html.matches("Download File As ZIP").count(),
        1,
        "only the file has one"
    );
    assert_eq!(html.matches(r#"<details class="actions">"#).count(), 4);

    // a site's action that tries for a script or another scheme isn't drawn
    let hostile = ace_gui::ObservableAction::new("x", "X", |t| {
        Some(format!("javascript:alert('{}')", t.value))
    });
    let other =
        ace_gui::ObservableAction::new("y", "Y", |_| Some("//evil.example.com/".to_owned()));
    let actions = ObservableActions::empty().with(hostile).with(other);
    assert!(
        actions
            .links(tree.alert.summary.id, &tree.observables[0])
            .is_empty()
    );
    assert_eq!(
        ace_gui::actions::encode("a b/<c>é"),
        "a%20b%2F%3Cc%3E%C3%A9"
    );
}

/// Add Comment's form: the action's page under `alert:read`, and its post under `observable:write`, which
/// comments on the observable, audits it and goes back to the observable in the tree.
#[tokio::test]
async fn add_comment_comments_on_the_observable() {
    let stack = stack().await;
    let alice = user(&stack, "alice").await;
    grant_alert_read(&stack, &alice).await;
    let carol = user(&stack, "carol").await;
    grant_alert_read(&stack, &carol).await;
    let _bob = user(&stack, "bob").await;
    let (root, fqdn) = splunk_alert(&stack).await;
    let alice_session = session_of(&stack, "alice").await;
    let alert = stack
        .get(&format!("/alerts/{root}"))
        .header("cookie", cookie(&alice_session))
        .send()
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    let path = format!("/alerts/{root}/observables/{}/comment", fqdn.0);
    assert!(
        alert.contains(&format!(r#"<a href="{path}">Add Comment</a>"#)),
        "{alert}"
    );

    let form = stack
        .get(&path)
        .header("cookie", cookie(&alice_session))
        .send()
        .await
        .expect("answered");
    assert_eq!(form.status(), StatusCode::OK);
    let form = form.text().await.expect("a page");
    assert!(inline_free(&form));
    contains_all(
        &form,
        &[
            &format!(r#"<form method="post" action="{path}" class="section">"#),
            r#"<b class="type">fqdn</b> : <span class="value">www.example.com</span>"#,
            r#"<textarea id="comment-field" name="comment" rows="4" required></textarea>"#,
        ],
    );

    // alice can read the alert but not comment
    let audits = stack.audit_count().await;
    let refused = stack
        .post(&path, &[("comment", "seen <b>before</b>")])
        .header("cookie", cookie(&alice_session))
        .send()
        .await
        .expect("answered");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(stack.audit_count().await, audits);

    let Actor::User { id, .. } = &carol else {
        panic!("a user")
    };
    stack
        .service
        .grant(
            &bootstrap(),
            &Holder::User(*id),
            &PermissionPattern::new("observable", "write").expect("a pattern"),
            Effect::Allow,
        )
        .await
        .expect("granted");
    let carol_session = session_of(&stack, "carol").await;
    let bob_session = session_of(&stack, "bob").await;
    let audits = stack.audit_count().await;
    let added = stack
        .post(&path, &[("comment", "seen <b>before</b>")])
        .header("cookie", cookie(&carol_session))
        .send()
        .await
        .expect("answered");
    assert_eq!(added.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&added), format!("/alerts/{root}#o{}", fqdn.0));
    assert_eq!(stack.audit_count().await, audits + 1);
    let page = stack
        .get(&format!("/alerts/{root}"))
        .header("cookie", cookie(&carol_session))
        .send()
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(
        page.contains(": seen &#60;b&#62;before&#60;/b&#62;</li>"),
        "{page}"
    );

    // an empty comment, a form that isn't one, no such observable, another site, no alert:read and no session
    let empty = stack
        .post(&path, &[("comment", "  ")])
        .header("cookie", cookie(&carol_session))
        .send()
        .await
        .expect("answered");
    assert_eq!(empty.status(), StatusCode::BAD_REQUEST);
    let incomplete = stack
        .post(&path, &[("other", "x")])
        .header("cookie", cookie(&carol_session))
        .send()
        .await
        .expect("answered");
    assert_eq!(incomplete.status(), StatusCode::BAD_REQUEST);
    for missing in [
        format!("/alerts/{root}/observables/999999/comment"),
        format!("/alerts/{root}/observables/x/comment"),
    ] {
        let response = stack
            .post(&missing, &[("comment", "x")])
            .header("cookie", cookie(&carol_session))
            .send()
            .await
            .expect("answered");
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{missing}");
    }
    let cross_site = stack
        .post(&path, &[("comment", "x")])
        .header("cookie", cookie(&carol_session))
        .header("sec-fetch-site", "cross-site")
        .send()
        .await
        .expect("answered");
    assert_eq!(cross_site.status(), StatusCode::FORBIDDEN);
    let unreadable = stack
        .get(&path)
        .header("cookie", cookie(&bob_session))
        .send()
        .await
        .expect("answered");
    assert_eq!(unreadable.status(), StatusCode::FORBIDDEN);
    let anonymous = stack
        .post(&path, &[("comment", "x")])
        .send()
        .await
        .expect("answered");
    assert_eq!(anonymous.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&anonymous), "/login");
    assert_eq!(stack.audit_count().await, audits + 1);
}

// PLAN.md 5.10: the alert list.

use ace_gui::list::{AlertListFragment, alert_list};
use ace_service::filters::FilterScreen;
use ace_service::{AlertPage as ListedPage, FilterEntry, ManageColumnsPreference};

/// An alert for the list, made an alert at `alerted`, with an optional disposition.
async fn list_alert(
    stack: &Stack,
    title: &str,
    alerted: &str,
    disposition: Option<&str>,
) -> uuid::Uuid {
    let root = ace_core::tree::NewRoot {
        description: title.to_owned(),
        ..ace_core::tree::NewRoot::new("correlation")
    };
    let db = stack.test_db.db();
    let mut tx = db.begin().await.expect("begins");
    ace_core::tree::create_root(&mut tx, &root)
        .await
        .expect("creates");
    tx.commit().await.expect("commits");
    sqlx::query(
        "UPDATE analysis.roots SET alerted_at = $2::timestamptz, disposition = $3,
                dispositioned_at = CASE WHEN $3 IS NULL THEN NULL ELSE now() END,
                dispositioned_by = CASE WHEN $3 IS NULL THEN NULL
                                   ELSE '{\"kind\": \"internal\", \"id\": \"test\"}'::jsonb END
         WHERE id = $1",
    )
    .bind(root.id)
    .bind(alerted)
    .bind(disposition)
    .execute(db.pool())
    .await
    .expect("an alert");
    root.id
}

fn fixture_summary(id: uuid::Uuid, title: &str, disposition: Option<&str>) -> AlertSummary {
    AlertSummary {
        disposition: disposition.map(str::to_owned),
        ..summary(id, title)
    }
}

/// The page's rows' ids, in order.
fn row_ids(page: &str) -> Vec<String> {
    page.split("id=\"alert-row-")
        .skip(1)
        .filter_map(|rest| rest.split('"').next())
        .map(str::to_owned)
        .collect()
}

/// The view function draws a page of alerts the service read: the viewer's columns in their order, the
/// headers that sort, the filter chips with links that remove them, the pager and the exports, every value
/// escaped, and nothing inline.
#[test]
fn the_list_view_draws_a_page_of_alerts() {
    let (one, two) = (uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2));
    let page = ListedPage {
        alerts: vec![
            fixture_summary(one, HOSTILE, None),
            fixture_summary(two, "second", Some("FALSE_POSITIVE")),
        ],
        next: Some(format!("alert_date.desc.{two}")),
        total: 3,
    };
    let query = ListQuery {
        filters: vec![
            FilterEntry::text("Description", false, &[HOSTILE]),
            FilterEntry::text("Disposition", true, &["IGNORE", "DELIVERY"]),
        ],
        after: Some(format!("alert_date.desc.{}", uuid::Uuid::from_u128(9))),
        ..ListQuery::default()
    };
    let columns = ace_service::PreferenceKey::ManageColumns
        .parse(serde_json::json!({"order": ["disposition", "description"], "hidden": ["status"]}))
        .expect("a value");
    let ace_service::PreferenceValue::ManageColumns(columns) = columns else {
        panic!("manage_columns");
    };
    let view = list_view(
        &page,
        &query,
        &columns,
        &[],
        &std::collections::HashMap::new(),
        chrono_tz::Tz::UTC,
        vec!["a <warning>".to_owned()],
        None,
    );
    let ids: Vec<&str> = view.list.headers.iter().map(|header| header.id).collect();
    assert_eq!(
        ids,
        ["disposition", "description", "date"],
        "the viewer's order, status hidden"
    );
    assert_eq!(view.chips.len(), 2);
    assert!(view.chips[1].inverted);
    let html = ListPage {
        layout: Layout::new("n0nce", Theme::Light, Some("alice".to_owned()), "/"),
        list: view.list.clone(),
        view: view.clone(),
    }
    .render()
    .expect("renders");
    assert!(!html.contains("<script>alert"), "{html}");
    assert!(!html.contains("<img"), "{html}");
    assert!(!html.contains("<warning>"));
    // the hostile title's handler is text: every_template_escapes_html checks the templates themselves
    assert!(!html.contains("style="), "{html}");
    assert_eq!(row_ids(&html), [one.to_string(), two.to_string()]);
    // the disposition links narrow the list to it, the title to the alert
    assert!(html.contains(&format!(r#"<a href="/alerts/{one}">"#)));
    assert!(html.contains(">OPEN</a>") && html.contains(">FALSE_POSITIVE</a>"));
    // the pager: the first page, since this isn't it, and the next
    let next = view.list.next.as_deref().expect("a next page");
    assert!(
        next.contains(&format!("after=alert_date.desc.{two}")),
        "{next}"
    );
    assert!(
        view.list
            .first
            .as_deref()
            .is_some_and(|first| !first.contains("after="))
    );
    // a chip's link removes it and keeps the other
    let remove = &view.chips[0].remove;
    assert!(
        !remove.contains("description") && remove.contains("disposition"),
        "{remove}"
    );
    // the refresh reads the same list, and the export the same filters in the viewer's zone
    assert!(
        view.refresh.starts_with("/alerts/list?f=description"),
        "{}",
        view.refresh
    );
    assert!(view.refresh.contains("after="));
    assert!(
        view.export_csv
            .starts_with("/api/alerts/v1/alerts/export/csv?f=")
    );
    assert!(view.export_csv.ends_with("tz=UTC"));
    // the refresh's expression is fixed text, its URL an attribute
    assert!(
        html.contains(
            r#"data-on-interval__duration.30s="!document.hidden && @get(el.dataset.refresh)""#
        ),
        "{html}"
    );
    // a sorted header toggles its direction
    let date = view
        .list
        .headers
        .iter()
        .find(|h| h.id == "date")
        .expect("date");
    assert_eq!(date.arrow, "↓");
    assert!(
        date.href
            .as_deref()
            .is_some_and(|href| href.contains("dir=asc"))
    );

    // the fragment a refresh sends is the table alone, with the id Datastar morphs by
    let fragment = AlertListFragment {
        list: alert_list(&page, &query, &columns, chrono_tz::Tz::UTC),
    }
    .render()
    .expect("renders");
    assert!(
        fragment.starts_with("<div id=\"alert-list\">"),
        "{fragment}"
    );
    assert!(
        html.contains(&fragment),
        "the page includes the same fragment"
    );
}

/// The Done check's GUI half: the list filters and pages through fixture alerts read from Postgres by the
/// service, through the server, its editor's form folding a filter into the URL, and its refresh sending
/// the same list as a fragment.
#[tokio::test]
async fn the_list_filters_and_pages_through_fixture_alerts() {
    let stack = stack().await;
    let alice = user(&stack, "alice").await;
    grant_alert_read(&stack, &alice).await;
    let session = session_of(&stack, "alice").await;
    let mut made = Vec::new();
    for n in 0..5 {
        let disposition = (n % 2 == 1).then_some("FALSE_POSITIVE");
        made.push(
            list_alert(
                &stack,
                &format!("fixture {n}"),
                &format!("2026-01-0{}T10:00:00Z", n + 1),
                disposition,
            )
            .await,
        );
    }
    let get = |path: String| {
        let request = stack.get(&path).header("cookie", cookie(&session));
        async move {
            let response = request.send().await.expect("answered");
            let status = response.status();
            (status, response.text().await.expect("a page"))
        }
    };
    let ids = |list: &[uuid::Uuid]| list.iter().map(|id| id.to_string()).collect::<Vec<_>>();

    // every alert, newest first, two at a time
    let mut seen = Vec::new();
    let mut path = "/?size=2".to_owned();
    loop {
        let (status, page) = get(path.clone()).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert!(page.contains("5 alerts"), "{page}");
        seen.extend(row_ids(&page));
        let Some(next) = page
            .split(r#"rel="next""#)
            .next()
            .and_then(|before| before.rsplit("href=\"").next())
            .filter(|_| page.contains(r#"rel="next""#))
        else {
            break;
        };
        path = next
            .split('"')
            .next()
            .expect("a link")
            .replace("&#38;", "&");
        assert!(seen.len() <= 5, "paging ends");
    }
    let newest: Vec<uuid::Uuid> = made.iter().rev().copied().collect();
    assert_eq!(seen, ids(&newest));

    // a filter, as a share link writes it
    let (_, page) = get("/?f=disposition:OPEN".to_owned()).await;
    assert_eq!(row_ids(&page), ids(&[made[4], made[2], made[0]]));
    let (_, page) = get("/?f=!disposition:OPEN&sort=description&dir=asc".to_owned()).await;
    assert_eq!(row_ids(&page), ids(&[made[1], made[3]]));
    // the editor's form folds a filter into the URL and comes back to it
    let response = stack
        .get("/?f=disposition:OPEN&add=description&value=fixture%204")
        .header("cookie", cookie(&session))
        .send()
        .await
        .expect("answered");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let to = location(&response).to_owned();
    assert_eq!(to, "/?f=disposition%3AOPEN&f=description%3Afixture%25204");
    let (_, page) = get(to).await;
    assert_eq!(row_ids(&page), ids(&[made[4]]));
    // a filter the list doesn't have is left out, saying so; a broken one shows the list without filters
    let (status, page) = get("/?f=queue:default".to_owned()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("alert routing (7.13)"), "{page}");
    assert_eq!(row_ids(&page).len(), 5);
    let (status, page) = get("/?f=tag:a,,b".to_owned()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("That filter couldn"), "{page}");
    assert_eq!(row_ids(&page).len(), 5);
    let (status, _) = get("/?sort=owner".to_owned()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // the refresh sends the same list as its fragment, and a request with no session gets 401
    let (status, fragment) = get("/alerts/list?f=disposition:OPEN".to_owned()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        fragment.starts_with("<div id=\"alert-list\">"),
        "{fragment}"
    );
    assert!(!fragment.contains("<html"));
    assert_eq!(row_ids(&fragment), ids(&[made[4], made[2], made[0]]));
    let anonymous = stack
        .get("/alerts/list")
        .header("datastar-request", "true")
        .send()
        .await
        .expect("answered");
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    // a viewer without alert:read sees no list
    let _bob = user(&stack, "bob").await;
    let bob = session_of(&stack, "bob").await;
    let refused = stack
        .get("/")
        .header("cookie", cookie(&bob))
        .send()
        .await
        .expect("answered");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
}

/// ace3's bulk "Set Disposition": each ticked alert through the service on its own, with its permission
/// and its audit row, and the page says which it did and which it couldn't.
#[tokio::test]
async fn a_bulk_disposition_is_each_alert_s_own_write() {
    let stack = stack().await;
    let alice = user(&stack, "alice").await;
    grant_alert_read(&stack, &alice).await;
    let session = session_of(&stack, "alice").await;
    let one = list_alert(&stack, "one", "2026-01-01T10:00:00Z", None).await;
    let two = list_alert(&stack, "two", "2026-01-02T10:00:00Z", None).await;
    let post = |form: Vec<(&'static str, String)>| {
        let request = stack
            .http
            .post(format!("{}/alerts/disposition", stack.url))
            .header("origin", &stack.url)
            .header("cookie", cookie(&session))
            .form(&form);
        async move { request.send().await.expect("answered") }
    };
    let form = |ids: &[String]| {
        let mut form = vec![
            ("disposition", "FALSE_POSITIVE".to_owned()),
            ("next", "/?f=disposition:OPEN".to_owned()),
        ];
        form.extend(ids.iter().map(|id| ("alert", id.clone())));
        form
    };
    // without alert:write, each is refused and nothing changes
    let audit = stack.audit_count().await;
    let refused = post(form(&[one.to_string(), two.to_string()])).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let page = refused.text().await.expect("a page");
    assert!(page.contains("0 alerts dispositioned, 2 not"), "{page}");
    assert!(page.contains("alert:write"), "{page}");
    assert_eq!(stack.audit_count().await, audit);

    let Actor::User { id, .. } = &alice else {
        panic!("a user")
    };
    stack
        .service
        .grant(
            &bootstrap(),
            &Holder::User(*id),
            &PermissionPattern::new("alert", "write").expect("a pattern"),
            Effect::Allow,
        )
        .await
        .expect("grants");
    let audit = stack.audit_count().await;
    let missing = uuid::Uuid::from_u128(77);
    let done = post(form(&[
        one.to_string(),
        two.to_string(),
        missing.to_string(),
        "x".to_owned(),
    ]))
    .await;
    assert_eq!(done.status(), StatusCode::OK);
    let page = done.text().await.expect("a page");
    assert!(page.contains("2 alerts dispositioned, 2 not"), "{page}");
    assert!(page.contains(&format!("{missing}: it couldn")), "{page}");
    assert!(
        page.contains(r#"<a href="/?f=disposition:OPEN">Back to the list</a>"#),
        "{page}"
    );
    assert!(inline_free(&page));
    assert_eq!(stack.audit_count().await, audit + 2, "a row for each alert");
    let dispositions: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT disposition FROM analysis.roots WHERE id = ANY($1) ORDER BY alerted_at",
    )
    .bind(vec![one, two])
    .fetch_all(stack.test_db.db().pool())
    .await
    .expect("reads");
    assert_eq!(
        dispositions,
        [
            Some("FALSE_POSITIVE".to_owned()),
            Some("FALSE_POSITIVE".to_owned())
        ]
    );

    // a disposition of the wrong shape, none ticked, or too many, is refused whole
    for bad in [
        vec![
            ("disposition", "not one".to_owned()),
            ("alert", one.to_string()),
        ],
        vec![("disposition", "IGNORE".to_owned())],
        std::iter::once(("disposition", "IGNORE".to_owned()))
            .chain((0..=ace_gui::list::MAX_BULK).map(|_| ("alert", one.to_string())))
            .collect(),
    ] {
        let response = post(bad).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    // and another site can't post it
    let cross = stack
        .http
        .post(format!("{}/alerts/disposition", stack.url))
        .header("origin", "https://evil.example")
        .header("cookie", cookie(&session))
        .form(&[("disposition", "IGNORE"), ("alert", &one.to_string())])
        .send()
        .await
        .expect("answered");
    assert_eq!(cross.status(), StatusCode::FORBIDDEN);
    assert_eq!(stack.audit_count().await, audit + 2);
}

/// The saved filter forms and the column chooser write through the service, and the list draws what they
/// wrote: a quick filter's badge with its count, and the columns in their new order.
#[tokio::test]
async fn saved_filters_and_columns_are_forms() {
    let stack = stack().await;
    let alice = user(&stack, "alice").await;
    grant_alert_read(&stack, &alice).await;
    let session = session_of(&stack, "alice").await;
    list_alert(&stack, "open one", "2026-01-01T10:00:00Z", None).await;
    list_alert(&stack, "closed one", "2026-01-02T10:00:00Z", Some("IGNORE")).await;
    let post = |path: &str, form: Vec<(&str, &str)>| {
        let request = stack.post(path, &form).header("cookie", cookie(&session));
        async move { request.send().await.expect("answered") }
    };
    let saved = post(
        "/filters/saved",
        vec![
            ("name", "Open <b>ones</b>"),
            ("f", "disposition:OPEN"),
            ("quick", "on"),
            ("indicator", "on"),
            ("next", "/?f=disposition:OPEN"),
        ],
    )
    .await;
    assert_eq!(saved.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&saved), "/?f=disposition:OPEN");
    let again = post(
        "/filters/saved",
        vec![("name", "Open <b>ones</b>"), ("f", "disposition:OPEN")],
    )
    .await;
    assert_eq!(again.status(), StatusCode::CONFLICT);
    let page = stack
        .get("/?f=disposition:OPEN")
        .header("cookie", cookie(&session))
        .send()
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(
        page.contains(r#"<a class="badge current" href="/?f=disposition%3AOPEN">Open &#60;b&#62;ones&#60;/b&#62; <span class="count">1</span></a>"#),
        "{page}"
    );
    let filters = stack
        .service
        .saved_filters(&alice, FilterScreen::Alerts)
        .await
        .expect("lists");
    let id = filters[0].id.to_string();
    let unpinned = post(
        &format!("/filters/saved/{id}/quick"),
        vec![("pin", "false"), ("next", "/")],
    )
    .await;
    assert_eq!(unpinned.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        stack
            .service
            .saved_filters(&alice, FilterScreen::Alerts)
            .await
            .expect("lists")[0]
            .quick_filter_order,
        None
    );
    let deleted = post(&format!("/filters/saved/{id}/delete"), vec![("next", "/")]).await;
    assert_eq!(deleted.status(), StatusCode::SEE_OTHER);
    assert!(
        stack
            .service
            .saved_filters(&alice, FilterScreen::Alerts)
            .await
            .expect("lists")
            .is_empty()
    );

    // the columns: move the disposition first, hide the date, and reset
    for (column, action) in [
        ("disposition", "up"),
        ("disposition", "up"),
        ("date", "hide"),
    ] {
        let moved = post(
            "/preferences/manage-columns",
            vec![("column", column), ("action", action), ("next", "/")],
        )
        .await;
        assert_eq!(moved.status(), StatusCode::SEE_OTHER);
    }
    let columns = stack.service.manage_columns(&alice).await.expect("reads");
    assert_eq!(
        columns.order,
        ["disposition", "date", "description", "status"]
    );
    assert_eq!(columns.hidden, ["date"]);
    let page = stack
        .get("/")
        .header("cookie", cookie(&session))
        .send()
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    let headers: Vec<&str> = page
        .split("<th data-col-id=\"")
        .skip(1)
        .filter_map(|rest| rest.split('"').next())
        .collect();
    assert_eq!(headers, ["disposition", "description", "status"]);
    for bad in [
        vec![("column", "queue"), ("action", "up")],
        vec![("column", "date"), ("action", "drag")],
    ] {
        assert_eq!(
            post("/preferences/manage-columns", bad).await.status(),
            StatusCode::BAD_REQUEST
        );
    }
    let reset = post(
        "/preferences/manage-columns",
        vec![("action", "reset"), ("next", "/")],
    )
    .await;
    assert_eq!(reset.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        stack.service.manage_columns(&alice).await.expect("reads"),
        ManageColumnsPreference::default()
    );
}

/// The refresh is bounded as 5.8's stream is: past its places, in all or for one user, it answers 503 and
/// the page stays as it was, and a refresh holds its place only while it runs.
#[tokio::test]
async fn list_refreshes_are_bounded() {
    let stack =
        stack_from(|service| Gui::new(service, Transport::Plain).with_refresh_limits(4, 1)).await;
    let alice = user(&stack, "alice").await;
    grant_alert_read(&stack, &alice).await;
    let session = session_of(&stack, "alice").await;
    list_alert(&stack, "one", "2026-01-01T10:00:00Z", None).await;
    // a lock holds the first refresh's read, so it keeps its place
    let mut locker = stack.test_db.db().pool().begin().await.expect("begins");
    sqlx::query("LOCK TABLE analysis.roots IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *locker)
        .await
        .expect("locks");
    let refresh = || {
        stack
            .get("/alerts/list")
            .header("cookie", cookie(&session))
            .header("datastar-request", "true")
            .send()
    };
    let held = tokio::spawn(refresh());
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let refused = refresh().await.expect("answered");
    assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
    locker.rollback().await.expect("unlocks");
    let first = held.await.expect("joins").expect("answered");
    assert_eq!(first.status(), StatusCode::OK);
    // the place went back
    assert_eq!(refresh().await.expect("answered").status(), StatusCode::OK);
}

// ---- PLAN.md 5.11's preferences area ----

use ace_gui::preferences::{KeyDraft, KeyPage, NewKeyPage, PreferencesPage, preferences_view};
use ace_service::{ApiKey, ApiKeyId, CATALOG, Grant, User};

fn fixture_user(name: &str) -> User {
    User {
        id: ace_service::UserId(uuid::Uuid::from_u128(1)),
        username: name.to_owned(),
        display_name: Some(name.to_owned()),
        email: Some(name.to_owned()),
        timezone: "America/New_York".to_owned(),
        enabled: true,
        created_at: chrono::DateTime::from_timestamp(1_793_000_000, 0).expect("a time"),
        api_keys: 2,
    }
}

fn fixture_key(id: u128, name: &str, grants: &[(&str, &str, Effect)]) -> ApiKey {
    ApiKey {
        id: ApiKeyId(uuid::Uuid::from_u128(id)),
        name: name.to_owned(),
        owner: Some(ace_service::UserId(uuid::Uuid::from_u128(1))),
        grants: grants
            .iter()
            .enumerate()
            .map(|(at, (major, minor, effect))| Grant {
                id: at as i64,
                major: (*major).to_owned(),
                minor: (*minor).to_owned(),
                effect: *effect,
            })
            .collect(),
        // 2026-10-26 12:53:20 UTC, 08:53 in New York
        created_at: chrono::DateTime::from_timestamp(1_793_019_200, 0).expect("a time"),
        created_by: RecordedActor {
            kind: "user".to_owned(),
            id: "1".to_owned(),
            name: Some("alice".to_owned()),
        },
    }
}

fn catalog_entries(names: &[&str]) -> Vec<&'static ace_service::CatalogEntry> {
    CATALOG
        .iter()
        .filter(|entry| names.contains(&entry.name.to_string().as_str()))
        .collect()
}

/// The preferences page's view functions, called directly: the profile with what 5.6 lets a user change,
/// the theme, the column chooser coming back here, and the keys with what `user:self` allows, with every
/// outside value escaped and nothing inline.
#[test]
fn the_preferences_view_draws_the_profile_theme_columns_and_keys() {
    let user = fixture_user("alice");
    let keys = [
        fixture_key(0xA, "triage", &[("alert", "read", Effect::Allow)]),
        fixture_key(0xB, "everything", &[("*", "*", Effect::Allow)]),
        fixture_key(
            0xC,
            "scoped",
            &[
                ("signature", "*", Effect::Allow),
                ("signature", "download", Effect::Deny),
            ],
        ),
    ];
    let held = catalog_entries(&["alert:read", "signature:read"]);
    let layout = || {
        Layout::new(
            "n0nce",
            Theme::Dark,
            Some("alice".to_owned()),
            "/preferences",
        )
    };
    let page = PreferencesPage {
        layout: layout(),
        view: preferences_view(
            &user,
            &keys,
            &held,
            true,
            &ace_service::ManageColumnsPreference::default(),
        ),
    }
    .render()
    .expect("renders");
    for part in [
        r#"<form method="post" action="/preferences/profile" class="fields">"#,
        r#"<input id="profile-username" type="text" value="alice" disabled>"#,
        r#"<input id="profile-email" type="text" value="alice" disabled>"#,
        r#"name="display_name" value="alice""#,
        r#"<option value="America/New_York" selected>America/New_York</option>"#,
        r#"<option value="Europe/London">Europe/London</option>"#,
        r#"<a href="/login/change">Change password</a>"#,
        r#"<a href="/preferences">Preferences</a>"#,
        r#"<input type="radio" name="mode" value="dark" checked> Dark"#,
        r#"<input type="radio" name="mode" value="light"> Light"#,
        r#"<form method="post" action="/preferences/manage-columns" class="inline">"#,
        r#"<input type="hidden" name="next" value="/preferences">"#,
        "<td>triage</td>",
        "<code>alert:read</code>",
        "<code>*:*</code>",
        "<code>signature:*</code>, <code>deny signature:download</code>",
        "2026-10-26 08:53 EDT",
        r#"<a href="/preferences/keys/00000000-0000-0000-0000-00000000000a">Edit</a>"#,
        r#"<a href="/preferences/keys/00000000-0000-0000-0000-00000000000c">Edit</a>"#,
        r#"action="/preferences/keys/00000000-0000-0000-0000-00000000000b/revoke""#,
        r#"<form method="post" action="/preferences/keys" class="fields">"#,
        r#"<input type="checkbox" name="scope" value="alert:read"> <code>alert:read</code>"#,
        r#"<input type="checkbox" name="scope" value="signature:read"> <code>signature:read</code>"#,
        r#"<textarea id="key-other" name="other""#,
    ] {
        assert!(page.contains(part), "{part}: {page}");
    }
    // the email is shown, not sent; a *:* key isn't edited here; only held permissions are offered
    assert!(!page.contains(r#"name="email""#), "{page}");
    assert!(!page.contains("00000000000b\">Edit"), "{page}");
    assert!(!page.contains(r#"value="user:self""#), "{page}");
    assert!(!page.contains(r#"value="alert:write""#), "{page}");
    assert_eq!(
        page.matches("<option value=").count(),
        chrono_tz::TZ_VARIANTS.len() + Theme::ALL.len(),
        "every chrono-tz timezone, and the menu's themes"
    );
    assert!(!page.contains(r#"role="alert""#), "{page}");
    assert!(inline_free(&page), "{page}");

    // without user:self the keys are listed, with no control to change them
    let page = PreferencesPage {
        layout: layout(),
        view: preferences_view(
            &user,
            &keys,
            &held,
            false,
            &ace_service::ManageColumnsPreference::default(),
        ),
    }
    .render()
    .expect("renders");
    assert!(page.contains("<td>triage</td>"), "{page}");
    assert!(!page.contains("/revoke"), "{page}");
    assert!(!page.contains(">Edit</a>"), "{page}");
    assert!(!page.contains(r#"action="/preferences/keys""#), "{page}");
    assert!(page.contains("Ask an administrator to make or change your API keys."));
    let page = PreferencesPage {
        layout: layout(),
        view: preferences_view(
            &user,
            &[],
            &held,
            true,
            &ace_service::ManageColumnsPreference::default(),
        ),
    }
    .render()
    .expect("renders");
    assert!(page.contains("You have no API keys."), "{page}");

    // hostile text in every outside value
    let escaped = "&#34;&#62;&#60;script&#62;alert(&#39;x&#39;)&#60;/script&#62;&#60;img src=x \
                   onerror=alert(1)&#62;&#38;amp;";
    let hostile_user = fixture_user(HOSTILE);
    let hostile_keys = [fixture_key(
        0xA,
        HOSTILE,
        &[("alert", "read", Effect::Allow)],
    )];
    let mut view = preferences_view(
        &hostile_user,
        &hostile_keys,
        &held,
        true,
        &ace_service::ManageColumnsPreference::default(),
    );
    view.profile_problem = Some(HOSTILE.to_owned());
    view.key_problem = Some(HOSTILE.to_owned());
    view.draft = KeyDraft {
        name: HOSTILE.to_owned(),
        ticked: vec![],
        other: HOSTILE.to_owned(),
    };
    let page = PreferencesPage {
        layout: layout(),
        view,
    }
    .render()
    .expect("renders");
    assert!(!page.contains("<script>alert"), "{page}");
    assert!(!page.contains("<img"), "{page}");
    // username, email and display name; the key's name; two problems; the draft's name and patterns
    assert_eq!(page.matches(escaped).count(), 8, "{page}");
    assert!(page.contains(&format!(r#"<p class="error" role="alert">{escaped}</p>"#)));
    // the hostile text has " onerror=" in it, escaped, so the page's own markup is checked without it
    assert!(inline_free(&page.replace(escaped, "")), "{page}");

    let key = KeyPage {
        layout: layout(),
        id: uuid::Uuid::from_u128(0xC),
        offered: ace_gui::preferences::offered(&held, &["signature:read".to_owned()]),
        draft: KeyDraft {
            name: HOSTILE.to_owned(),
            ticked: vec!["signature:read".to_owned()],
            other: HOSTILE.to_owned(),
        },
        denies: vec!["signature:download".to_owned()],
        problem: Some(HOSTILE.to_owned()),
    }
    .render()
    .expect("renders");
    for part in [
        r#"<form method="post" action="/preferences/keys/00000000-0000-0000-0000-00000000000c" class="fields">"#,
        r#"<input type="checkbox" name="scope" value="signature:read" checked>"#,
        r#"<input type="checkbox" name="scope" value="alert:read"> "#,
        "denies this key <code>signature:download</code>",
    ] {
        assert!(key.contains(part), "{part}: {key}");
    }
    assert_eq!(key.matches(escaped).count(), 3, "{key}");
    assert!(!key.contains("<script>alert"), "{key}");
    // the hostile text has " onerror=" in it, escaped, so the page's own markup is checked without it
    assert!(inline_free(&key.replace(escaped, "")), "{key}");

    let made = NewKeyPage {
        layout: layout(),
        name: HOSTILE.to_owned(),
        token: "ace4k_the-token".to_owned(),
    };
    assert!(!format!("{made:?}").contains("the-token"), "Debug hides it");
    let made = made.render().expect("renders");
    assert!(
        made.contains(
            r#"<input id="new-key" class="token" type="text" value="ace4k_the-token" readonly"#
        ),
        "{made}"
    );
    assert_eq!(made.matches(escaped).count(), 1, "{made}");
    assert!(inline_free(&made.replace(escaped, "")), "{made}");
}

async fn grant_to(stack: &Stack, actor: &Actor, major: &str, minor: &str) {
    let Actor::User { id, .. } = actor else {
        panic!("a user");
    };
    stack
        .service
        .grant(
            &bootstrap(),
            &Holder::User(*id),
            &PermissionPattern::new(major, minor).expect("a pattern"),
            Effect::Allow,
        )
        .await
        .expect("grants");
}

async fn last_action(stack: &Stack) -> String {
    sqlx::query_scalar("SELECT action FROM service.audit ORDER BY id DESC LIMIT 1")
        .fetch_one(stack.test_db.db().pool())
        .await
        .expect("a row")
}

/// The page and its profile form through the server: signed out goes to the login, the page reads the
/// user's own account, a save writes through `update_own_profile` with its audit row, and each refusal,
/// a cross-site post among them, changes nothing. An email in the form is ignored, as 5.6 leaves it to an
/// administrator.
#[tokio::test]
async fn the_preferences_page_saves_the_profile() {
    let stack = stack().await;
    let alice = user(&stack, "alice").await;
    let page = stack.get("/preferences").send().await.expect("answered");
    assert_eq!(page.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&page), "/login?next=%2Fpreferences");
    let post = stack
        .post(
            "/preferences/profile",
            &[("display_name", "Alice"), ("timezone", "UTC")],
        )
        .send()
        .await
        .expect("answered");
    assert_eq!(post.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&post), "/login");

    let session = session_of(&stack, "alice").await;
    let page = stack
        .get("/preferences")
        .header("cookie", cookie(&session))
        .send()
        .await
        .expect("answered");
    assert_eq!(page.status(), StatusCode::OK);
    let page = page.text().await.expect("a page");
    assert!(
        page.contains(r#"<option value="UTC" selected>UTC</option>"#),
        "{page}"
    );
    assert!(page.contains("Ask an administrator to make or change your API keys."));

    let audit = stack.audit_count().await;
    let profile = |form: &[(&str, &str)]| {
        stack
            .post("/preferences/profile", form)
            .header("cookie", cookie(&session))
    };
    for (what, request, status, says) in [
        (
            "a timezone chrono-tz doesn't know",
            profile(&[("display_name", "Alice"), ("timezone", "Mars/Olympus_Mons")]),
            StatusCode::BAD_REQUEST,
            "Not saved: &#34;Mars/Olympus_Mons&#34; isn&#39;t an IANA timezone",
        ),
        (
            "a display name with a control character",
            profile(&[("display_name", "Al\u{7}ice"), ("timezone", "UTC")]),
            StatusCode::BAD_REQUEST,
            "Not saved: a display name is up to 1024 characters with no control characters.",
        ),
        (
            "an incomplete form",
            profile(&[("display_name", "Alice")]),
            StatusCode::BAD_REQUEST,
            "The form wasn&#39;t complete.",
        ),
        (
            "a post from another site",
            stack
                .http
                .post(format!("{}/preferences/profile", stack.url))
                .header("origin", "https://evil.example")
                .header("cookie", cookie(&session))
                .form(&[("display_name", "Alice"), ("timezone", "UTC")]),
            StatusCode::FORBIDDEN,
            "this request came from another site",
        ),
    ] {
        let response = request.send().await.expect("answered");
        assert_eq!(response.status(), status, "{what}");
        let page = response.text().await.expect("a page");
        assert!(page.contains(says), "{what}: {page}");
    }
    assert_eq!(stack.audit_count().await, audit, "nothing changed");

    let saved = profile(&[
        ("display_name", "Alice A."),
        ("timezone", "Europe/London"),
        ("email", "alice@evil.example"),
    ])
    .send()
    .await
    .expect("answered");
    assert_eq!(saved.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&saved), "/preferences?done=profile");
    assert_eq!(stack.audit_count().await, audit + 1);
    assert_eq!(last_action(&stack).await, "update_own_profile");
    let account = stack.service.own_account(&alice).await.expect("reads");
    assert_eq!(account.display_name.as_deref(), Some("Alice A."));
    assert_eq!(account.timezone, "Europe/London");
    assert_eq!(account.email, None, "an email isn't the user's to change");
    let page = stack
        .get("/preferences?done=profile")
        .header("cookie", cookie(&session))
        .send()
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(page.contains("Your profile is saved."), "{page}");
    assert!(page.contains(r#"<option value="Europe/London" selected>"#));
    assert!(page.contains(r#"name="display_name" value="Alice A.""#));

    // the theme and the columns come back here
    let themed = stack
        .post(
            "/preferences/theme",
            &[("mode", "jd"), ("next", "/preferences")],
        )
        .header("cookie", cookie(&session))
        .send()
        .await
        .expect("answered");
    assert_eq!(location(&themed), "/preferences");
    let moved = stack
        .post(
            "/preferences/manage-columns",
            &[
                ("column", "description"),
                ("action", "up"),
                ("next", "/preferences"),
            ],
        )
        .header("cookie", cookie(&session))
        .send()
        .await
        .expect("answered");
    assert_eq!(location(&moved), "/preferences");
    let page = stack
        .get("/preferences")
        .header("cookie", cookie(&session))
        .send()
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(page.contains(r#"value="jd" checked"#), "{page}");
}

/// A user's own keys through the server: without `user:self` there's nothing to change and a post is
/// refused; with it a key is made with its token shown once, in an answer no cache keeps and no URL
/// holds, then changed and revoked, each with its audit row. A scope `_check_scope_within_grants` refuses
/// comes back with the service's reason and the form as it was, and each refusal changes nothing.
#[tokio::test]
async fn own_api_keys_are_made_shown_once_changed_and_revoked() {
    let stack = stack().await;
    let alice = user(&stack, "alice").await;
    grant_to(&stack, &alice, "alert", "read").await;
    let session = session_of(&stack, "alice").await;
    let make = |form: &[(&str, &str)]| {
        stack
            .post("/preferences/keys", form)
            .header("cookie", cookie(&session))
    };
    let audit = stack.audit_count().await;
    let refused = make(&[("name", "mine"), ("scope", "alert:read")])
        .send()
        .await
        .expect("answered");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN, "no user:self");
    assert!(refused.text().await.expect("a page").contains("user:self"));
    let page = stack
        .get("/preferences/keys/00000000-0000-0000-0000-00000000000a")
        .header("cookie", cookie(&session))
        .send()
        .await
        .expect("answered");
    assert_eq!(page.status(), StatusCode::FORBIDDEN);
    assert_eq!(stack.audit_count().await, audit);

    grant_to(&stack, &alice, "user", "self").await;
    let audit = stack.audit_count().await;
    let page = stack
        .get("/preferences")
        .header("cookie", cookie(&session))
        .send()
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(page.contains(r#"value="alert:read""#), "{page}");
    assert!(!page.contains(r#"value="user:self""#), "{page}");

    for (what, form, says) in [
        (
            "a pattern covering what alice doesn't hold",
            vec![
                ("name", "mine"),
                ("scope", "alert:read"),
                ("other", "alert:*"),
            ],
            "No key was made: alert:* covers alert:create, alert:write, which you don&#39;t hold.",
        ),
        (
            "a pattern covering nothing",
            vec![("name", "mine"), ("other", "alret:read")],
            "alret:read matches no permission ACE checks",
        ),
        (
            "user:self",
            vec![("name", "mine"), ("other", "user:self")],
            "user:self is only ever a person&#39;s",
        ),
        (
            "no scope",
            vec![("name", "mine")],
            "a key you make yourself has to list the permissions it needs",
        ),
        (
            "text that isn't a pattern",
            vec![("name", "mine"), ("other", "alert")],
            "alert isn&#39;t a pattern, which is major:minor",
        ),
        (
            "no name",
            vec![("name", " "), ("scope", "alert:read")],
            "an API key&#39;s name is 1 to 255 characters",
        ),
    ] {
        let response = make(&form).send().await.expect("answered");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{what}");
        let page = response.text().await.expect("a page");
        assert!(page.contains(says), "{what}: {page}");
        assert!(!page.contains("ace4k_"), "{what}: {page}");
    }
    // the refused form comes back as it was sent
    let page = make(&[
        ("name", "mine"),
        ("scope", "alert:read"),
        ("other", "alert:*"),
    ])
    .send()
    .await
    .expect("answered")
    .text()
    .await
    .expect("a page");
    assert!(page.contains(r#"name="name" value="mine""#), "{page}");
    assert!(page.contains(r#"value="alert:read" checked"#), "{page}");
    assert!(page.contains(">alert:*</textarea>"), "{page}");
    let cross_site = stack
        .http
        .post(format!("{}/preferences/keys", stack.url))
        .header("origin", "https://evil.example")
        .header("cookie", cookie(&session))
        .form(&[("name", "mine"), ("scope", "alert:read")])
        .send()
        .await
        .expect("answered");
    assert_eq!(cross_site.status(), StatusCode::FORBIDDEN);
    let signed_out = stack
        .post(
            "/preferences/keys",
            &[("name", "mine"), ("scope", "alert:read")],
        )
        .send()
        .await
        .expect("answered");
    assert_eq!(location(&signed_out), "/login");
    assert_eq!(stack.audit_count().await, audit, "nothing changed");
    assert!(
        stack
            .service
            .own_api_keys(&alice)
            .await
            .expect("reads")
            .is_empty()
    );

    // made, and shown once
    let made = make(&[("name", "triage"), ("scope", "alert:read")])
        .send()
        .await
        .expect("answered");
    assert_eq!(made.status(), StatusCode::CREATED);
    assert_eq!(made.headers()["cache-control"], "no-store");
    assert!(made.headers().get(LOCATION).is_none(), "no redirect");
    let page = made.text().await.expect("a page");
    let token = page
        .split(r#"class="token" type="text" value=""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("the token")
        .to_owned();
    assert!(token.starts_with("ace4k_"), "{page}");
    assert_eq!(stack.audit_count().await, audit + 1);
    assert_eq!(last_action(&stack).await, "create_own_api_key");
    let as_key = stack
        .service
        .authenticate_api_key(&token)
        .await
        .expect("the token works");
    assert!(
        stack
            .service
            .allowed(&as_key, &ace_service::ALERT_READ)
            .await
            .expect("checks")
    );
    let keys = stack.service.own_api_keys(&alice).await.expect("reads");
    let id = keys[0].id.0;
    let listing = stack
        .get("/preferences")
        .header("cookie", cookie(&session))
        .send()
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(listing.contains("<td>triage</td>"), "{listing}");
    assert!(!listing.contains(&token), "shown once");

    // changed
    let edit = stack
        .get(&format!("/preferences/keys/{id}"))
        .header("cookie", cookie(&session))
        .send()
        .await
        .expect("answered");
    assert_eq!(edit.status(), StatusCode::OK);
    let edit = edit.text().await.expect("a page");
    assert!(edit.contains(r#"name="name" value="triage""#), "{edit}");
    assert!(edit.contains(r#"value="alert:read" checked"#), "{edit}");
    let change = |id: &str, form: &[(&str, &str)]| {
        stack
            .post(&format!("/preferences/keys/{id}"), form)
            .header("cookie", cookie(&session))
    };
    let audit = stack.audit_count().await;
    let refused = change(
        &id.to_string(),
        &[("name", "renamed"), ("other", "alert:*")],
    )
    .send()
    .await
    .expect("answered");
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    let page = refused.text().await.expect("a page");
    assert!(
        page.contains("Not changed: alert:* covers alert:create, alert:write"),
        "{page}"
    );
    assert!(page.contains(r#"name="name" value="renamed""#), "{page}");
    assert_eq!(stack.audit_count().await, audit);
    let changed = change(
        &id.to_string(),
        &[("name", "renamed"), ("scope", "alert:read")],
    )
    .send()
    .await
    .expect("answered");
    assert_eq!(changed.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&changed), "/preferences?done=key");
    assert_eq!(stack.audit_count().await, audit + 1);
    assert_eq!(last_action(&stack).await, "set_own_api_key_scope");
    assert_eq!(
        stack.service.own_api_keys(&alice).await.expect("reads")[0].name,
        "renamed"
    );

    // another user's key isn't there, to alice; an id that isn't a uuid is a bad request
    let bob = user(&stack, "bob").await;
    grant_to(&stack, &bob, "user", "self").await;
    grant_to(&stack, &bob, "alert", "read").await;
    let bobs = stack
        .service
        .create_own_api_key(
            &bob,
            "bob's",
            &[PermissionPattern::new("alert", "read").expect("a pattern")],
        )
        .await
        .expect("makes bob's key")
        .id
        .0
        .to_string();
    let audit = stack.audit_count().await;
    for (what, response, status) in [
        (
            "bob's key's page",
            stack
                .get(&format!("/preferences/keys/{bobs}"))
                .header("cookie", cookie(&session))
                .send()
                .await,
            StatusCode::NOT_FOUND,
        ),
        (
            "changing bob's key",
            change(&bobs, &[("name", "mine now"), ("scope", "alert:read")])
                .send()
                .await,
            StatusCode::NOT_FOUND,
        ),
        (
            "revoking bob's key",
            stack
                .post(&format!("/preferences/keys/{bobs}/revoke"), &[])
                .header("cookie", cookie(&session))
                .send()
                .await,
            StatusCode::NOT_FOUND,
        ),
        (
            "a revoke from another site",
            stack
                .http
                .post(format!("{}/preferences/keys/{id}/revoke", stack.url))
                .header("origin", "https://evil.example")
                .header("cookie", cookie(&session))
                .send()
                .await,
            StatusCode::FORBIDDEN,
        ),
        (
            "an id that isn't a uuid",
            stack
                .post("/preferences/keys/not-a-uuid/revoke", &[])
                .header("cookie", cookie(&session))
                .send()
                .await,
            StatusCode::BAD_REQUEST,
        ),
        (
            "a page for an id that isn't a uuid",
            stack
                .get("/preferences/keys/not-a-uuid")
                .header("cookie", cookie(&session))
                .send()
                .await,
            StatusCode::BAD_REQUEST,
        ),
    ] {
        assert_eq!(response.expect("answered").status(), status, "{what}");
    }
    let signed_out = stack
        .post(&format!("/preferences/keys/{id}/revoke"), &[])
        .send()
        .await
        .expect("answered");
    assert_eq!(location(&signed_out), "/login");
    assert_eq!(stack.audit_count().await, audit, "nothing changed");
    assert_eq!(
        stack.service.own_api_keys(&bob).await.expect("reads")[0].name,
        "bob's"
    );

    // revoked
    let revoked = stack
        .post(&format!("/preferences/keys/{id}/revoke"), &[])
        .header("cookie", cookie(&session))
        .send()
        .await
        .expect("answered");
    assert_eq!(revoked.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&revoked), "/preferences?done=revoked");
    assert_eq!(stack.audit_count().await, audit + 1);
    assert_eq!(last_action(&stack).await, "revoke_own_api_key");
    assert!(stack.service.authenticate_api_key(&token).await.is_err());
    let again = stack
        .post(&format!("/preferences/keys/{id}/revoke"), &[])
        .header("cookie", cookie(&session))
        .send()
        .await
        .expect("answered");
    assert_eq!(again.status(), StatusCode::NOT_FOUND);
}

// PLAN.md 5.11's saved_filters area: ace3's Manage Filters dialog as a page, with rename and the quick
// filters' order.

use ace_gui::saved_filters::{EditPage, FilterDraft, ManagePage, manage_view, moved};
use ace_service::{NewSavedFilter, SavedFilter, UserId};

fn fixture_filter(
    id: u128,
    name: &str,
    description: Option<&str>,
    order: Option<i32>,
) -> SavedFilter {
    let at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .expect("a time")
        .with_timezone(&chrono::Utc);
    SavedFilter {
        id: uuid::Uuid::from_u128(id),
        screen: FilterScreen::Alerts,
        name: name.to_owned(),
        description: description.map(str::to_owned),
        filters: vec![FilterEntry::text("Disposition", false, &["OPEN"])],
        quick_filter_order: order,
        quick_filter_indicator: order == Some(0),
        owner: UserId(uuid::Uuid::from_u128(99)),
        owner_name: "alice".to_owned(),
        created_at: at,
        updated_at: at,
    }
}

/// The view functions draw the user's saved filters: the quick filters numbered in their order, each with
/// Up and Down forms but at its end, the rest with Pin, every row's Open, Rename and Delete, every value
/// escaped and nothing inline. A move swaps a place, stops at either end, and refuses a filter that isn't a
/// quick filter.
#[test]
fn the_saved_filters_views_draw_the_order_and_the_rename_form() {
    let saved = [
        fixture_filter(1, "First", None, Some(0)),
        fixture_filter(2, HOSTILE, Some(HOSTILE), Some(1)),
        fixture_filter(3, "Unpinned", None, None),
    ];
    let back = "/?f=disposition%3AOPEN";
    let view = manage_view(&saved, back);
    assert_eq!(
        view.rows.iter().map(|row| row.place).collect::<Vec<_>>(),
        [Some(1), Some(2), None]
    );
    assert_eq!(
        view.here,
        "/filters/saved?next=%2F%3Ff%3Ddisposition%253AOPEN"
    );
    assert_eq!(
        view.rows[2].rename,
        format!(
            "/filters/saved/{}?next=%2F%3Ff%3Ddisposition%253AOPEN",
            uuid::Uuid::from_u128(3)
        )
    );
    assert_eq!(view.rows[0].href, "/?f=disposition%3AOPEN");
    let page = ManagePage {
        layout: Layout::new(
            "n",
            Theme::default(),
            Some("alice".to_owned()),
            "/filters/saved",
        ),
        view,
    }
    .render()
    .expect("renders");
    let escaped = "&#34;&#62;&#60;script&#62;alert(&#39;x&#39;)&#60;/script&#62;&#60;img src=x \
                   onerror=alert(1)&#62;&#38;amp;";
    assert_eq!(page.matches(escaped).count(), 2, "its name and description");
    assert!(!page.contains("<script>alert"), "{page}");
    assert!(inline_free(&page.replace(escaped, "")), "{page}");
    assert_eq!(page.matches(r#"name="to" value="up""#).count(), 2);
    assert_eq!(page.matches(r#"title="Move up" disabled"#).count(), 1);
    assert_eq!(page.matches(r#"title="Move down" disabled"#).count(), 1);
    assert_eq!(page.matches(">Unpin</button>").count(), 2);
    assert_eq!(page.matches(">Pin</button>").count(), 1);
    assert_eq!(page.matches(">Delete</button>").count(), 3);
    assert_eq!(page.matches("with its count").count(), 1);
    assert!(page.contains(r#"<a href="/?f=disposition%3AOPEN">Back to the alert list</a>"#));
    assert_eq!(
        page.matches(r#"name="next" value="/filters/saved?next=%2F%3Ff%3Ddisposition%253AOPEN""#)
            .count(),
        10,
        "every form comes back here: three pins, two pairs of moves, three deletes"
    );
    let empty = ManagePage {
        layout: Layout::signed_out("n"),
        view: manage_view(&[], "/"),
    }
    .render()
    .expect("renders");
    assert!(empty.contains("You have no saved filters yet."), "{empty}");
    assert!(empty.contains(r#"<a href="/">Back to the alert list</a>"#));

    let edit = EditPage {
        layout: Layout::signed_out("n"),
        id: uuid::Uuid::from_u128(2),
        draft: FilterDraft {
            name: HOSTILE.to_owned(),
            description: HOSTILE.to_owned(),
            indicator: true,
        },
        quick: false,
        next: "/".to_owned(),
        manage: "/filters/saved".to_owned(),
        problem: Some(HOSTILE.to_owned()),
        max_name: 255,
        max_description: 1024,
    }
    .render()
    .expect("renders");
    assert_eq!(edit.matches(escaped).count(), 3, "{edit}");
    assert!(inline_free(&edit.replace(escaped, "")), "{edit}");
    assert!(edit.contains(&format!(
        r#"action="/filters/saved/{}""#,
        uuid::Uuid::from_u128(2)
    )));
    assert!(edit.contains(r#"name="indicator" checked"#));
    assert!(edit.contains("It isn't a quick filter now."));

    let (a, b, c) = (
        uuid::Uuid::from_u128(1),
        uuid::Uuid::from_u128(2),
        uuid::Uuid::from_u128(3),
    );
    assert_eq!(moved(&[a, b, c], b, true), Ok(Some(vec![b, a, c])));
    assert_eq!(moved(&[a, b, c], b, false), Ok(Some(vec![a, c, b])));
    assert_eq!(moved(&[a, b, c], a, true), Ok(None));
    assert_eq!(moved(&[a, b, c], c, false), Ok(None));
    assert!(moved(&[a, b], c, true).is_err());
}

/// Through the server: signed out goes to the login, a user without `alert:read` is refused, the page
/// lists the user's own filters, a move and a rename each write through the service with one audit row,
/// and each refusal, a cross-site post among them, changes nothing. Another user's filter is no filter.
#[tokio::test]
async fn saved_filters_are_renamed_and_reordered() {
    let stack = stack().await;
    let alice = user(&stack, "alice").await;
    grant_alert_read(&stack, &alice).await;
    let bob = user(&stack, "bob").await;
    grant_alert_read(&stack, &bob).await;
    user(&stack, "carol").await;
    let save = |actor: &Actor, name: &str, quick: bool| {
        let (service, actor) = (stack.service.clone(), actor.clone());
        let new = NewSavedFilter {
            name: name.to_owned(),
            filters: vec![FilterEntry::text("Disposition", false, &["OPEN"])],
            quick_filter: quick,
            ..NewSavedFilter::default()
        };
        async move {
            service
                .create_saved_filter(&actor, FilterScreen::Alerts, &new)
                .await
                .expect("saves")
                .id
        }
    };
    let first = save(&alice, "First", true).await;
    let second = save(&alice, HOSTILE, true).await;
    let loose = save(&alice, "Loose", false).await;
    let bobs = save(&bob, "Bob's", true).await;
    let order = || async {
        stack
            .service
            .saved_filters(&alice, FilterScreen::Alerts)
            .await
            .expect("lists")
            .into_iter()
            .map(|filter| (filter.name, filter.quick_filter_order))
            .collect::<Vec<_>>()
    };

    // signed out
    for path in [
        "/filters/saved".to_owned(),
        format!("/filters/saved/{first}"),
    ] {
        let page = stack.get(&path).send().await.expect("answered");
        assert_eq!(page.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&page), format!("/login?{}", next_query(&path)));
    }
    let post = stack
        .post(&format!("/filters/saved/{first}/move"), &[("to", "down")])
        .send()
        .await
        .expect("answered");
    assert_eq!(location(&post), "/login");

    // without alert:read
    let carol = session_of(&stack, "carol").await;
    for path in [
        "/filters/saved".to_owned(),
        format!("/filters/saved/{first}"),
    ] {
        let page = stack
            .get(&path)
            .header("cookie", cookie(&carol))
            .send()
            .await
            .expect("answered");
        assert_eq!(page.status(), StatusCode::FORBIDDEN, "{path}");
    }

    let session = session_of(&stack, "alice").await;
    let get = |path: String| {
        let request = stack.get(&path).header("cookie", cookie(&session));
        async move { request.send().await.expect("answered") }
    };
    let page = get("/filters/saved?next=%2F%3Fsize%3D10".to_owned()).await;
    assert_eq!(page.status(), StatusCode::OK);
    let page = page.text().await.expect("a page");
    assert!(
        page.contains(r#"<a href="/?size=10">Back to the alert list</a>"#),
        "{page}"
    );
    assert!(page.contains(">First</a>"));
    assert!(page.contains("&#60;script&#62;alert"), "{page}");
    assert!(!page.contains("<script>alert"), "{page}");
    assert!(!page.contains("Bob&#39;s"), "only her own filters");
    let list = get("/".to_owned()).await.text().await.expect("a page");
    assert!(
        list.contains(r#"<a href="/filters/saved">Manage…</a>"#),
        "{list}"
    );

    let audit = stack.audit_count().await;
    let send = |path: String, form: Vec<(&'static str, &'static str)>| {
        let request = stack.post(&path, &form).header("cookie", cookie(&session));
        async move { request.send().await.expect("answered") }
    };
    for (what, response, status) in [
        (
            "moving the first up",
            send(
                format!("/filters/saved/{first}/move"),
                vec![("to", "up"), ("next", "/filters/saved")],
            )
            .await,
            StatusCode::SEE_OTHER,
        ),
        (
            "moving one that isn't a quick filter",
            send(format!("/filters/saved/{loose}/move"), vec![("to", "up")]).await,
            StatusCode::BAD_REQUEST,
        ),
        (
            "a direction that isn't one",
            send(
                format!("/filters/saved/{second}/move"),
                vec![("to", "sideways")],
            )
            .await,
            StatusCode::BAD_REQUEST,
        ),
        (
            "another user's filter",
            send(format!("/filters/saved/{bobs}/move"), vec![("to", "down")]).await,
            StatusCode::NOT_FOUND,
        ),
        (
            "an id that isn't one",
            send("/filters/saved/nope/move".to_owned(), vec![("to", "down")]).await,
            StatusCode::NOT_FOUND,
        ),
        (
            "a move from another site",
            stack
                .http
                .post(format!("{}/filters/saved/{first}/move", stack.url))
                .header("origin", "https://evil.example")
                .header("cookie", cookie(&session))
                .form(&[("to", "down")])
                .send()
                .await
                .expect("answered"),
            StatusCode::FORBIDDEN,
        ),
    ] {
        assert_eq!(response.status(), status, "{what}");
    }
    assert_eq!(stack.audit_count().await, audit, "nothing changed");
    assert_eq!(
        order().await,
        [
            ("First".to_owned(), Some(0)),
            (HOSTILE.to_owned(), Some(1)),
            ("Loose".to_owned(), None)
        ]
    );

    let down = send(
        format!("/filters/saved/{first}/move"),
        vec![
            ("to", "down"),
            ("next", "/filters/saved?next=%2F%3Fsize%3D10"),
        ],
    )
    .await;
    assert_eq!(down.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&down), "/filters/saved?next=%2F%3Fsize%3D10");
    assert_eq!(stack.audit_count().await, audit + 1);
    assert_eq!(last_action(&stack).await, "set_quick_filters");
    assert_eq!(
        order().await,
        [
            (HOSTILE.to_owned(), Some(0)),
            ("First".to_owned(), Some(1)),
            ("Loose".to_owned(), None)
        ]
    );
    let pinned = send(
        format!("/filters/saved/{loose}/quick"),
        vec![("pin", "true"), ("next", "/filters/saved")],
    )
    .await;
    assert_eq!(location(&pinned), "/filters/saved");
    let up = send(format!("/filters/saved/{loose}/move"), vec![("to", "up")]).await;
    assert_eq!(up.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&up), "/");
    assert_eq!(
        order().await,
        [
            (HOSTILE.to_owned(), Some(0)),
            ("Loose".to_owned(), Some(1)),
            ("First".to_owned(), Some(2))
        ]
    );
    assert_eq!(stack.audit_count().await, audit + 3);

    // rename
    let page = get(format!("/filters/saved/{first}?next=%2F%3Fsize%3D10")).await;
    assert_eq!(page.status(), StatusCode::OK);
    let page = page.text().await.expect("a page");
    assert!(page.contains(r#"name="name" value="First""#), "{page}");
    assert!(
        page.contains(r#"<input type="hidden" name="next" value="/?size=10">"#),
        "{page}"
    );
    assert!(
        page.contains(r#"<a href="/filters/saved?next=%2F%3Fsize%3D10">Back to Saved filters</a>"#)
    );
    for path in [
        format!("/filters/saved/{bobs}"),
        "/filters/saved/nope".to_owned(),
    ] {
        assert_eq!(
            get(path.clone()).await.status(),
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }

    let audit = stack.audit_count().await;
    let rename = |id: uuid::Uuid, form: Vec<(&'static str, &'static str)>| {
        send(format!("/filters/saved/{id}"), form)
    };
    for (what, response, status, says) in [
        (
            "a name she has already",
            rename(first, vec![("name", "Loose"), ("description", "")]).await,
            StatusCode::CONFLICT,
            "You have a saved filter named &#34;Loose&#34; already.",
        ),
        (
            "a blank name",
            rename(first, vec![("name", "   "), ("description", "")]).await,
            StatusCode::BAD_REQUEST,
            "Not saved: a saved filter&#39;s name is 1 to 255 characters, not all whitespace.",
        ),
        (
            "another user's filter",
            rename(bobs, vec![("name", "Mine now")]).await,
            StatusCode::NOT_FOUND,
            "There&#39;s no such saved filter.",
        ),
        (
            "a rename from another site",
            stack
                .http
                .post(format!("{}/filters/saved/{first}", stack.url))
                .header("origin", "https://evil.example")
                .header("cookie", cookie(&session))
                .form(&[("name", "Renamed")])
                .send()
                .await
                .expect("answered"),
            StatusCode::FORBIDDEN,
            "this request came from another site",
        ),
    ] {
        assert_eq!(response.status(), status, "{what}");
        let page = response.text().await.expect("a page");
        assert!(page.contains(says), "{what}: {page}");
    }
    let refused = rename(first, vec![("name", "Loose"), ("description", "kept <b>")])
        .await
        .text()
        .await
        .expect("a page");
    assert!(
        refused.contains(r#"name="description" value="kept &#60;b&#62;""#),
        "the form comes back as it was sent: {refused}"
    );
    assert_eq!(stack.audit_count().await, audit, "nothing changed");
    let bobs_now = stack.service.saved_filter(&bob, bobs).await.expect("reads");
    assert_eq!(bobs_now.name, "Bob's");

    // the same values change nothing and write no row
    let same = rename(first, vec![("name", "First"), ("description", "")]).await;
    assert_eq!(same.status(), StatusCode::SEE_OTHER);
    assert_eq!(stack.audit_count().await, audit);

    let renamed = rename(
        first,
        vec![
            ("name", "  Renamed  "),
            ("description", "Open ones"),
            ("indicator", "on"),
            ("next", "/?size=10"),
        ],
    )
    .await;
    assert_eq!(renamed.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&renamed), "/filters/saved?next=%2F%3Fsize%3D10");
    assert_eq!(stack.audit_count().await, audit + 1);
    assert_eq!(last_action(&stack).await, "update_saved_filter");
    let now = stack
        .service
        .saved_filter(&alice, first)
        .await
        .expect("reads");
    assert_eq!(now.name, "Renamed");
    assert_eq!(now.description.as_deref(), Some("Open ones"));
    assert!(now.quick_filter_indicator);
    assert_eq!(now.quick_filter_order, Some(2), "its place is kept");
    assert_eq!(
        now.filters,
        vec![FilterEntry::text("Disposition", false, &["OPEN"])]
    );
    let list = get("/".to_owned()).await.text().await.expect("a page");
    assert!(list.contains(">Renamed <span class=\"count\">"), "{list}");
}

// ---- PLAN.md 5.11's admin area ----

use ace_gui::admin::{
    AdminKeyPage, ConfirmGrantPage, GroupPage, HubPage, Named, SecretPage, UserPage, UsersPage,
    gives, group_view, scope_choices, user_view, users_view,
};
use ace_service::{Group, GroupId, UserDetail};

const HOSTILE_ESCAPED: &str = "&#34;&#62;&#60;script&#62;alert(&#39;x&#39;)&#60;/script&#62;&#60;img \
                               src=x onerror=alert(1)&#62;&#38;amp;";

fn fixture_grant(id: i64, major: &str, minor: &str, effect: Effect) -> Grant {
    Grant {
        id,
        major: major.to_owned(),
        minor: minor.to_owned(),
        effect,
    }
}

/// A drawn page: it holds the hostile text only escaped, and nothing inline.
fn drawn_safely(page: &impl Template) -> String {
    let html = page.render().expect("renders");
    assert!(!html.contains("<script>alert"), "{html}");
    assert!(!html.contains("<img"), "{html}");
    assert!(inline_free(&html.replace(HOSTILE_ESCAPED, "")), "{html}");
    html
}

/// The password or token a page shows once.
fn shown_secret(page: &str) -> String {
    page.split(r#"id="secret" class="token" type="text" value=""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_else(|| panic!("a secret: {page}"))
        .to_owned()
}

/// The area's view functions, called directly: the users list with each user's grants and groups, a
/// user's page with what each grant gives and the self-harm notes, a group's page, the hub, the confirm
/// for an allow covering `user:write`, a key's edit and the page that shows a secret once, each with
/// hostile text escaped and nothing inline, and without `user:write` no forms.
#[test]
fn the_admin_views_draw_users_groups_grants_and_keys() {
    let layout = || Layout::new("n", Theme::default(), Some("boss".to_owned()), "/admin");
    let mut alice = fixture_user("alice");
    alice.display_name = Some(HOSTILE.to_owned());
    alice.email = Some(HOSTILE.to_owned());
    let mut bob = fixture_user("bob");
    bob.id = ace_service::UserId(uuid::Uuid::from_u128(2));
    bob.enabled = false;
    let group = Group {
        id: GroupId(uuid::Uuid::from_u128(6)),
        name: HOSTILE.to_owned(),
        members: vec![alice.id],
        grants: vec![fixture_grant(5, "user", "*", Effect::Allow)],
    };
    let other = Group {
        id: GroupId(uuid::Uuid::from_u128(7)),
        name: "readers".to_owned(),
        members: vec![],
        grants: vec![],
    };
    let alice_detail = UserDetail {
        user: alice.clone(),
        grants: vec![
            fixture_grant(1, "*", "*", Effect::Allow),
            fixture_grant(2, "signature", "download", Effect::Deny),
        ],
        groups: vec![group.clone()],
    };
    let bob_detail = UserDetail {
        user: bob.clone(),
        grants: vec![],
        groups: vec![],
    };
    let mut service_key = fixture_key(0xB, "pipeline", &[("alert", "create", Effect::Allow)]);
    service_key.owner = None;
    let keys = [
        fixture_key(0xA, HOSTILE, &[("alert", "read", Effect::Allow)]),
        service_key,
    ];

    // what a grant gives
    let every = gives(&PermissionPattern::new("*", "*").expect("a pattern"));
    assert!(every.everything && every.escalates);
    assert_eq!(every.covers.len(), CATALOG.len());
    let alerts = gives(&PermissionPattern::new("alert", "*").expect("a pattern"));
    assert_eq!(
        alerts.covers,
        ["alert:create", "alert:read", "alert:write"],
        "the catalog's order"
    );
    assert!(!alerts.escalates);
    assert_eq!(
        alerts.summary(false),
        "Gives alert:create, alert:read, alert:write."
    );
    assert_eq!(
        alerts.summary(true),
        "Takes away alert:create, alert:read, alert:write, whatever else allows them."
    );
    let none = gives(&PermissionPattern::new("alret", "read").expect("a pattern"));
    assert_eq!(none.summary(false), "Covers nothing ACE checks today.");
    assert!(gives(&PermissionPattern::new("user", "w*").expect("a pattern")).escalates);

    // the list
    let users = drawn_safely(&UsersPage {
        layout: layout(),
        view: users_view(
            &[alice_detail.clone(), bob_detail.clone()],
            &[group.clone(), other.clone()],
            &keys,
            false,
            true,
        ),
    });
    for part in [
        r#"<a href="/admin/users/00000000-0000-0000-0000-000000000001">alice</a>"#,
        r#"<a href="/admin/users/00000000-0000-0000-0000-000000000002">bob</a>"#,
        "<td><b>no</b></td>",
        &format!("<td>{HOSTILE_ESCAPED}</td>"),
        &format!(
            r#"allow <code>user:*</code> <span class="muted">(through {HOSTILE_ESCAPED})</span>"#
        ),
        "deny <code>signature:download</code>",
        &format!(
            r#"<a href="/admin/groups/00000000-0000-0000-0000-000000000006">{HOSTILE_ESCAPED}</a>"#
        ),
        "Keys with no owner",
        "<td>pipeline</td>",
        r#"<form method="post" action="/admin/users" class="fields">"#,
        r#"<form method="post" action="/admin/groups" class="fields">"#,
        r#"<a href="/admin/users?disabled=hide">Hide disabled users</a>"#,
    ] {
        assert!(users.contains(part), "{part}: {users}");
    }
    assert!(!users.contains(&format!(
        "<td>{HOSTILE_ESCAPED}</td>\n          <td>alert:read"
    )));
    let read_only = drawn_safely(&UsersPage {
        layout: layout(),
        view: users_view(
            &[alice_detail.clone(), bob_detail.clone()],
            std::slice::from_ref(&group),
            &keys,
            true,
            false,
        ),
    });
    assert!(!read_only.contains(">bob</a>"), "hidden: {read_only}");
    assert!(read_only.contains("Changing users and groups needs user:write."));
    assert!(
        !read_only.contains("<form method=\"post\" action=\"/admin"),
        "{read_only}"
    );
    assert!(read_only.contains(r#"<a href="/admin/users">Show disabled users</a>"#));

    // alice's own page: no Disable, and the note
    let own = drawn_safely(&UserPage {
        layout: layout(),
        view: user_view(
            &alice_detail,
            &[group.clone(), other.clone()],
            &keys,
            Some(alice.id),
            true,
        ),
    });
    for part in [
        "You can't disable yourself: another user with user:write has to.",
        "You can't take user:write from yourself",
        "Gives everything ACE checks, now and as permissions are added: full administration.",
        "With user:write they can change any grant, and give themselves *:*.",
        "Takes away signature:download, whatever else allows them.",
        &format!(r#"<span class="muted">through {HOSTILE_ESCAPED}</span>"#),
        r#"<input type="hidden" name="holder_kind" value="user">"#,
        r#"<input type="hidden" name="major" value="signature">"#,
        r#"<option value="00000000-0000-0000-0000-000000000007">readers</option>"#,
        r#"action="/admin/groups/00000000-0000-0000-0000-000000000006/members/00000000-0000-0000-0000-000000000001/remove""#,
        &format!("<td>{HOSTILE_ESCAPED}</td>"),
        r#"<a href="/admin/keys/00000000-0000-0000-0000-00000000000a">Edit</a>"#,
        r#"<option value="*:*">*:*: Everything ACE checks"#,
        "so they can give themselves <code>*:*</code>",
        &format!(r#"name="display_name" value="{HOSTILE_ESCAPED}""#),
    ] {
        assert!(own.contains(part), "{part}: {own}");
    }
    assert!(!own.contains(r#"name="enabled" value="false""#), "{own}");
    assert!(!own.contains("<td>pipeline</td>"), "only alice's keys");
    assert!(
        !own.contains(r#"name="scope" value="user:self""#),
        "no key holds user:self"
    );
    let theirs = drawn_safely(&UserPage {
        layout: layout(),
        view: user_view(
            &alice_detail,
            std::slice::from_ref(&group),
            &keys,
            Some(bob.id),
            true,
        ),
    });
    assert!(
        theirs.contains(r#"name="enabled" value="false""#),
        "{theirs}"
    );
    assert!(!theirs.contains("You can't disable yourself"));
    let disabled = drawn_safely(&UserPage {
        layout: layout(),
        view: user_view(
            &bob_detail,
            std::slice::from_ref(&group),
            &[],
            Some(alice.id),
            true,
        ),
    });
    assert!(
        disabled.contains(r#"name="enabled" value="true""#),
        "{disabled}"
    );
    assert!(disabled.contains("bob <span class=\"muted\">(disabled)</span>"));
    let looking = drawn_safely(&UserPage {
        layout: layout(),
        view: user_view(
            &alice_detail,
            std::slice::from_ref(&group),
            &keys,
            None,
            false,
        ),
    });
    assert!(
        !looking.contains("<form method=\"post\" action=\"/admin"),
        "{looking}"
    );

    // a group
    let group_page = drawn_safely(&GroupPage {
        layout: layout(),
        view: group_view(&group, &[alice.clone(), bob.clone()], true),
    });
    for part in [
        &format!("<h1>Group {HOSTILE_ESCAPED}</h1>"),
        r#"<a href="/admin/users/00000000-0000-0000-0000-000000000001">alice</a>"#,
        r#"<option value="00000000-0000-0000-0000-000000000002">bob</option>"#,
        "With user:write its members can change any grant",
        r#"<input type="hidden" name="holder_kind" value="group">"#,
        r#"action="/admin/groups/00000000-0000-0000-0000-000000000006/delete""#,
    ] {
        assert!(group_page.contains(part), "{part}: {group_page}");
    }

    // the hub
    let hub = drawn_safely(&HubPage {
        layout: layout(),
        modules: vec![],
    });
    assert!(hub.contains("You do not have access to any administration areas."));

    // the confirm
    let confirm = drawn_safely(&ConfirmGrantPage {
        layout: layout(),
        holder_kind: "group",
        holder_id: group.id.0,
        holder_name: HOSTILE.to_owned(),
        pattern: "user:*".to_owned(),
        gives: gives(&PermissionPattern::new("user", "*").expect("a pattern")),
        back: "/admin/groups/00000000-0000-0000-0000-000000000006".to_owned(),
    });
    for part in [
        &format!("Grant <code>user:*</code> to {HOSTILE_ESCAPED}?"),
        "Gives user:read, user:self, user:write.",
        &format!("every member of {HOSTILE_ESCAPED} can change any grant"),
        r#"<input type="hidden" name="confirm" value="yes">"#,
        r#"<input type="hidden" name="other" value="user:*">"#,
        r#"<a href="/admin/groups/00000000-0000-0000-0000-000000000006">Cancel</a>"#,
    ] {
        assert!(confirm.contains(part), "{part}: {confirm}");
    }

    // a key's edit
    let key = drawn_safely(&AdminKeyPage {
        layout: layout(),
        id: uuid::Uuid::from_u128(0xA),
        owner: Some(Named {
            id: alice.id.0,
            name: HOSTILE.to_owned(),
        }),
        back: "/admin/users/00000000-0000-0000-0000-000000000001".to_owned(),
        scope: scope_choices(&["alert:read".to_owned()]),
        draft: KeyDraft {
            name: HOSTILE.to_owned(),
            ticked: vec!["alert:read".to_owned()],
            other: HOSTILE.to_owned(),
        },
        inherit: true,
        denies: vec!["signature:download".to_owned()],
        problem: Some(HOSTILE.to_owned()),
    });
    for part in [
        r#"value="inherit" checked"#,
        r#"value="alert:read" checked"#,
        "This key is denied <code>signature:download</code>",
        &format!(r#"name="name" value="{HOSTILE_ESCAPED}""#),
        &format!(r#"<p class="error" role="alert">{HOSTILE_ESCAPED}</p>"#),
    ] {
        assert!(key.contains(part), "{part}: {key}");
    }

    // a secret, once
    let secret = SecretPage {
        layout: layout(),
        title: "New user",
        what: format!("The password for {HOSTILE}"),
        secret: "s3cret-value".to_owned(),
        hint: "hand it over",
        back: "/admin/users".to_owned(),
    };
    assert!(!format!("{secret:?}").contains("s3cret-value"));
    let secret = drawn_safely(&secret);
    assert_eq!(shown_secret(&secret), "s3cret-value");
    assert!(secret.contains(&format!("The password for {HOSTILE_ESCAPED} is below.")));
}

async fn grant_effect(stack: &Stack, actor: &Actor, major: &str, minor: &str, effect: Effect) {
    let Actor::User { id, .. } = actor else {
        panic!("a user");
    };
    stack
        .service
        .grant(
            &bootstrap(),
            &Holder::User(*id),
            &PermissionPattern::new(major, minor).expect("a pattern"),
            effect,
        )
        .await
        .expect("grants");
}

/// The area through the server: signed out goes to the login; without `admin:read` every page and
/// form is 403 and the layout has no Admin link; with it the hub shows only what the viewer may open,
/// Users & Roles needs `user:read`, and its forms need `user:write`, each refusal changing nothing.
#[tokio::test]
async fn the_admin_area_needs_admin_read_then_each_page_s_own_permission() {
    let stack = stack().await;
    let alice = user(&stack, "alice").await;
    for (path, back) in [
        ("/admin", "/login?next=%2Fadmin"),
        ("/admin/users", "/login?next=%2Fadmin%2Fusers"),
    ] {
        let page = stack.get(path).send().await.expect("answered");
        assert_eq!(page.status(), StatusCode::SEE_OTHER, "{path}");
        assert_eq!(location(&page), back);
    }
    let post = stack
        .post("/admin/users", &[("username", "mallory")])
        .send()
        .await
        .expect("answered");
    assert_eq!(location(&post), "/login");

    let session = session_of(&stack, "alice").await;
    let get = |path: &str| stack.get(path).header("cookie", cookie(&session)).send();
    let audit = stack.audit_count().await;
    for path in ["/admin", "/admin/users", "/admin/users/not-a-uuid"] {
        let page = get(path).await.expect("answered");
        assert_eq!(page.status(), StatusCode::FORBIDDEN, "{path}");
        assert!(page.text().await.expect("a page").contains("admin:read"));
    }
    for (path, form) in [
        (
            "/admin/users",
            vec![("username", "mallory"), ("password", PASSWORD)],
        ),
        ("/admin/groups", vec![("name", "mine")]),
    ] {
        let refused = stack
            .post(path, &form)
            .header("cookie", cookie(&session))
            .send()
            .await
            .expect("answered");
        assert_eq!(refused.status(), StatusCode::FORBIDDEN, "{path}");
    }
    let home = get("/")
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(!home.contains(r#"href="/admin""#), "{home}");

    grant_to(&stack, &alice, "admin", "read").await;
    let hub = get("/admin").await.expect("answered");
    assert_eq!(hub.status(), StatusCode::OK);
    let hub = hub.text().await.expect("a page");
    assert!(hub.contains("You do not have access to any administration areas."));
    assert!(hub.contains(r#"<a href="/admin">Admin</a>"#), "{hub}");
    let users = get("/admin/users").await.expect("answered");
    assert_eq!(users.status(), StatusCode::FORBIDDEN);
    assert!(users.text().await.expect("a page").contains("user:read"));

    grant_to(&stack, &alice, "user", "read").await;
    let hub = get("/admin")
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(
        hub.contains(r#"<a href="/admin/users"><b>Users &#38; Roles</b>"#),
        "{hub}"
    );
    let users = get("/admin/users").await.expect("answered");
    assert_eq!(users.status(), StatusCode::OK);
    let users = users.text().await.expect("a page");
    assert!(users.contains("Changing users and groups needs user:write."));
    assert!(users.contains(">alice</a>"), "{users}");

    let Actor::User { id: alice_id, .. } = &alice else {
        panic!("a user");
    };
    let alice_id = alice_id.0.to_string();
    let audit_now = stack.audit_count().await;
    for (what, path, form) in [
        (
            "a new user",
            "/admin/users".to_owned(),
            vec![
                ("username", "mallory"),
                ("password", PASSWORD),
                ("timezone", "UTC"),
            ],
        ),
        (
            "a new group",
            "/admin/groups".to_owned(),
            vec![("name", "mine")],
        ),
        (
            "granting herself *:*",
            "/admin/grants".to_owned(),
            vec![
                ("holder_kind", "user"),
                ("holder", alice_id.as_str()),
                ("effect", "allow"),
                ("permission", "*:*"),
            ],
        ),
        (
            "a reset",
            format!("/admin/users/{alice_id}/password"),
            vec![("password", "")],
        ),
    ] {
        let refused = stack
            .post(&path, &form)
            .header("cookie", cookie(&session))
            .send()
            .await
            .expect("answered");
        assert_eq!(refused.status(), StatusCode::FORBIDDEN, "{what}");
        let page = refused.text().await.expect("a page");
        assert!(page.contains("user:write"), "{what}: {page}");
        assert!(!page.contains(r#"id="secret""#), "{what}");
    }
    assert_eq!(stack.audit_count().await, audit_now, "nothing changed");
    assert_eq!(audit_now, audit + 2, "only the two grants");
    assert!(
        !stack
            .service
            .allowed(&alice, &ace_service::USER_WRITE)
            .await
            .expect("checks")
    );

    let nil = uuid::Uuid::nil();
    for (path, status) in [
        (
            "/admin/users/not-a-uuid".to_owned(),
            StatusCode::BAD_REQUEST,
        ),
        (format!("/admin/users/{nil}"), StatusCode::NOT_FOUND),
        (format!("/admin/groups/{nil}"), StatusCode::NOT_FOUND),
        (format!("/admin/keys/{nil}"), StatusCode::NOT_FOUND),
        ("/admin/keys/nope".to_owned(), StatusCode::BAD_REQUEST),
    ] {
        assert_eq!(
            get(&path).await.expect("answered").status(),
            status,
            "{path}"
        );
    }
}

/// Users through the area: made with a typed password or one made and shown once, their profile saved,
/// disabled and enabled, and their password reset, each with its one audit row; a refusal the service
/// gives draws the page again with its reason, and disabling yourself is refused.
#[tokio::test]
async fn users_are_made_changed_disabled_and_reset_through_the_admin_area() {
    let stack = stack().await;
    let boss = user(&stack, "boss").await;
    grant_to(&stack, &boss, "*", "*").await;
    let session = session_of(&stack, "boss").await;
    let post = |path: &str, form: &[(&str, &str)]| {
        stack.post(path, form).header("cookie", cookie(&session))
    };
    let page = |path: String| {
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

    // made, with a typed password
    let audit = stack.audit_count().await;
    let made = post(
        "/admin/users",
        &[
            ("username", "Carol"),
            ("password", PASSWORD),
            ("display_name", HOSTILE),
            ("email", "carol@example.com"),
            ("timezone", "Europe/London"),
        ],
    )
    .send()
    .await
    .expect("answered");
    assert_eq!(made.status(), StatusCode::SEE_OTHER);
    let carol_page = location(&made).to_owned();
    assert!(carol_page.starts_with("/admin/users/") && carol_page.ends_with("?done=created"));
    assert_eq!(stack.audit_count().await, audit + 1);
    assert_eq!(last_action(&stack).await, "create_user");
    let carol = stack
        .service
        .users(&boss, true)
        .await
        .expect("reads")
        .into_iter()
        .find(|user| user.username == "carol")
        .expect("carol");
    assert_eq!(carol.timezone, "Europe/London");
    let carol_id = carol.id.0;
    let carol_session = session_of(&stack, "carol").await;
    let shown = page(carol_page).await;
    assert!(shown.contains("The user is made."), "{shown}");
    assert!(shown.contains(&format!(r#"value="{HOSTILE_ESCAPED}""#)));
    let listed = page("/admin/users".to_owned()).await;
    assert!(
        listed.contains(&format!("<td>{HOSTILE_ESCAPED}</td>")),
        "{listed}"
    );
    assert!(!listed.contains("<script>alert"));

    // made, with one made for her, shown once
    let audit = stack.audit_count().await;
    let made = post(
        "/admin/users",
        &[("username", "dave"), ("password", ""), ("timezone", "UTC")],
    )
    .send()
    .await
    .expect("answered");
    assert_eq!(made.status(), StatusCode::CREATED);
    assert_eq!(made.headers()["cache-control"], "no-store");
    assert!(made.headers().get(LOCATION).is_none(), "no redirect");
    let password = shown_secret(&made.text().await.expect("a page"));
    assert_eq!(password.len(), 48);
    assert_eq!(stack.audit_count().await, audit + 1);
    assert!(session_set(stack.log_in("dave", &password).await.headers()).is_some());
    let listed = page("/admin/users".to_owned()).await;
    assert!(!listed.contains(&password), "shown once");

    // refusals draw the page again, and change nothing
    let audit = stack.audit_count().await;
    for (what, form, status, says) in [
        (
            "a taken username",
            vec![
                ("username", "carol"),
                ("password", PASSWORD),
                ("timezone", "UTC"),
            ],
            StatusCode::CONFLICT,
            "No user was made: that username is taken.",
        ),
        (
            "a username that isn't one",
            vec![
                ("username", "carol smith"),
                ("password", PASSWORD),
                ("timezone", "UTC"),
            ],
            StatusCode::BAD_REQUEST,
            "No user was made: a username is 1 to 64 ASCII letters",
        ),
        (
            "a weak password",
            vec![
                ("username", "erin"),
                ("password", "short"),
                ("timezone", "UTC"),
            ],
            StatusCode::BAD_REQUEST,
            "No user was made: a password has to be at least 12 characters",
        ),
        (
            "an email that isn't one",
            vec![
                ("username", "erin"),
                ("password", PASSWORD),
                ("email", "erin"),
                ("timezone", "UTC"),
            ],
            StatusCode::BAD_REQUEST,
            "No user was made: an email is a name, an @ and a domain",
        ),
    ] {
        let response = post("/admin/users", &form).send().await.expect("answered");
        assert_eq!(response.status(), status, "{what}");
        let text = response.text().await.expect("a page");
        assert!(text.contains(says), "{what}: {text}");
        assert!(
            !text.contains(PASSWORD),
            "{what}: a password isn't drawn back"
        );
        assert!(!text.contains(r#"id="secret""#), "{what}");
    }
    let refilled = post(
        "/admin/users",
        &[
            ("username", "carol"),
            ("password", PASSWORD),
            ("display_name", "C"),
            ("timezone", "UTC"),
        ],
    )
    .send()
    .await
    .expect("answered")
    .text()
    .await
    .expect("a page");
    assert!(
        refilled.contains(r#"name="username" value="carol""#),
        "{refilled}"
    );
    assert!(refilled.contains(r#"name="display_name" value="C""#));
    let cross_site = stack
        .http
        .post(format!("{}/admin/users", stack.url))
        .header("origin", "https://evil.example")
        .header("cookie", cookie(&session))
        .form(&[("username", "erin"), ("password", PASSWORD)])
        .send()
        .await
        .expect("answered");
    assert_eq!(cross_site.status(), StatusCode::FORBIDDEN);
    assert_eq!(stack.audit_count().await, audit, "nothing changed");

    // the profile
    let profile = format!("/admin/users/{carol_id}/profile");
    let saved = post(
        &profile,
        &[
            ("display_name", "Carol"),
            ("email", "c@example.com"),
            ("timezone", "UTC"),
        ],
    )
    .send()
    .await
    .expect("answered");
    assert_eq!(
        location(&saved),
        format!("/admin/users/{carol_id}?done=profile")
    );
    assert_eq!(stack.audit_count().await, audit + 1);
    assert_eq!(last_action(&stack).await, "update_user");
    let same = post(
        &profile,
        &[
            ("display_name", "Carol"),
            ("email", "c@example.com"),
            ("timezone", "UTC"),
        ],
    )
    .send()
    .await
    .expect("answered");
    assert_eq!(
        location(&same),
        format!("/admin/users/{carol_id}?done=unchanged")
    );
    assert_eq!(
        stack.audit_count().await,
        audit + 1,
        "the same values write no row"
    );
    let refused = post(
        &profile,
        &[
            ("display_name", "Carol"),
            ("email", ""),
            ("timezone", "Mars/Olympus_Mons"),
        ],
    )
    .send()
    .await
    .expect("answered");
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert!(
        refused
            .text()
            .await
            .expect("a page")
            .contains("Not saved: &#34;Mars/Olympus_Mons&#34; isn&#39;t an IANA timezone")
    );

    // disabled, which ends her session, and enabled
    let enabled = format!("/admin/users/{carol_id}/enabled");
    let audit = stack.audit_count().await;
    let off = post(&enabled, &[("enabled", "false")])
        .send()
        .await
        .expect("answered");
    assert_eq!(
        location(&off),
        format!("/admin/users/{carol_id}?done=disabled")
    );
    assert_eq!(stack.audit_count().await, audit + 1);
    assert_eq!(last_action(&stack).await, "set_user_enabled");
    let hers = stack
        .get("/preferences")
        .header("cookie", cookie(&carol_session))
        .send()
        .await
        .expect("answered");
    assert_eq!(hers.status(), StatusCode::SEE_OTHER, "her session ended");
    let shown = page(format!("/admin/users/{carol_id}?done=disabled")).await;
    assert!(shown.contains("The user is disabled."), "{shown}");
    assert!(shown.contains(r#"name="enabled" value="true""#));
    let on = post(&enabled, &[("enabled", "true")])
        .send()
        .await
        .expect("answered");
    assert_eq!(
        location(&on),
        format!("/admin/users/{carol_id}?done=enabled")
    );
    assert_eq!(stack.audit_count().await, audit + 2);
    let bad = post(&enabled, &[("enabled", "maybe")])
        .send()
        .await
        .expect("answered");
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);

    // nobody disables themselves
    let Actor::User { id: boss_id, .. } = &boss else {
        panic!("a user");
    };
    let own = page(format!("/admin/users/{}", boss_id.0)).await;
    assert!(own.contains("You can't disable yourself"), "{own}");
    let audit = stack.audit_count().await;
    let refused = post(
        &format!("/admin/users/{}/enabled", boss_id.0),
        &[("enabled", "false")],
    )
    .send()
    .await
    .expect("answered");
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    let text = refused.text().await.expect("a page");
    assert!(
        text.contains(
            "Not changed: a user can&#39;t disable themselves: another user with user:write has to."
        ),
        "{text}"
    );
    assert_eq!(stack.audit_count().await, audit);
    assert!(
        stack
            .get("/admin")
            .header("cookie", cookie(&session))
            .send()
            .await
            .expect("answered")
            .status()
            .is_success()
    );

    // a reset, made and shown once, which ends her sessions
    let carol_session = session_of(&stack, "carol").await;
    let audit = stack.audit_count().await;
    let reset = format!("/admin/users/{carol_id}/password");
    let made = post(&reset, &[("password", "")])
        .send()
        .await
        .expect("answered");
    assert_eq!(made.status(), StatusCode::OK);
    assert_eq!(made.headers()["cache-control"], "no-store");
    assert!(made.headers().get(LOCATION).is_none());
    let text = made.text().await.expect("a page");
    assert!(
        text.contains("The new password for carol is below."),
        "{text}"
    );
    let password = shown_secret(&text);
    assert_eq!(stack.audit_count().await, audit + 1);
    assert_eq!(last_action(&stack).await, "reset_password");
    assert_eq!(
        stack
            .get("/preferences")
            .header("cookie", cookie(&carol_session))
            .send()
            .await
            .expect("answered")
            .status(),
        StatusCode::SEE_OTHER
    );
    assert!(session_set(stack.log_in("carol", PASSWORD).await.headers()).is_none());
    assert!(session_set(stack.log_in("carol", &password).await.headers()).is_some());
    let audit = stack.audit_count().await;
    let weak = post(&reset, &[("password", "short")])
        .send()
        .await
        .expect("answered");
    assert_eq!(weak.status(), StatusCode::BAD_REQUEST);
    assert!(
        weak.text()
            .await
            .expect("a page")
            .contains("Not reset: a password has to be")
    );
    assert_eq!(stack.audit_count().await, audit, "nothing changed");
    let typed = post(&reset, &[("password", PASSWORD)])
        .send()
        .await
        .expect("answered");
    assert_eq!(
        location(&typed),
        format!("/admin/users/{carol_id}?done=password")
    );
    assert!(session_set(stack.log_in("carol", PASSWORD).await.headers()).is_some());
}

/// Groups, grants and keys through the area, each write with its one audit row: a group made, joined,
/// granted, left and deleted; an allow covering `user:write` confirmed before it's made; a grant revoked;
/// the administrator refused when a change would take their own `user:write`; and a key made with its
/// token shown once, changed and revoked.
#[tokio::test]
async fn groups_grants_and_keys_through_the_admin_area() {
    let stack = stack().await;
    let boss = user(&stack, "boss").await;
    grant_to(&stack, &boss, "*", "*").await;
    let carol = user(&stack, "carol").await;
    let Actor::User { id: carol_id, .. } = &carol else {
        panic!("a user");
    };
    let Actor::User { id: boss_id, .. } = &boss else {
        panic!("a user");
    };
    let (carol_id, boss_id) = (carol_id.0.to_string(), boss_id.0.to_string());
    let session = session_of(&stack, "boss").await;
    let post = |path: &str, form: &[(&str, &str)]| {
        stack.post(path, form).header("cookie", cookie(&session))
    };

    // a group, made
    let audit = stack.audit_count().await;
    let made = post("/admin/groups", &[("name", HOSTILE)])
        .send()
        .await
        .expect("answered");
    assert_eq!(made.status(), StatusCode::SEE_OTHER);
    let group_page = location(&made).to_owned();
    assert!(group_page.ends_with("?done=group"), "{group_page}");
    let group = group_page
        .trim_start_matches("/admin/groups/")
        .trim_end_matches("?done=group")
        .to_owned();
    assert_eq!(stack.audit_count().await, audit + 1);
    assert_eq!(last_action(&stack).await, "create_group");
    let shown = stack
        .get(&group_page)
        .header("cookie", cookie(&session))
        .send()
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(
        shown.contains(&format!("<h1>Group {HOSTILE_ESCAPED}</h1>")),
        "{shown}"
    );
    for (name, status, says) in [
        (
            HOSTILE,
            StatusCode::CONFLICT,
            "No group was made: that group name is taken.",
        ),
        (
            " ",
            StatusCode::BAD_REQUEST,
            "No group was made: a group&#39;s name is 1 to 255",
        ),
    ] {
        let refused = post("/admin/groups", &[("name", name)])
            .send()
            .await
            .expect("answered");
        assert_eq!(refused.status(), status, "{name}");
        assert!(refused.text().await.expect("a page").contains(says));
    }
    assert_eq!(stack.audit_count().await, audit + 1);

    // joined, from the group's page and from the user's
    let joined = post(
        &format!("/admin/groups/{group}/members"),
        &[("user", &carol_id), ("back", "group")],
    )
    .send()
    .await
    .expect("answered");
    assert_eq!(
        location(&joined),
        format!("/admin/groups/{group}?done=joined")
    );
    assert_eq!(last_action(&stack).await, "add_group_member");
    let readers = stack
        .service
        .create_group(&boss, "readers")
        .await
        .expect("makes")
        .0;
    let joined = post(
        &format!("/admin/users/{carol_id}/groups"),
        &[("group", &readers.to_string())],
    )
    .send()
    .await
    .expect("answered");
    assert_eq!(
        location(&joined),
        format!("/admin/users/{carol_id}?done=joined")
    );
    let audit = stack.audit_count().await;

    // a grant to the group
    let grant = |holder_kind: &str, holder: &str, extra: &[(&str, &str)]| {
        let mut form = vec![
            ("holder_kind", holder_kind.to_owned()),
            ("holder", holder.to_owned()),
        ];
        form.extend(extra.iter().map(|(k, v)| (*k, (*v).to_owned())));
        stack
            .http
            .post(format!("{}/admin/grants", stack.url))
            .header("origin", &stack.url)
            .header("cookie", cookie(&session))
            .form(&form)
    };
    let granted = grant(
        "group",
        &group,
        &[("effect", "allow"), ("permission", "alert:read")],
    )
    .send()
    .await
    .expect("answered");
    assert_eq!(
        location(&granted),
        format!("/admin/groups/{group}?done=granted")
    );
    assert_eq!(stack.audit_count().await, audit + 1);
    assert_eq!(last_action(&stack).await, "grant");
    assert!(
        stack
            .service
            .allowed(&carol, &ace_service::ALERT_READ)
            .await
            .expect("checks")
    );
    let shown = stack
        .get(&format!("/admin/groups/{group}"))
        .header("cookie", cookie(&session))
        .send()
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(shown.contains("Gives alert:read."), "{shown}");
    for (what, holder_kind, holder, extra, says) in [
        (
            "both a choice and a pattern",
            "group",
            group.as_str(),
            vec![
                ("effect", "allow"),
                ("permission", "alert:read"),
                ("other", "alert:write"),
            ],
            "No grant was made: choose a permission or type a pattern, not both.",
        ),
        (
            "neither",
            "group",
            group.as_str(),
            vec![("effect", "allow")],
            "No grant was made: choose a permission or type a pattern.",
        ),
        (
            "text that isn't a pattern",
            "user",
            carol_id.as_str(),
            vec![("effect", "deny"), ("other", "alert")],
            "No grant was made: alert isn&#39;t a pattern, which is major:minor.",
        ),
    ] {
        let refused = grant(holder_kind, holder, &extra)
            .send()
            .await
            .expect("answered");
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "{what}");
        let text = refused.text().await.expect("a page");
        assert!(text.contains(says), "{what}: {text}");
    }
    for form in [
        vec![
            ("holder_kind", "key"),
            ("holder", carol_id.as_str()),
            ("effect", "allow"),
            ("permission", "alert:read"),
        ],
        vec![
            ("holder_kind", "user"),
            ("holder", "nope"),
            ("effect", "allow"),
            ("permission", "alert:read"),
        ],
        vec![
            ("holder_kind", "user"),
            ("holder", carol_id.as_str()),
            ("effect", "maybe"),
            ("permission", "alert:read"),
        ],
    ] {
        let refused = post("/admin/grants", &form).send().await.expect("answered");
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "{form:?}");
    }
    let cross_site = stack
        .http
        .post(format!("{}/admin/grants", stack.url))
        .header("origin", "https://evil.example")
        .header("cookie", cookie(&session))
        .form(&[
            ("holder_kind", "user"),
            ("holder", carol_id.as_str()),
            ("effect", "allow"),
            ("permission", "*:*"),
        ])
        .send()
        .await
        .expect("answered");
    assert_eq!(cross_site.status(), StatusCode::FORBIDDEN);
    assert_eq!(stack.audit_count().await, audit + 1, "nothing more changed");

    // an allow covering user:write is confirmed first
    let asked = grant(
        "user",
        &carol_id,
        &[("effect", "allow"), ("permission", "user:write")],
    )
    .send()
    .await
    .expect("answered");
    assert_eq!(asked.status(), StatusCode::OK);
    let text = asked.text().await.expect("a page");
    assert!(
        text.contains("Grant <code>user:write</code> to carol?"),
        "{text}"
    );
    assert!(text.contains("carol can change any grant, their own included"));
    assert_eq!(
        stack.audit_count().await,
        audit + 1,
        "asking writes nothing"
    );
    assert!(
        !stack
            .service
            .allowed(&carol, &ace_service::USER_WRITE)
            .await
            .expect("checks")
    );
    let confirmed = grant(
        "user",
        &carol_id,
        &[
            ("effect", "allow"),
            ("other", "user:write"),
            ("confirm", "yes"),
        ],
    )
    .send()
    .await
    .expect("answered");
    assert_eq!(
        location(&confirmed),
        format!("/admin/users/{carol_id}?done=granted")
    );
    assert_eq!(stack.audit_count().await, audit + 2);
    assert!(
        stack
            .service
            .allowed(&carol, &ace_service::USER_WRITE)
            .await
            .expect("checks")
    );
    let denied = grant(
        "user",
        &carol_id,
        &[("effect", "deny"), ("permission", "*:*")],
    )
    .send()
    .await
    .expect("answered");
    assert_eq!(
        location(&denied),
        format!("/admin/users/{carol_id}?done=granted"),
        "a deny isn't asked"
    );
    assert_eq!(stack.audit_count().await, audit + 3);

    // revoked
    let revoke = |holder_kind: &str, holder: &str, major: &str, minor: &str, effect: &str| {
        let form = [
            ("holder_kind", holder_kind.to_owned()),
            ("holder", holder.to_owned()),
            ("major", major.to_owned()),
            ("minor", minor.to_owned()),
            ("effect", effect.to_owned()),
        ];
        stack
            .http
            .post(format!("{}/admin/grants/revoke", stack.url))
            .header("origin", &stack.url)
            .header("cookie", cookie(&session))
            .form(&form)
    };
    for (major, minor, effect) in [("user", "write", "allow"), ("*", "*", "deny")] {
        let revoked = revoke("user", &carol_id, major, minor, effect)
            .send()
            .await
            .expect("answered");
        assert_eq!(
            location(&revoked),
            format!("/admin/users/{carol_id}?done=revoked")
        );
        assert_eq!(last_action(&stack).await, "revoke");
    }
    assert_eq!(stack.audit_count().await, audit + 5);
    let again = revoke("user", &carol_id, "user", "write", "allow")
        .send()
        .await
        .expect("answered");
    assert_eq!(again.status(), StatusCode::NOT_FOUND);
    let bad = revoke("user", &carol_id, "user:", "write", "allow")
        .send()
        .await
        .expect("answered");
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);

    // the administrator can't take their own user:write
    let audit = stack.audit_count().await;
    let refused = revoke("user", &boss_id, "*", "*", "allow")
        .send()
        .await
        .expect("answered");
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    let text = refused.text().await.expect("a page");
    assert!(
        text.contains("Not revoked: that would take user:write from you, and only another user with user:write could give it back."),
        "{text}"
    );
    let refused = grant(
        "user",
        &boss_id,
        &[("effect", "deny"), ("permission", "user:write")],
    )
    .send()
    .await
    .expect("answered");
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert!(
        refused
            .text()
            .await
            .expect("a page")
            .contains("would take user:write from you")
    );
    assert_eq!(stack.audit_count().await, audit, "nothing changed");
    assert!(
        stack
            .service
            .allowed(&boss, &ace_service::USER_WRITE)
            .await
            .expect("checks")
    );

    // left
    let left = post(
        &format!("/admin/groups/{group}/members/{carol_id}/remove"),
        &[("back", "user")],
    )
    .send()
    .await
    .expect("answered");
    assert_eq!(
        location(&left),
        format!("/admin/users/{carol_id}?done=left")
    );
    assert_eq!(stack.audit_count().await, audit + 1);
    assert_eq!(last_action(&stack).await, "remove_group_member");
    assert!(
        !stack
            .service
            .allowed(&carol, &ace_service::ALERT_READ)
            .await
            .expect("checks")
    );
    let again = post(
        &format!("/admin/groups/{group}/members/{carol_id}/remove"),
        &[],
    )
    .send()
    .await
    .expect("answered");
    assert_eq!(again.status(), StatusCode::NOT_FOUND);

    // a key, made and shown once
    grant_effect(&stack, &carol, "alert", "read", Effect::Allow).await;
    let keys = format!("/admin/users/{carol_id}/keys");
    let audit = stack.audit_count().await;
    for (what, form, says) in [
        (
            "user:self",
            vec![("name", "triage"), ("other", "user:self")],
            "No key was made: user:self is only ever a person&#39;s",
        ),
        (
            "text that isn't a pattern",
            vec![("name", "triage"), ("other", "alert")],
            "No key was made: alert isn&#39;t a pattern",
        ),
        (
            "no name",
            vec![("name", " "), ("scope", "alert:read")],
            "No key was made: an API key&#39;s name is 1 to 255 characters",
        ),
    ] {
        let refused = post(&keys, &form).send().await.expect("answered");
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "{what}");
        let text = refused.text().await.expect("a page");
        assert!(text.contains(says), "{what}: {text}");
        assert!(!text.contains("ace4k_"), "{what}");
    }
    assert_eq!(stack.audit_count().await, audit);
    let made = post(
        &keys,
        &[
            ("name", "triage"),
            ("mode", "restricted"),
            ("scope", "alert:read"),
        ],
    )
    .send()
    .await
    .expect("answered");
    assert_eq!(made.status(), StatusCode::CREATED);
    assert_eq!(made.headers()["cache-control"], "no-store");
    assert!(made.headers().get(LOCATION).is_none());
    let token = shown_secret(&made.text().await.expect("a page"));
    assert!(token.starts_with("ace4k_"));
    assert_eq!(stack.audit_count().await, audit + 1);
    assert_eq!(last_action(&stack).await, "create_api_key");
    let as_key = stack
        .service
        .authenticate_api_key(&token)
        .await
        .expect("works");
    assert!(
        stack
            .service
            .allowed(&as_key, &ace_service::ALERT_READ)
            .await
            .expect("checks")
    );
    let key = stack.service.api_keys(&boss, None).await.expect("reads")[0]
        .id
        .0;
    let shown = stack
        .get(&format!("/admin/users/{carol_id}"))
        .header("cookie", cookie(&session))
        .send()
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(shown.contains("<td>triage</td>"), "{shown}");
    assert!(!shown.contains(&token), "shown once");

    // changed
    let edit = stack
        .get(&format!("/admin/keys/{key}"))
        .header("cookie", cookie(&session))
        .send()
        .await
        .expect("answered");
    assert_eq!(edit.status(), StatusCode::OK);
    let edit = edit.text().await.expect("a page");
    assert!(edit.contains(r#"name="name" value="triage""#), "{edit}");
    assert!(edit.contains(r#"value="alert:read" checked"#));
    assert!(edit.contains(r#"value="restricted" checked"#));
    let refused = post(
        &format!("/admin/keys/{key}"),
        &[("name", "renamed"), ("other", "user:self")],
    )
    .send()
    .await
    .expect("answered");
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    let text = refused.text().await.expect("a page");
    assert!(
        text.contains("Not changed: user:self is only ever"),
        "{text}"
    );
    assert!(text.contains(r#"name="name" value="renamed""#));
    let changed = post(
        &format!("/admin/keys/{key}"),
        &[("name", "renamed"), ("mode", "inherit")],
    )
    .send()
    .await
    .expect("answered");
    assert_eq!(
        location(&changed),
        format!("/admin/users/{carol_id}?done=key")
    );
    assert_eq!(stack.audit_count().await, audit + 2);
    assert_eq!(last_action(&stack).await, "set_api_key_scope");
    let now = &stack.service.api_keys(&boss, None).await.expect("reads")[0];
    assert_eq!(now.name, "renamed");
    assert_eq!(
        (now.grants[0].major.as_str(), now.grants[0].minor.as_str()),
        ("*", "*")
    );

    // revoked
    let revoked = post(
        &format!("/admin/keys/{key}/revoke"),
        &[("owner", &carol_id)],
    )
    .send()
    .await
    .expect("answered");
    assert_eq!(
        location(&revoked),
        format!("/admin/users/{carol_id}?done=key-revoked")
    );
    assert_eq!(stack.audit_count().await, audit + 3);
    assert_eq!(last_action(&stack).await, "revoke_api_key");
    assert!(stack.service.authenticate_api_key(&token).await.is_err());
    let again = post(&format!("/admin/keys/{key}/revoke"), &[])
        .send()
        .await
        .expect("answered");
    assert_eq!(again.status(), StatusCode::NOT_FOUND);

    // the group, deleted
    let deleted = post(&format!("/admin/groups/{group}/delete"), &[])
        .send()
        .await
        .expect("answered");
    assert_eq!(location(&deleted), "/admin/users?done=deleted");
    assert_eq!(stack.audit_count().await, audit + 4);
    assert_eq!(last_action(&stack).await, "delete_group");
    let again = post(&format!("/admin/groups/{group}/delete"), &[])
        .send()
        .await
        .expect("answered");
    assert_eq!(again.status(), StatusCode::NOT_FOUND);
}

// ---- PLAN.md 5.11's signatures area ----

fn qa_time(seconds: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(1_800_000_000 + seconds, 0).expect("a time")
}

fn fixture_qa_rule(
    uuid: &str,
    name: &str,
    status: ace_service::QaStatus,
) -> ace_service::QaRuleSummary {
    ace_service::QaRuleSummary {
        signature_uuid: uuid.to_owned(),
        name: name.to_owned(),
        status,
        enabled: Some(true),
        namespace: Some(HOSTILE.to_owned()),
        path: Some(HOSTILE.to_owned()),
        tags: vec![HOSTILE.to_owned()],
        match_count: 7,
        stored_count: 3,
        version_count: 2,
        first_match_at: Some(qa_time(0)),
        last_match_at: Some(qa_time(60)),
    }
}

fn fixture_qa_match(id: i64, uuid: &str, version: &str, alerted: bool) -> ace_service::QaMatch {
    ace_service::QaMatch {
        id,
        signature_uuid: uuid.to_owned(),
        signature_version: version.to_owned(),
        rule: HOSTILE.to_owned(),
        namespace: HOSTILE.to_owned(),
        ruleset: Some(HOSTILE.to_owned()),
        sha256: "ab".repeat(32),
        file_path: HOSTILE.to_owned(),
        file_size: Some(1536),
        root: uuid::Uuid::from_u128(9),
        alerted,
        observable_id: 1,
        hit_count: 2,
        first_seen: qa_time(0),
        last_seen: qa_time(30),
        expires_at: qa_time(86_400),
    }
}

/// The area's view functions, called directly: the hub, the list with its filters and pages, a rule's
/// page with its versions and files, with and without `signature:download` and `signature:qa_purge`, a
/// match's page with its meta, the purge's confirm and its answer, each with a rule's and a file's
/// hostile text escaped, a link only percent-encoded, and nothing inline.
#[test]
fn the_signatures_views_draw_rules_versions_files_and_purges() {
    use ace_gui::signatures::{
        ConfirmPurgePage, HubPage, ListForm, MatchPage, PurgedPage, RulePage, YaraQaPage,
        list_view, match_row, match_view, rule_href, rule_view, short_version, size,
    };
    use ace_service::{
        QaMatchDetail, QaMatchPage, QaMatchSummary, QaRuleDetail, QaRulePage, QaRuleset, QaStatus,
        QaStringSummary, QaVersion,
    };
    let layout = || {
        Layout::new(
            "n",
            Theme::default(),
            Some("analyst".to_owned()),
            "/signatures",
        )
    };
    let encoded = "%22%3E%3Cscript%3Ealert%28%27x%27%29%3C%2Fscript%3E%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E%26amp%3B";
    assert_eq!(
        rule_href(HOSTILE),
        format!("/signatures/yara-qa/rules/{encoded}")
    );
    assert_eq!(size(10), "10 B");
    assert_eq!(size(1536), "1.5 KB");
    assert_eq!(size(3 << 30), "3.0 GB");
    assert_eq!(short_version(&"c".repeat(40)), "cccccccccc");
    assert_eq!(short_version("unknown"), "unknown");

    let hub = drawn_safely(&HubPage {
        layout: layout(),
        modules: vec![ace_gui::admin::Module {
            href: "/signatures/yara-qa",
            title: "Yara QA Results",
            description: "d",
        }],
    });
    assert!(
        hub.contains(r#"<a href="/signatures/yara-qa"><b>Yara QA Results</b>"#),
        "{hub}"
    );

    // the list
    let ruleset = QaRuleset {
        key: "k".repeat(64),
        commit: "c".repeat(40),
        built_at: qa_time(0),
        qa_rules_recorded: true,
    };
    let page = QaRulePage {
        rules: vec![
            fixture_qa_rule(HOSTILE, HOSTILE, QaStatus::Qa),
            fixture_qa_rule("plain", "plain", QaStatus::NotQa),
        ],
        total: 5,
        ruleset: Some(ruleset.clone()),
    };
    let mut form =
        ListForm::parse("q=%3Cb%3E&status=&sort=match_count&descending=true&limit=2&offset=2")
            .expect("a form");
    assert_eq!(form.q, "<b>");
    assert_eq!(form.status, "");
    let list = drawn_safely(&YaraQaPage {
        layout: layout(),
        view: list_view(form.clone(), &page),
    });
    assert!(
        list.contains(&format!(
            r#"<a href="/signatures/yara-qa/rules/{encoded}"><b>{HOSTILE_ESCAPED}</b></a>"#
        )),
        "{list}"
    );
    assert!(list.contains(r#"<a href="/signatures/yara-qa/rules/plain">"#));
    assert!(list.contains(r#"value="&#60;b&#62;""#), "{list}");
    assert!(
        list.contains(r#"<option value="" selected>All</option>"#),
        "{list}"
    );
    assert!(
        list.contains(r#"<option value="match_count" selected>"#),
        "{list}"
    );
    assert!(list.contains("3–4 of 5"), "{list}");
    assert!(list.contains("q=%3Cb%3E&#38;status=&#38;has_matches=&#38;sort=match_count&#38;descending=true&#38;limit=2&#38;offset=0\" rel=\"prev\""), "{list}");
    assert!(list.contains("offset=4\" rel=\"next\""), "{list}");
    assert!(!list.contains("class=\"warning\""), "{list}");
    form.offset = 0;
    let none = QaRulePage {
        rules: vec![],
        total: 0,
        ruleset: None,
    };
    let empty = drawn_safely(&YaraQaPage {
        layout: layout(),
        view: list_view(form, &none),
    });
    assert!(empty.contains("No signatures match these filters."));
    assert!(empty.contains("No ruleset has been built yet"), "{empty}");
    assert!(!empty.contains("rel=\"prev\"") && !empty.contains("rel=\"next\""));
    for bad in [
        "status=missing",
        "sort=bogus",
        "has_matches=maybe",
        "limit=x",
        "offset=-1",
    ] {
        assert!(ListForm::parse(bad).is_err(), "{bad}");
    }
    let defaults = ListForm::parse("").expect("a form");
    assert_eq!(defaults.status, "qa");
    assert_eq!(defaults.limit, 50);

    // a rule's page
    let current = "c".repeat(40);
    let detail = QaRuleDetail {
        rule: fixture_qa_rule(HOSTILE, HOSTILE, QaStatus::Qa),
        versions: vec![
            QaVersion {
                signature_version: current.clone(),
                rule: HOSTILE.to_owned(),
                namespace: HOSTILE.to_owned(),
                match_count: 4,
                stored_count: 2,
                first_match_at: qa_time(0),
                last_match_at: qa_time(60),
            },
            QaVersion {
                signature_version: HOSTILE.to_owned(),
                rule: HOSTILE.to_owned(),
                namespace: HOSTILE.to_owned(),
                match_count: 3,
                stored_count: 1,
                first_match_at: qa_time(0),
                last_match_at: qa_time(10),
            },
        ],
        ruleset: Some(ruleset.clone()),
    };
    let matches = QaMatchPage {
        matches: vec![
            fixture_qa_match(12, HOSTILE, HOSTILE, true),
            fixture_qa_match(11, HOSTILE, &current, false),
        ],
        next: Some(11),
    };
    let full = drawn_safely(&RulePage {
        layout: layout(),
        view: rule_view(&detail, Some(HOSTILE), Some(20), &matches, true, true),
    });
    let rule = format!("/signatures/yara-qa/rules/{encoded}");
    // a query encodes a space as +
    let query = encoded.replace("%20", "+");
    for part in [
        format!(
            r#"<a href="{rule}?version=cccccccccccccccccccccccccccccccccccccccc"><code title="{current}">cccccccccc</code></a> <span class="badge current">current</span>"#
        ),
        format!(r#"<b><code title="{HOSTILE_ESCAPED}">{HOSTILE_ESCAPED}</code></b>"#),
        format!(
            r#"<a href="/api/yara-qa/v1/rules/{encoded}/download?version={query}" title="password: infected">Download all (this version)</a>"#
        ),
        format!(r#"<a href="{rule}/purge?version={query}">Purge this version…</a>"#),
        format!(
            r#"<a href="{rule}/purge?version={query}" title="every version but the one loaded now">Purge older versions… (1 files of 1 version)</a>"#
        ),
        format!(r#"<form method="get" action="{rule}/purge" id="qa-files">"#),
        r#"<input type="checkbox" name="match_id" value="12""#.to_owned(),
        format!(r#"<button type="submit" formaction="{rule}/download""#),
        "<button type=\"submit\">Purge selected…</button>".to_owned(),
        r#"<a href="/api/yara-qa/v1/matches/12/download" title="password: infected">Download</a>"#
            .to_owned(),
        format!(
            r#"<a href="/alerts/{}">Alert</a>"#,
            uuid::Uuid::from_u128(9)
        ),
        r#"<a href="/signatures/yara-qa/matches/11">Match</a>"#.to_owned(),
        format!(r#"<a href="{rule}?version={query}">First</a>"#),
        format!(r#"<a href="{rule}?version={query}&#38;after=11" rel="next">Next</a>"#),
        format!("<td class=\"qa-text\">{HOSTILE_ESCAPED}</td>"),
        "1.5 KB".to_owned(),
        "Loaded now: commit cccccccccc".to_owned(),
    ] {
        assert!(full.contains(&part), "{part}: {full}");
    }
    // the second file's root isn't an alert
    assert_eq!(full.matches(">Alert</a>").count(), 1);
    let reader = drawn_safely(&RulePage {
        layout: layout(),
        view: rule_view(&detail, None, None, &matches, false, false),
    });
    for absent in [
        "checkbox",
        "<form method=\"get\"",
        "/download",
        "/purge",
        "First</a>",
        "All versions",
    ] {
        assert!(!reader.contains(absent), "{absent}: {reader}");
    }
    assert!(reader.contains("rel=\"next\""));

    // a match's page
    let mut meta = serde_json::Map::new();
    meta.insert(
        "description".to_owned(),
        serde_json::Value::String(HOSTILE.to_owned()),
    );
    let shown = drawn_safely(&MatchPage {
        layout: layout(),
        view: match_view(
            &QaMatchDetail {
                qa_match: fixture_qa_match(12, HOSTILE, HOSTILE, true),
                summary: Some(QaMatchSummary {
                    meta,
                    tags: vec![HOSTILE.to_owned()],
                    commit: Some(HOSTILE.to_owned()),
                    strings: vec![QaStringSummary {
                        identifier: HOSTILE.to_owned(),
                        count: 3,
                        first_offset: 255,
                    }],
                }),
            },
            false,
        ),
    });
    for part in [
        format!(
            r#"<td class="qa-text"><code>{HOSTILE_ESCAPED}</code></td><td>3</td><td><code>0xff</code></td>"#
        ),
        format!(
            r#"<pre class="qa-meta">{{
  &#34;description&#34;: &#34;\{HOSTILE_ESCAPED}"#
        ),
        r#"<a href="/api/yara-qa/v1/matches/12/record">Full match record (JSON)</a>"#.to_owned(),
        format!(r#"<a href="{rule}">{HOSTILE_ESCAPED}</a>"#),
    ] {
        assert!(shown.contains(&part), "{part}: {shown}");
    }
    assert!(
        !shown.contains("/download"),
        "no download without signature:download"
    );
    let bare = drawn_safely(&MatchPage {
        layout: layout(),
        view: match_view(
            &QaMatchDetail {
                qa_match: fixture_qa_match(13, "u", "v", false),
                summary: None,
            },
            true,
        ),
    });
    assert!(bare.contains("The record isn't one the YARA module writes"));
    assert!(bare.contains("(not an alert)"));
    assert!(bare.contains(r#"href="/api/yara-qa/v1/matches/13/download""#));

    // the confirm and the answer
    let confirm = drawn_safely(&ConfirmPurgePage {
        layout: layout(),
        view: ace_gui::signatures::PurgeView {
            rule: HOSTILE.to_owned(),
            rule_href: rule.clone(),
            action: format!("{rule}/purge"),
            versions: vec![],
            matches: vec![match_row(
                &fixture_qa_match(12, HOSTILE, HOSTILE, true),
                false,
            )],
            files: 1,
            reason: HOSTILE.to_owned(),
            max_reason: 1024,
            problem: Some(HOSTILE.to_owned()),
        },
    });
    for part in [
        format!("<h1>Purge 1 stored file of {HOSTILE_ESCAPED}?</h1>"),
        format!(r#"<form method="post" action="{rule}/purge" class="fields">"#),
        r#"<input type="hidden" name="match_id" value="12">"#.to_owned(),
        format!(r#"maxlength="1024" rows="3">{HOSTILE_ESCAPED}</textarea>"#),
        format!("Nothing was purged: {HOSTILE_ESCAPED}"),
        format!(r#"<a href="{rule}">Cancel</a>"#),
    ] {
        assert!(confirm.contains(&part), "{part}: {confirm}");
    }
    let purged = drawn_safely(&PurgedPage {
        layout: layout(),
        uuid: HOSTILE.to_owned(),
        rule_href: rule.clone(),
        purged: 500,
        remaining: 3,
        again: Some(format!("{rule}/purge?version=v")),
    });
    assert!(
        purged.contains(&format!(
            "Purged 500 stored files of <code>{HOSTILE_ESCAPED}</code>. 3 more are left"
        )),
        "{purged}"
    );
    assert!(purged.contains(&format!(
        r#"<a href="{rule}/purge?version=v">Purge again…</a>"#
    )));
}

/// A kept QA match, as the core's recorder writes one, with a hostile file path and meta.
async fn gui_qa_match(
    stack: &Stack,
    uuid: &str,
    version: &str,
    alert: Option<uuid::Uuid>,
    n: u8,
) -> i64 {
    let root = alert.unwrap_or_else(uuid::Uuid::new_v4);
    sqlx::query_scalar(
        "INSERT INTO yara.qa_matches
             (signature_uuid, signature_version, rule, namespace, sha256, file_path, root_id,
              observable_id, match, expires_at)
         VALUES ($1, $2, $3, 'ns', $4, $5, $6, 1, $7, now() + interval '30 days')
         RETURNING id",
    )
    .bind(uuid)
    .bind(version)
    .bind(HOSTILE)
    .bind(format!("{n:02x}").repeat(32))
    .bind(HOSTILE)
    .bind(root)
    .bind(serde_json::json!({
        "rule": HOSTILE, "namespace": "ns",
        "meta": {"uuid": uuid, "modifiers": "qa", "description": HOSTILE},
        "tags": ["candidate"], "commit": version, "ruleset": null, "target": "a",
        "strings": [[4, "$a", {"base64": "RVZJTA=="}]], "context": [], "match_context": [],
    }))
    .fetch_one(stack.test_db.db().pool())
    .await
    .expect("a QA match")
}

async fn qa_rows(stack: &Stack) -> i64 {
    sqlx_count(&stack.test_db, "SELECT count(*) FROM yara.qa_matches").await
}

/// The area through the server: signed out goes to the login; without `signature:read` every page and
/// form is 403 and the layout has no Signatures link; with it the hub, the list, a rule with a hostile
/// uuid by its encoded link, and a match draw, with no downloads or purges; `signature:download` adds
/// the API's download links and Download selected, which goes on to the API; `signature:qa_purge` adds
/// the purges, whose confirm lists what goes and refuses what isn't the rule's, and whose post, from this
/// site only, removes it with one audit row carrying the reason. Each refusal changes nothing.
#[tokio::test]
async fn the_signatures_area_needs_signature_read_then_download_and_purge() {
    let stack = stack().await;
    let alice = user(&stack, "alice").await;
    let pool = stack.test_db.db().pool().clone();
    sqlx::query(
        "INSERT INTO yara.rulesets
             (key, commit, tree, sources_sha256, yara_x_version, files, left_out, qa_rules)
         VALUES (repeat('b', 64), 'c0ffee', 'tree', 'sources', $1, '[]', '[]', $2)",
    )
    .bind(ace_core::rulesets::YARA_X_VERSION)
    .bind(serde_json::json!([
        {"namespace": "ns", "path": "ns/qa.yar", "name": "qa_rule", "uuid": HOSTILE,
         "enabled": true, "tags": ["candidate"]},
        {"namespace": "ns", "path": "ns/new.yar", "name": "never_matched", "uuid": "never",
         "enabled": false, "tags": []},
    ]))
    .execute(&pool)
    .await
    .expect("a ruleset");
    let alert_root = uuid::Uuid::new_v4();
    let first = gui_qa_match(&stack, HOSTILE, "c0ffee", Some(alert_root), 1).await;
    let second = gui_qa_match(&stack, HOSTILE, "old", None, 2).await;
    let third = gui_qa_match(&stack, HOSTILE, "old", None, 3).await;
    let other = gui_qa_match(&stack, "other-rule", "c0ffee", None, 4).await;
    let encoded = "%22%3E%3Cscript%3Ealert%28%27x%27%29%3C%2Fscript%3E%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E%26amp%3B";
    let rule = format!("/signatures/yara-qa/rules/{encoded}");

    for (path, back) in [
        ("/signatures", "/login?next=%2Fsignatures"),
        ("/signatures/yara-qa", "/login?next=%2Fsignatures%2Fyara-qa"),
    ] {
        let page = stack.get(path).send().await.expect("answered");
        assert_eq!(page.status(), StatusCode::SEE_OTHER, "{path}");
        assert_eq!(location(&page), back);
    }
    let post = stack
        .post(
            &format!("{rule}/purge"),
            &[("match_id", &first.to_string())],
        )
        .send()
        .await
        .expect("answered");
    assert_eq!(location(&post), "/login");

    let session = session_of(&stack, "alice").await;
    let get = |path: String| stack.get(&path).header("cookie", cookie(&session)).send();
    let purge = |form: Vec<(&'static str, String)>| {
        let form: Vec<(&str, &str)> = form.iter().map(|(k, v)| (*k, v.as_str())).collect();
        stack
            .post(&format!("{rule}/purge"), &form)
            .header("cookie", cookie(&session))
            .send()
    };
    let audit = stack.audit_count().await;
    for path in [
        "/signatures".to_owned(),
        "/signatures/yara-qa".to_owned(),
        rule.clone(),
        format!("/signatures/yara-qa/matches/{first}"),
        format!("{rule}/purge?match_id={first}"),
        format!("{rule}/download?match_id={first}"),
    ] {
        let page = get(path.clone()).await.expect("answered");
        assert_eq!(page.status(), StatusCode::FORBIDDEN, "{path}");
        assert!(
            page.text()
                .await
                .expect("a page")
                .contains("signature:read"),
            "{path}"
        );
    }
    let refused = purge(vec![("match_id", first.to_string())])
        .await
        .expect("answered");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let home = get("/".to_owned())
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(!home.contains(r#"href="/signatures""#), "{home}");

    // signature:read: the pages, with no downloads or purges
    grant_to(&stack, &alice, "signature", "read").await;
    let hub = get("/signatures".to_owned()).await.expect("answered");
    assert_eq!(hub.status(), StatusCode::OK);
    let hub = hub.text().await.expect("a page");
    assert!(
        hub.contains(r#"<a href="/signatures">Signatures</a>"#),
        "{hub}"
    );
    assert!(
        hub.contains(r#"<a href="/signatures/yara-qa"><b>Yara QA Results</b>"#),
        "{hub}"
    );
    let list = get("/signatures/yara-qa".to_owned())
        .await
        .expect("answered");
    assert_eq!(list.status(), StatusCode::OK);
    let list = list.text().await.expect("a page");
    assert!(
        list.contains(&format!(r#"<a href="{rule}"><b>qa_rule</b></a>"#)),
        "{list}"
    );
    assert!(list.contains(r#"<a href="/signatures/yara-qa/rules/never"><b>never_matched</b></a>"#));
    assert!(
        !list.contains("other-rule"),
        "not in QA mode, so not listed by default"
    );
    assert!(!list.contains("<script>alert"), "{list}");
    let all = get(
        "/signatures/yara-qa?status=&has_matches=true&sort=match_count&descending=true".to_owned(),
    )
    .await
    .expect("answered")
    .text()
    .await
    .expect("a page");
    assert!(
        all.contains("other-rule") && !all.contains("never_matched"),
        "{all}"
    );
    assert!(all.contains("1–2 of 2"), "{all}");
    let paged = get("/signatures/yara-qa?status=&limit=1&offset=1".to_owned())
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(
        paged.contains("2–2 of 3")
            && paged.contains("rel=\"prev\"")
            && paged.contains("rel=\"next\""),
        "{paged}"
    );

    let page = get(rule.clone()).await.expect("answered");
    assert_eq!(page.status(), StatusCode::OK);
    let page = page.text().await.expect("a page");
    assert!(
        page.contains(&format!(
            r#"<td class="qa-text"><code>{HOSTILE_ESCAPED}</code></td>"#
        )),
        "{page}"
    );
    assert!(
        page.contains(r#"<a href="/signatures/yara-qa/matches"#),
        "{page}"
    );
    // no root of that id is an alert, so no file links to one
    assert!(!page.contains(&format!("/alerts/{alert_root}")), "{page}");
    assert!(
        page.contains(r#"<span class="badge current">current</span>"#),
        "{page}"
    );
    for absent in ["checkbox", "/download", "/purge"] {
        assert!(!page.contains(absent), "{absent}: {page}");
    }
    let old = get(format!("{rule}?version=old"))
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(
        old.contains(&format!("matches/{second}\""))
            && !old.contains(&format!("matches/{first}\"")),
        "{old}"
    );
    let shown = get(format!("/signatures/yara-qa/matches/{first}"))
        .await
        .expect("answered");
    assert_eq!(shown.status(), StatusCode::OK);
    let shown = shown.text().await.expect("a page");
    assert!(shown.contains("<code>0x4</code>"), "{shown}");
    assert!(shown.contains(&format!(
        r#"<a href="/api/yara-qa/v1/matches/{first}/record">"#
    )));
    assert!(!shown.contains("<script>alert"), "{shown}");

    for (path, status) in [
        (
            "/signatures/yara-qa?sort=bogus".to_owned(),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/signatures/yara-qa?limit=0".to_owned(),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/signatures/yara-qa/rules/nothing-here".to_owned(),
            StatusCode::NOT_FOUND,
        ),
        (format!("{rule}?after=x"), StatusCode::BAD_REQUEST),
        (
            "/signatures/yara-qa/matches/x".to_owned(),
            StatusCode::BAD_REQUEST,
        ),
        (
            format!("/signatures/yara-qa/matches/{}", other + 1000),
            StatusCode::NOT_FOUND,
        ),
        // the confirm needs qa_purge before anything else
        (
            format!("{rule}/purge?match_id={first}"),
            StatusCode::FORBIDDEN,
        ),
    ] {
        assert_eq!(
            get(path.clone()).await.expect("answered").status(),
            status,
            "{path}"
        );
    }
    let refused = purge(vec![("match_id", first.to_string())])
        .await
        .expect("answered");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert!(
        refused
            .text()
            .await
            .expect("a page")
            .contains("signature:qa_purge")
    );
    assert_eq!(qa_rows(&stack).await, 4);
    assert_eq!(stack.audit_count().await, audit + 1, "only the grant");

    // signature:download: the API's downloads
    grant_to(&stack, &alice, "signature", "download").await;
    let page = get(rule.clone())
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(page.contains(&format!(r#"<a href="/api/yara-qa/v1/rules/{encoded}/download" title="password: infected">Download all</a>"#)), "{page}");
    assert!(page.contains(&format!(
        r#"<a href="/api/yara-qa/v1/matches/{first}/download""#
    )));
    assert!(page.contains(&format!(
        r#"<button type="submit" formaction="{rule}/download""#
    )));
    assert!(!page.contains("/purge"), "{page}");
    let sent = get(format!(
        "{rule}/download?match_id={first}&match_id={second}"
    ))
    .await
    .expect("answered");
    assert_eq!(sent.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&sent),
        format!("/api/yara-qa/v1/rules/{encoded}/download?match_ids={first}%2C{second}")
    );
    for path in [
        format!("{rule}/download"),
        format!("{rule}/download?match_id=x"),
    ] {
        assert_eq!(
            get(path.clone()).await.expect("answered").status(),
            StatusCode::BAD_REQUEST,
            "{path}"
        );
    }

    // signature:qa_purge: the confirm, then the purge
    grant_to(&stack, &alice, "signature", "qa_purge").await;
    let audit = stack.audit_count().await;
    let page = get(rule.clone())
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(page.contains(&format!(r#"<a href="{rule}/purge?version=old" title="every version but the one loaded now">Purge older versions… (2 files of 1 version)</a>"#)), "{page}");
    let confirm = get(format!("{rule}/purge?match_id={first}"))
        .await
        .expect("answered");
    assert_eq!(confirm.status(), StatusCode::OK);
    let confirm = confirm.text().await.expect("a page");
    assert!(
        confirm.contains("<h1>Purge 1 stored file of qa_rule?</h1>"),
        "{confirm}"
    );
    assert!(confirm.contains(&format!(
        r#"<input type="hidden" name="match_id" value="{first}">"#
    )));
    let by_version = get(format!("{rule}/purge?version=old"))
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(
        by_version.contains("<h1>Purge 2 stored files of qa_rule?</h1>"),
        "{by_version}"
    );
    assert!(by_version.contains(r#"<input type="hidden" name="version" value="old">"#));
    for (path, status) in [
        (format!("{rule}/purge"), StatusCode::BAD_REQUEST),
        (
            format!("{rule}/purge?version=old&match_id={first}"),
            StatusCode::BAD_REQUEST,
        ),
        (format!("{rule}/purge?match_id=x"), StatusCode::BAD_REQUEST),
        (
            format!("{rule}/purge?match_id={other}"),
            StatusCode::NOT_FOUND,
        ),
        (format!("{rule}/purge?version=nope"), StatusCode::NOT_FOUND),
    ] {
        assert_eq!(
            get(path.clone()).await.expect("answered").status(),
            status,
            "{path}"
        );
    }

    // refusals that change nothing: from another site, a reason too long, no target, both
    let cross = stack
        .http
        .post(format!("{}{rule}/purge", stack.url))
        .header("origin", "https://evil.example")
        .header("cookie", cookie(&session))
        .form(&[("match_id", first.to_string())])
        .send()
        .await
        .expect("answered");
    assert_eq!(cross.status(), StatusCode::FORBIDDEN);
    let long = purge(vec![
        ("match_id", first.to_string()),
        ("reason", "x".repeat(1025)),
    ])
    .await
    .expect("answered");
    assert_eq!(long.status(), StatusCode::BAD_REQUEST);
    let long = long.text().await.expect("a page");
    assert!(
        long.contains("Nothing was purged: a reason is at most 1024 characters"),
        "{long}"
    );
    assert!(long.contains(&format!("rows=\"3\">{}</textarea>", "x".repeat(1025))));
    for form in [
        vec![("reason", "why".to_owned())],
        vec![
            ("match_id", first.to_string()),
            ("version", "old".to_owned()),
        ],
        vec![("match_id", "x".to_owned())],
    ] {
        let refused = purge(form.clone()).await.expect("answered");
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "{form:?}");
    }
    assert_eq!(qa_rows(&stack).await, 4);
    assert_eq!(stack.audit_count().await, audit);

    // another rule's match, named in this rule's purge, stays
    let elsewhere = purge(vec![("match_id", other.to_string())])
        .await
        .expect("answered");
    assert_eq!(elsewhere.status(), StatusCode::OK);
    assert!(
        elsewhere
            .text()
            .await
            .expect("a page")
            .contains("Purged 0 stored files")
    );
    assert_eq!(qa_rows(&stack).await, 4);
    assert_eq!(
        stack.audit_count().await,
        audit,
        "a purge that finds nothing has no row"
    );

    let done = purge(vec![
        ("match_id", first.to_string()),
        ("reason", "<b>false positive</b>".to_owned()),
    ])
    .await
    .expect("answered");
    assert_eq!(done.status(), StatusCode::OK);
    let done = done.text().await.expect("a page");
    assert!(
        done.contains(&format!(
            "Purged 1 stored file of <code>{HOSTILE_ESCAPED}</code>."
        )),
        "{done}"
    );
    assert!(!done.contains("Purge again"));
    assert_eq!(qa_rows(&stack).await, 3);
    assert_eq!(stack.audit_count().await, audit + 1);
    assert_eq!(last_action(&stack).await, "purge_qa_matches");
    let details: String =
        sqlx::query_scalar("SELECT details::text FROM service.audit ORDER BY id DESC LIMIT 1")
            .fetch_one(&pool)
            .await
            .expect("a row");
    assert!(details.contains("<b>false positive</b>"), "{details}");

    let versions = purge(vec![("version", "old".to_owned())])
        .await
        .expect("answered");
    assert_eq!(versions.status(), StatusCode::OK);
    assert!(
        versions
            .text()
            .await
            .expect("a page")
            .contains("Purged 2 stored files")
    );
    assert_eq!(qa_rows(&stack).await, 1);
    assert_eq!(stack.audit_count().await, audit + 2);
    let _ = third;
}

// ---- PLAN.md 5.11's events area (6b): adding alerts to an event ----

use ace_gui::events::{AddPage, AddedPage, add_view, added_view};
use ace_service::{AddedToEvent, Event as GuiEvent};

fn fixture_event(id: i64, day: &str, name: &str) -> GuiEvent {
    GuiEvent {
        id,
        uuid: uuid::Uuid::from_u128(id as u128),
        creation_date: day.parse().expect("a date"),
        name: name.to_owned(),
        status: "OPEN".to_owned(),
        remediation: "not remediated".to_owned(),
        kind: "phish".to_owned(),
        vector: "corporate email".to_owned(),
        risk_level: "0".to_owned(),
        prevention_tool: "response team".to_owned(),
        campaign: None,
        comment: None,
        event_time: None,
        alert_time: None,
        ownership_time: None,
        disposition_time: None,
        contain_time: None,
        remediation_time: None,
        owner: None,
        malware: Vec::new(),
        disposition: "DELIVERY".to_owned(),
        alerts: Vec::new(),
        tags: Vec::new(),
        alert_tags: Vec::new(),
        created_at: chrono::Utc::now(),
    }
}

/// The view functions draw the open and closed events to choose, labelled as ace3 labels them, the
/// closed ones' Show more and First, a new event's fields and times, and with no alerts only those; the
/// answer says what was added and what was gone. Every value is escaped and nothing is inline.
#[test]
fn the_event_views_draw_the_choices_and_the_answer() {
    let alerts = vec![uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2)];
    let open = [
        fixture_event(3, "2026-01-01", "older"),
        fixture_event(4, "2026-02-01", HOSTILE),
    ];
    let closed = [fixture_event(9, "2025-12-01", "closed one")];
    let view = add_view(
        alerts.clone(),
        &open,
        true,
        &closed,
        Some(9),
        true,
        "/?f=disposition:OPEN".to_owned(),
    );
    assert_eq!(view.open[0].id, 4, "newest first");
    let page = drawn_safely(&AddPage {
        layout: Layout::signed_out("n"),
        view,
    });
    assert!(page.contains("Add 2 alerts to an event"), "{page}");
    assert!(page.contains(&format!(
        "2026-02-01 - phish - corporate email - {HOSTILE_ESCAPED}"
    )));
    for id in &alerts {
        assert_eq!(
            page.matches(&format!(r#"name="alert" value="{id}""#))
                .count(),
            2,
            "in the add form and the Show more form"
        );
    }
    assert!(page.contains(r#"<input type="radio" name="event" value="4">"#));
    assert!(page.contains(r#"<input type="radio" name="event" value="9">"#));
    assert!(page.contains(r#"<input type="radio" name="event" value="NEW">"#));
    assert!(page.contains(r#"form="more-events" name="closed_after" value="9">Show more…"#));
    assert!(page.contains(r#"form="more-events" name="closed_after" value="">First"#));
    assert!(page.contains("More open events than these exist"));
    assert!(page.contains(r#"name="remediation_time""#));
    assert!(page.contains(r#"<input type="hidden" name="next" value="/?f=disposition:OPEN">"#));

    // Create Event: no alerts, no events to choose, a new one's fields
    let page = drawn_safely(&AddPage {
        layout: Layout::signed_out("n"),
        view: add_view(Vec::new(), &[], false, &[], None, false, "/".to_owned()),
    });
    assert!(page.contains("<h1>Create Event</h1>"), "{page}");
    assert!(page.contains(r#"<input type="hidden" name="event" value="NEW">"#));
    assert!(!page.contains(r#"type="radio""#));
    assert!(!page.contains("more-events"));

    // the answer
    let mut event = fixture_event(4, "2026-02-01", HOSTILE);
    event.alerts = Vec::new();
    let added = AddedToEvent {
        event,
        made: false,
        added: vec![alerts[0]],
        already: vec![alerts[1]],
        missing: vec![uuid::Uuid::from_u128(0xDEAD)],
    };
    let page = drawn_safely(&AddedPage {
        layout: Layout::signed_out("n"),
        view: added_view(&added, "/".to_owned()),
    });
    assert!(page.contains("Added to the event"), "{page}");
    assert!(page.contains(HOSTILE_ESCAPED));
    assert!(page.contains("1 alert added, 1 in it already"), "{page}");
    assert!(page.contains(&format!(r#"<a href="/alerts/{}">"#, alerts[0])));
    assert!(page.contains("1 of the ticked alerts no longer exist"));
    assert!(page.contains(&uuid::Uuid::from_u128(0xDEAD).to_string()));
}

/// A time as the add form sends it: a `datetime-local` value, with or without seconds, or ace3's form, in
/// UTC; empty is none.
#[test]
fn an_event_time_is_read_as_the_form_sends_it() {
    use ace_gui::events::form_time;
    let want: chrono::DateTime<chrono::Utc> = "2026-01-02T03:04:05Z".parse().expect("a time");
    assert_eq!(form_time("2026-01-02T03:04:05"), Ok(Some(want)));
    assert_eq!(form_time("2026-01-02 03:04:05"), Ok(Some(want)));
    assert_eq!(
        form_time("2026-01-02T03:04"),
        Ok(Some("2026-01-02T03:04:00Z".parse().expect("a time")))
    );
    assert_eq!(form_time("  "), Ok(None));
    assert!(form_time("yesterday").is_err());
    assert!(form_time("2026-13-01T00:00").is_err());
}

/// An event made by SQL on a day, with a status, as ace3's defaults make one.
async fn gui_event(stack: &Stack, name: &str, day: &str, status: &str) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO events.events
             (creation_date, name, status_id, remediation_id, type_id, vector_id, risk_level_id,
              prevention_tool_id)
         VALUES ($2::date, $1, (SELECT id FROM events.statuses WHERE value = $3),
                 (SELECT min(id) FROM events.remediations), (SELECT min(id) FROM events.types),
                 (SELECT min(id) FROM events.vectors), (SELECT min(id) FROM events.risk_levels),
                 (SELECT min(id) FROM events.prevention_tools))
         RETURNING id",
    )
    .bind(name)
    .bind(day)
    .bind(status)
    .fetch_one(stack.test_db.db().pool())
    .await
    .expect("makes an event")
}

async fn alerts_in_event(stack: &Stack, event: i64) -> BTreeSet<uuid::Uuid> {
    sqlx::query_scalar("SELECT root_id FROM events.event_alerts WHERE event_id = $1")
        .bind(event)
        .fetch_all(stack.test_db.db().pool())
        .await
        .expect("reads")
        .into_iter()
        .collect()
}

/// Through the server: signed out goes to the login; the page and its post need `event:write`, and the
/// page `event:read` too; the alert list's form opens it with the ticked alerts; the closed events come a
/// page at a time; a post adds to an event, or makes one, in one audited write and says which alerts
/// were gone; Create Event makes one with none; and each refusal, a cross-site post among them, changes
/// nothing.
#[tokio::test]
async fn alerts_are_added_to_an_event_through_the_form() {
    let stack = stack().await;
    let alice = user(&stack, "alice").await;
    grant_alert_read(&stack, &alice).await;
    let session = session_of(&stack, "alice").await;
    let one = list_alert(&stack, "one", "2026-05-01T10:00:00Z", None).await;
    let two = list_alert(&stack, "two", "2026-05-02T10:00:00Z", None).await;
    let gone = uuid::Uuid::from_u128(0x6011E);
    let open = gui_event(&stack, HOSTILE, "2026-04-01", "OPEN").await;
    let mut closed = Vec::new();
    for day in 1..=17 {
        closed.push(
            gui_event(
                &stack,
                &format!("closed {day}"),
                &format!("2026-03-{day:02}"),
                "CLOSED",
            )
            .await,
        );
    }
    let get = |path: String| {
        let request = stack.get(&path).header("cookie", cookie(&session));
        async move { request.send().await.expect("answered") }
    };
    let post = |form: Vec<(&'static str, String)>| {
        let request = stack
            .http
            .post(format!("{}/events/add", stack.url))
            .header("origin", &stack.url)
            .header("cookie", cookie(&session))
            .form(&form);
        async move { request.send().await.expect("answered") }
    };
    let ticked = format!("/events/add?alert={one}&alert={two}&alert={gone}&next=%2F%3Fsize%3D10");

    // the alert list's bulk form opens it
    let list = get("/".to_owned()).await.text().await.expect("a page");
    assert!(
        list.contains(r#"<button type="submit" formaction="/events/add" formmethod="get">Add to Event</button>"#),
        "{list}"
    );

    // signed out
    let signed_out = stack.get(&ticked).send().await.expect("answered");
    assert_eq!(signed_out.status(), StatusCode::SEE_OTHER);
    assert!(location(&signed_out).starts_with("/login?next=%2Fevents%2Fadd"));

    // without event:write, then without event:read, refused, and the post changes nothing
    let audit = stack.audit_count().await;
    assert_eq!(get(ticked.clone()).await.status(), StatusCode::FORBIDDEN);
    let refused = post(vec![
        ("event", open.to_string()),
        ("alert", one.to_string()),
    ])
    .await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    grant_to(&stack, &alice, "event", "write").await;
    assert_eq!(get(ticked.clone()).await.status(), StatusCode::FORBIDDEN);
    grant_to(&stack, &alice, "event", "read").await;
    let audit = audit + 2;
    assert_eq!(stack.audit_count().await, audit, "only the grants' rows");
    assert!(alerts_in_event(&stack, open).await.is_empty());

    // the page: the open event, the newest 15 closed, Show more, and the ticked alerts
    let response = get(ticked.clone()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let page = response.text().await.expect("a page");
    assert!(inline_free(&page.replace(HOSTILE_ESCAPED, "")));
    assert!(page.contains("Add 3 alerts to an event"), "{page}");
    assert!(page.contains(HOSTILE_ESCAPED));
    assert!(!page.contains(HOSTILE));
    assert!(page.contains(&format!(r#"value="{}"> 2026-03-17 - phish"#, closed[16])));
    assert!(page.contains(&format!(r#"value="{}"> 2026-03-03 - phish"#, closed[2])));
    assert!(!page.contains("2026-03-02 - phish"));
    assert!(page.contains(&format!(
        r#"name="closed_after" value="{}">Show more…"#,
        closed[2]
    )));
    assert!(page.contains(r#"<input type="hidden" name="next" value="/?size=10">"#));
    // the next page of closed events
    let more = get(format!("{ticked}&closed_after={}", closed[2]))
        .await
        .text()
        .await
        .expect("a page");
    assert!(more.contains("2026-03-02 - phish") && more.contains("2026-03-01 - phish"));
    assert!(!more.contains("2026-03-03 - phish"));
    assert!(!more.contains("Show more"));
    assert!(more.contains(r#"name="closed_after" value="">First"#));
    // a page asked for wrongly
    for bad in [
        "/events/add?alert=x".to_owned(),
        "/events/add?alert=1&closed_after=nope".to_owned(),
        format!(
            "/events/add?{}",
            (0..=ace_gui::list::MAX_BULK)
                .map(|_| format!("alert={one}"))
                .collect::<Vec<_>>()
                .join("&")
        ),
    ] {
        assert_eq!(get(bad).await.status(), StatusCode::BAD_REQUEST);
    }

    // adding to the open event: one row, the gone alert said
    let alerts = |ids: &[uuid::Uuid]| {
        ids.iter()
            .map(|id| ("alert", id.to_string()))
            .collect::<Vec<_>>()
    };
    let mut form = vec![
        ("event", open.to_string()),
        ("next", "/?size=10".to_owned()),
    ];
    form.extend(alerts(&[one, gone]));
    let response = post(form).await;
    assert_eq!(response.status(), StatusCode::OK);
    let page = response.text().await.expect("a page");
    assert!(inline_free(&page.replace(HOSTILE_ESCAPED, "")));
    assert!(!page.contains(HOSTILE));
    assert!(page.contains("Added to the event"), "{page}");
    assert!(page.contains("1 alert added"), "{page}");
    assert!(
        page.contains("1 of the ticked alerts no longer exist"),
        "{page}"
    );
    assert!(page.contains(&gone.to_string()));
    assert!(page.contains(r#"<a href="/?size=10">Back</a>"#));
    assert_eq!(stack.audit_count().await, audit + 1);
    assert_eq!(last_action(&stack).await, "add_to_event");
    assert_eq!(alerts_in_event(&stack, open).await, BTreeSet::from([one]));

    // a new event, dated by its oldest alert, with its comment and times
    let mut form = vec![
        ("event", "NEW".to_owned()),
        ("name", " <i>new</i> ".to_owned()),
        ("comment", "seen twice".to_owned()),
        ("event_time", "2026-05-01T09:00".to_owned()),
        ("alert_time", "2026-05-01T10:00:00".to_owned()),
        ("ownership_time", String::new()),
    ];
    form.extend(alerts(&[two, one]));
    let response = post(form).await;
    assert_eq!(response.status(), StatusCode::OK);
    let page = response.text().await.expect("a page");
    assert!(page.contains("Made the event"), "{page}");
    assert!(
        page.contains("2026-05-01 - phish - corporate email - &#60;i&#62;new&#60;/i&#62;"),
        "{page}"
    );
    assert_eq!(stack.audit_count().await, audit + 2);
    let (made, comment, event_time): (i64, Option<String>, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as(
            "SELECT id, comment, event_time FROM events.events WHERE name = '<i>new</i>'",
        )
        .fetch_one(stack.test_db.db().pool())
        .await
        .expect("made");
    assert_eq!(comment.as_deref(), Some("seen twice"));
    assert_eq!(
        event_time,
        Some("2026-05-01T09:00:00Z".parse().expect("a time"))
    );
    assert_eq!(
        alerts_in_event(&stack, made).await,
        BTreeSet::from([one, two])
    );

    // Create Event: the page with no alerts, and a post that makes one with none
    let create = get("/events/add".to_owned()).await;
    assert_eq!(create.status(), StatusCode::OK);
    let page = create.text().await.expect("a page");
    assert!(page.contains("<h1>Create Event</h1>"), "{page}");
    let response = post(vec![
        ("event", "NEW".to_owned()),
        ("name", "empty".to_owned()),
    ])
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .text()
            .await
            .expect("a page")
            .contains("0 alerts added")
    );
    assert_eq!(stack.audit_count().await, audit + 3);

    // refusals change nothing
    let audit = stack.audit_count().await;
    let refusals: Vec<(Vec<(&'static str, String)>, StatusCode)> = vec![
        (vec![("alert", one.to_string())], StatusCode::BAD_REQUEST),
        (vec![("event", "nope".to_owned())], StatusCode::BAD_REQUEST),
        (vec![("event", "new".to_owned())], StatusCode::BAD_REQUEST),
        (vec![("event", "-1".to_owned())], StatusCode::BAD_REQUEST),
        (vec![("event", "".to_owned())], StatusCode::BAD_REQUEST),
        (
            vec![("event", "NEW".to_owned()), ("name", "  ".to_owned())],
            StatusCode::BAD_REQUEST,
        ),
        (
            vec![
                ("event", "NEW".to_owned()),
                ("name", "bad times".to_owned()),
                ("event_time", "2026-05-02T00:00".to_owned()),
                ("contain_time", "2026-05-01T00:00".to_owned()),
            ],
            StatusCode::BAD_REQUEST,
        ),
        (
            vec![
                ("event", "NEW".to_owned()),
                ("name", "x".to_owned()),
                ("event_time", "soon".to_owned()),
            ],
            StatusCode::BAD_REQUEST,
        ),
        (
            vec![
                ("event", "NEW".to_owned()),
                ("name", "x".to_owned()),
                ("alert", "x".to_owned()),
            ],
            StatusCode::BAD_REQUEST,
        ),
        (
            vec![("event", i64::MAX.to_string()), ("alert", one.to_string())],
            StatusCode::NOT_FOUND,
        ),
    ];
    for (form, status) in refusals {
        let response = post(form.clone()).await;
        assert_eq!(response.status(), status, "{form:?}");
        if form.iter().any(|(_, v)| v == "bad times") {
            assert!(
                response
                    .text()
                    .await
                    .expect("a page")
                    .contains("out of order")
            );
        }
    }
    let cross = stack
        .http
        .post(format!("{}/events/add", stack.url))
        .header("origin", "https://evil.example")
        .header("cookie", cookie(&session))
        .form(&[
            ("event", "NEW"),
            ("name", "cross-site"),
            ("alert", &two.to_string()),
        ])
        .send()
        .await
        .expect("answered");
    assert_eq!(cross.status(), StatusCode::FORBIDDEN);
    assert_eq!(stack.audit_count().await, audit);
    assert_eq!(
        sqlx_count(&stack.test_db, "SELECT count(*) FROM events.events").await,
        20,
        "18 made by SQL, the new one and the empty one"
    );
}

// ---- PLAN.md 5.11's events area (6c): the event list and an event's page ----

use ace_gui::events::{
    ClosePage, EventListPageHtml, EventListQuery, EventMay, EventPageHtml, close_view,
    event_list_view, event_view,
};
use ace_service::{
    EventAlert, EventChoices, EventListPage, EventMalware, EventOwner, EventOwnerChoice,
    EventOwnerFilter, EventSort, EventValue,
};

fn event_value(id: i32, value: &str) -> EventValue {
    EventValue {
        id,
        value: value.to_owned(),
    }
}

/// A fixture event full of hostile text: its name, comment, tags, campaign, malware and threat types, its
/// owner's name and its alert's title and tags.
fn hostile_event() -> GuiEvent {
    let mut event = fixture_event(7, "2026-03-04", HOSTILE);
    event.comment = Some(HOSTILE.to_owned());
    event.tags = vec![HOSTILE.to_owned()];
    event.campaign = Some(HOSTILE.to_owned());
    event.kind = HOSTILE.to_owned();
    event.alert_time = Some("2026-03-04T05:06:07Z".parse().expect("a time"));
    event.owner = Some(EventOwner {
        id: ace_service::UserId(uuid::Uuid::from_u128(0xA1)),
        username: "alice".to_owned(),
        display_name: Some(HOSTILE.to_owned()),
    });
    event.malware = vec![EventMalware {
        id: 1,
        name: HOSTILE.to_owned(),
        threat_types: vec!["rat".to_owned(), HOSTILE.to_owned()],
    }];
    event.disposition = "DAMAGE".to_owned();
    event.alerts = vec![
        EventAlert {
            id: uuid::Uuid::from_u128(0xA),
            title: HOSTILE.to_owned(),
            alerted_at: Some("2026-03-04T01:02:03Z".parse().expect("a time")),
            disposition: Some("DAMAGE".to_owned()),
            dispositioned_at: None,
            dispositioned_by: None,
            added_at: chrono::Utc::now(),
            analysis: AnalysisState::Complete,
            tags: vec![HOSTILE.to_owned()],
        },
        EventAlert {
            id: uuid::Uuid::from_u128(0xB),
            title: "second".to_owned(),
            alerted_at: None,
            disposition: None,
            dispositioned_at: None,
            dispositioned_by: None,
            added_at: chrono::Utc::now(),
            analysis: AnalysisState::Running,
            tags: Vec::new(),
        },
    ];
    event
}

fn fixture_choices() -> EventChoices {
    EventChoices {
        statuses: vec![event_value(2, "CLOSED"), event_value(1, "OPEN")],
        types: vec![event_value(1, "phish"), event_value(2, HOSTILE)],
        vectors: vec![event_value(1, "corporate email")],
        prevention_tools: vec![event_value(1, "response team")],
        risk_levels: vec![event_value(4, "0"), event_value(1, "1")],
        owners: vec![EventOwnerChoice {
            id: ace_service::UserId(uuid::Uuid::from_u128(0xA1)),
            username: "alice".to_owned(),
            display_name: Some(HOSTILE.to_owned()),
        }],
        malware: vec![event_value(1, HOSTILE)],
        campaigns: vec![event_value(3, "APT-x")],
        tags: vec![HOSTILE.to_owned(), "kit".to_owned()],
    }
}

/// The view functions: the list draws ace3's columns with the event's alerts linked, its sort links and
/// arrows, its filters' form with what's chosen, First and Next, Export and Create Event; the event's
/// page its details, times, malware, threat types, alerts with their state, the still-analyzing note
/// and Close Event; and the close confirm. Every value is escaped and nothing is inline.
#[test]
fn the_event_list_and_page_views_draw_ace3_s_columns() {
    let event = hostile_event();
    let pairs = |text: &str| -> Vec<(String, String)> {
        serde_urlencoded::from_str(text).expect("a query")
    };
    let query = EventListQuery::parse(&pairs(
        "filtered=1&status=OPEN&owner=None&type=phish&malware=1&tag=kit&sort=risk_level&dir=asc&after=x",
    ))
    .expect("parses");
    assert_eq!(query.query.sort, EventSort::RiskLevel);
    assert!(!query.query.descending);
    assert_eq!(query.query.filters.owners, [EventOwnerFilter::Nobody]);
    assert_eq!(query.query.filters.kind.as_deref(), Some("phish"));
    let page = EventListPage {
        events: vec![event.clone()],
        next: Some("cursor".to_owned()),
        total: 7,
    };
    let html = drawn_safely(&EventListPageHtml {
        layout: Layout::signed_out("n"),
        view: event_list_view(Some(&page), &query, &fixture_choices(), None, true),
    });
    assert!(
        html.contains(&format!(
            r#"{HOSTILE_ESCAPED} - corporate email - <a href="/events/7">{HOSTILE_ESCAPED}</a>"#
        )),
        "{html}"
    );
    assert!(
        html.contains(r#"<a href="/events/7#alerts">2 alerts</a>"#),
        "{html}"
    );
    assert!(html.contains(r#"<input type="checkbox" form="export" name="id" value="7""#));
    assert!(html.contains(r#"<button type="submit" form="export">Export to CSV</button>"#));
    assert!(html.contains(r#"<a href="/events/add">Create Event</a>"#));
    assert!(html.contains("7 events."));
    assert!(html.contains("<td>DAMAGE</td>"));
    // the current sort turns around, another starts descending, and the filters go with each
    assert!(
        html.contains(r#"<a href="/events?filtered=1&#38;type=phish&#38;"#),
        "{html}"
    );
    assert!(html.contains("sort=risk_level\">Severity↑</a>"), "{html}");
    assert!(
        html.contains("sort=disposition\">Disposition</a>"),
        "{html}"
    );
    assert!(html.contains(r#">First</a>"#));
    assert!(
        html.contains(r#"after=cursor" rel="next">Next</a>"#),
        "{html}"
    );
    // the form, with what's chosen
    assert!(html.contains(r#"<option value="OPEN" selected>OPEN</option>"#));
    assert!(html.contains(r#"<option value="CLOSED">CLOSED</option>"#));
    assert!(html.contains(r#"<option value="None" selected>None</option>"#));
    assert!(html.contains(r#"<option value="phish" selected>phish</option>"#));
    assert!(html.contains(r#"<option value="ANY" selected>ANY</option>"#));
    assert!(html.contains(r#"<option value="kit" selected>kit</option>"#));
    assert!(html.contains(r#"name="malware" value="1" checked>"#));
    assert!(html.contains(r#"name="campaign" value="3">"#));
    assert!(html.contains(r#"<option value="ipv4">ipv4</option>"#));

    // a filter that can't be read: said, with the form and no rows; and without event:write, no Create
    let html = drawn_safely(&EventListPageHtml {
        layout: Layout::signed_out("n"),
        view: event_list_view(
            None,
            &EventListQuery::default(),
            &fixture_choices(),
            Some(HOSTILE.to_owned()),
            false,
        ),
    });
    assert!(html.contains(&format!("The filters couldn't be read: {HOSTILE_ESCAPED}")));
    assert!(html.contains("No events match."));
    assert!(!html.contains("Create Event"));
    assert!(!html.contains("rel=\"next\""));

    // the event's page
    let html = drawn_safely(&EventPageHtml {
        layout: Layout::signed_out("n"),
        view: event_view(
            &event,
            EventMay {
                write: true,
                disposition: true,
            },
        ),
    });
    assert!(
        html.contains(&format!("<h1>{HOSTILE_ESCAPED}</h1>")),
        "{html}"
    );
    assert!(html.contains(&format!("<strong>Description:</strong> {HOSTILE_ESCAPED}")));
    assert!(html.contains("<th>Alert Time (UTC)</th>"), "{html}");
    assert!(html.contains("2026-03-04 05:06:07"));
    assert!(html.contains("ALERTS ARE STILL ANALYZING!"));
    assert!(html.contains(r#"<a href="/events/7/close">Close Event</a>"#));
    assert!(html.contains(r#"<span class="badge">rat</span>"#));
    assert!(html.contains(&format!(
        r#"<a href="/alerts/{}">{HOSTILE_ESCAPED}</a>"#,
        uuid::Uuid::from_u128(0xA)
    )));
    assert!(html.contains("<td>Completed</td>") && html.contains("<td>Analyzing</td>"));
    assert!(html.contains("<td>OPEN</td>"), "an alert with none is open");
    assert!(html.contains(r#"<h2 id="alerts">Alerts</h2>"#));
    // closed, or without event:write: no Close Event; nothing running: no note
    let mut closed = event.clone();
    closed.status = "CLOSED".to_owned();
    for alert in &mut closed.alerts {
        alert.analysis = AnalysisState::Complete;
    }
    for (event, write) in [(&closed, true), (&event, false)] {
        let html = drawn_safely(&EventPageHtml {
            layout: Layout::signed_out("n"),
            view: event_view(
                event,
                EventMay {
                    write,
                    disposition: false,
                },
            ),
        });
        assert!(!html.contains("Close Event"), "{html}");
    }
    let html = drawn_safely(&EventPageHtml {
        layout: Layout::signed_out("n"),
        view: event_view(
            &closed,
            EventMay {
                write: true,
                disposition: false,
            },
        ),
    });
    assert!(!html.contains("STILL ANALYZING"));

    // the confirm, and the confirm of one closed already
    let html = drawn_safely(&ClosePage {
        layout: Layout::signed_out("n"),
        view: close_view(&event),
    });
    assert!(
        html.contains(r#"<form method="post" action="/events/7/close""#),
        "{html}"
    );
    assert!(html.contains(&format!("Close 2026-03-04 - {HOSTILE_ESCAPED}")));
    let html = drawn_safely(&ClosePage {
        layout: Layout::signed_out("n"),
        view: close_view(&closed),
    });
    assert!(!html.contains("<form method=\"post\""));
    assert!(html.contains("closed already"));

    // a list URL that's hand-made wrongly
    for bad in [
        "sort=nope",
        "dir=up",
        "filtered=1&owner=bob",
        "filtered=1&malware=x",
        "filtered=1&campaign=1.5",
    ] {
        assert!(EventListQuery::parse(&pairs(bad)).is_err(), "{bad}");
    }
    // without the form's field it's ace3's opening list; with it, exactly what was chosen
    assert_eq!(
        EventListQuery::parse(&pairs(""))
            .expect("parses")
            .query
            .filters
            .statuses,
        ["OPEN"]
    );
    assert!(
        EventListQuery::parse(&pairs("filtered=1&type=ANY"))
            .expect("parses")
            .query
            .filters
            == ace_service::EventFilters::default()
    );
}

/// Through the server: signed out goes to the login; the list, an event's page and the export need
/// `event:read`, and Close Event `event:write`; the list filters, sorts and pages by its URL; a filter
/// that can't be read is said; an event is reached by its id or uuid; the export goes on to the API's;
/// and Close Event confirms, then closes in one audited write, from this site only, and each refusal
/// changes nothing.
#[tokio::test]
async fn the_event_list_and_an_event_s_page_through_the_server() {
    let stack = stack().await;
    let alice = user(&stack, "alice").await;
    let session = session_of(&stack, "alice").await;
    let one = list_alert(&stack, HOSTILE, "2026-05-01T10:00:00Z", Some("DAMAGE")).await;
    let open = gui_event(&stack, HOSTILE, "2026-04-01", "OPEN").await;
    let closed = gui_event(&stack, "closed one", "2026-04-02", "CLOSED").await;
    sqlx::query("INSERT INTO events.event_alerts (event_id, root_id) VALUES ($1, $2)")
        .bind(open)
        .bind(one)
        .execute(stack.test_db.db().pool())
        .await
        .expect("adds");
    // enough open events for a second page
    for n in 0..ace_gui::events::EVENTS_PAGE_SIZE {
        gui_event(&stack, &format!("filler {n:03}"), "2026-03-01", "OPEN").await;
    }
    let get = |path: String| {
        let request = stack.get(&path).header("cookie", cookie(&session));
        async move { request.send().await.expect("answered") }
    };
    let close = |id: i64, origin: &str| {
        let request = stack
            .http
            .post(format!("{}/events/{id}/close", stack.url))
            .header("origin", origin)
            .header("cookie", cookie(&session))
            .form(&[("x", "y")]);
        async move { request.send().await.expect("answered") }
    };

    // signed out
    for path in [
        "/events".to_owned(),
        format!("/events/{open}"),
        format!("/events/{open}/close"),
        format!("/events/export?id={open}"),
    ] {
        let response = stack.get(&path).send().await.expect("answered");
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{path}");
        assert!(
            location(&response).starts_with("/login?next=%2Fevents"),
            "{path}"
        );
    }

    // without event:read: refused, and no link in the menu
    let audit = stack.audit_count().await;
    for path in [
        "/events".to_owned(),
        format!("/events/{open}"),
        format!("/events/export?id={open}"),
        format!("/events/{open}/close"),
    ] {
        assert_eq!(
            get(path.clone()).await.status(),
            StatusCode::FORBIDDEN,
            "{path}"
        );
    }
    let home = get("/preferences".to_owned())
        .await
        .text()
        .await
        .expect("a page");
    assert!(!home.contains(r#"<a href="/events">Events</a>"#));
    assert_eq!(
        close(open, &stack.url).await.status(),
        StatusCode::FORBIDDEN
    );
    grant_to(&stack, &alice, "event", "read").await;
    let audit = audit + 1;
    assert_eq!(stack.audit_count().await, audit, "only the grant's row");
    let home = get("/preferences".to_owned())
        .await
        .text()
        .await
        .expect("a page");
    assert!(home.contains(r#"<a href="/events">Events</a>"#), "{home}");

    // the list as ace3 opens it: the open events, newest first, a page of them, then the next
    let response = get("/events".to_owned()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let page = response.text().await.expect("a page");
    assert!(inline_free(&page.replace(HOSTILE_ESCAPED, "")));
    assert!(!page.contains(HOSTILE));
    assert!(page.contains("101 events."), "{page}");
    assert!(page.contains(&format!(
        r#"<a href="/events/{open}">{HOSTILE_ESCAPED}</a>"#
    )));
    assert!(page.contains(&format!(r#"<a href="/events/{open}#alerts">1 alert</a>"#)));
    assert!(!page.contains("closed one"));
    assert!(!page.contains("Create Event"), "no event:write");
    let next = page
        .split(r#"<a href=""#)
        .find_map(|tail| {
            let (href, rest) = tail.split_once('"')?;
            rest.starts_with(r#" rel="next">"#)
                .then(|| href.replace("&#38;", "&"))
        })
        .expect("a Next link");
    let second = get(next).await.text().await.expect("a page");
    assert!(second.contains("filler 000"), "{second}");
    assert!(
        !second.contains(&format!("/events/{open}\"")),
        "on the first page"
    );
    assert!(second.contains(">First</a>"));
    assert!(!second.contains(r#"rel="next""#));

    // filters and sorts by the URL
    let page = get("/events?filtered=1&status=CLOSED".to_owned())
        .await
        .text()
        .await
        .expect("a page");
    assert!(
        page.contains("closed one") && page.contains("1 event."),
        "{page}"
    );
    let page = get("/events?filtered=1&disposition=DAMAGE&sort=date&dir=asc".to_owned())
        .await
        .text()
        .await
        .expect("a page");
    assert!(page.contains("1 event.") && page.contains(&format!("/events/{open}\"")));
    let page = get(format!(
        "/events?filtered=1&observable_type=ANY&observable_value={}",
        "evil.example.com"
    ))
    .await
    .text()
    .await
    .expect("a page");
    assert!(
        page.contains("0 events."),
        "the fixture alert holds no observable"
    );
    // a filter that can't be read is said, with the form
    let response = get("/events?filtered=1&created=whenever".to_owned()).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let page = response.text().await.expect("a page");
    assert!(page.contains("The filters couldn't be read"), "{page}");
    assert!(page.contains(r#"value="whenever""#));
    for bad in [
        "/events?sort=nope",
        "/events?dir=sideways",
        "/events?filtered=1&owner=bob",
        "/events?after=nope",
    ] {
        assert_eq!(
            get(bad.to_owned()).await.status(),
            StatusCode::BAD_REQUEST,
            "{bad}"
        );
    }

    // an event's page, by id and by uuid
    let uuid: uuid::Uuid = sqlx::query_scalar("SELECT uuid FROM events.events WHERE id = $1")
        .bind(open)
        .fetch_one(stack.test_db.db().pool())
        .await
        .expect("reads");
    for path in [format!("/events/{open}"), format!("/events/{uuid}")] {
        let response = get(path).await;
        assert_eq!(response.status(), StatusCode::OK);
        let page = response.text().await.expect("a page");
        assert!(inline_free(&page.replace(HOSTILE_ESCAPED, "")));
        assert!(!page.contains(HOSTILE));
        assert!(
            page.contains(&format!(r#"<a href="/alerts/{one}">{HOSTILE_ESCAPED}</a>"#)),
            "{page}"
        );
        assert!(page.contains("<td>DAMAGE</td>"));
        assert!(!page.contains("Close Event"), "no event:write");
    }
    assert_eq!(
        get(format!("/events/{}", i64::MAX)).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get("/events/nope".to_owned()).await.status(),
        StatusCode::BAD_REQUEST
    );

    // the export goes on to the API's, with the ticked ids
    let response = get(format!("/events/export?id={open}&id={closed}&id={open}")).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&response),
        format!("/api/events/v1/events/export/csv?ids={open}%2C{closed}")
    );
    assert_eq!(
        get("/events/export".to_owned()).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        get("/events/export?id=x".to_owned()).await.status(),
        StatusCode::BAD_REQUEST
    );
    let too_many = (0..=ace_service::MAX_EXPORT_EVENTS)
        .map(|n| format!("id={n}"))
        .collect::<Vec<_>>()
        .join("&");
    assert_eq!(
        get(format!("/events/export?{too_many}")).await.status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );

    // Close Event needs event:write
    assert_eq!(
        get(format!("/events/{open}/close")).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        close(open, &stack.url).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(stack.audit_count().await, audit);
    grant_to(&stack, &alice, "event", "write").await;
    let audit = audit + 1;
    let page = get(format!("/events/{open}"))
        .await
        .text()
        .await
        .expect("a page");
    assert!(page.contains(&format!(
        r#"<a href="/events/{open}/close">Close Event</a>"#
    )));
    let list = get("/events".to_owned())
        .await
        .text()
        .await
        .expect("a page");
    assert!(list.contains(r#"<a href="/events/add">Create Event</a>"#));
    let confirm = get(format!("/events/{open}/close")).await;
    assert_eq!(confirm.status(), StatusCode::OK);
    let page = confirm.text().await.expect("a page");
    assert!(inline_free(&page.replace(HOSTILE_ESCAPED, "")));
    assert!(
        page.contains(&format!(r#"action="/events/{open}/close""#)),
        "{page}"
    );
    assert_eq!(
        get("/events/nope/close".to_owned()).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        get(format!("/events/{}/close", i64::MAX)).await.status(),
        StatusCode::NOT_FOUND
    );

    // from another site, refused; an unknown event, 404; neither changes anything
    assert_eq!(
        close(open, "https://evil.example").await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        close(i64::MAX, &stack.url).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(stack.audit_count().await, audit);
    let status = || async {
        sqlx::query_scalar::<_, String>(
            "SELECT s.value FROM events.events e JOIN events.statuses s ON s.id = e.status_id
             WHERE e.id = $1",
        )
        .bind(open)
        .fetch_one(stack.test_db.db().pool())
        .await
        .expect("reads")
    };
    assert_eq!(status().await, "OPEN");

    // closing: one audited write, back to the event's page, which has no Close Event now
    let response = close(open, &stack.url).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&response), format!("/events/{open}"));
    assert_eq!(status().await, "CLOSED");
    assert_eq!(stack.audit_count().await, audit + 1);
    assert_eq!(last_action(&stack).await, "set_event_status");
    let page = get(format!("/events/{open}"))
        .await
        .text()
        .await
        .expect("a page");
    assert!(!page.contains("Close Event</a>"));
    let page = get(format!("/events/{open}/close"))
        .await
        .text()
        .await
        .expect("a page");
    assert!(page.contains("closed already"));
    // closing it again changes nothing
    assert_eq!(
        close(open, &stack.url).await.status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(stack.audit_count().await, audit + 1);

    // the answer to an add links to the event's page
    let added = stack
        .http
        .post(format!("{}/events/add", stack.url))
        .header("origin", &stack.url)
        .header("cookie", cookie(&session))
        .form(&[("event", closed.to_string()), ("alert", one.to_string())])
        .send()
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(
        added.contains(&format!(r#"<a href="/events/{closed}">"#)),
        "{added}"
    );
}

// ---- PLAN.md 5.11's events area (6d): an event's edit, its alerts removed and dispositioned, its tags ----

use ace_gui::events::{EditForm, EventEditPage, TaggedPage, TaggedView, edit_view};
use ace_service::EventEditChoices;

fn fixture_edit_choices() -> EventEditChoices {
    EventEditChoices {
        statuses: vec![
            event_value(2, "CLOSED"),
            event_value(3, "IGNORE"),
            event_value(1, "OPEN"),
        ],
        remediations: vec![event_value(1, "not remediated"), event_value(2, HOSTILE)],
        types: vec![event_value(1, "phish")],
        vectors: vec![event_value(1, "corporate email")],
        risk_levels: vec![event_value(4, "0")],
        prevention_tools: vec![event_value(1, "response team")],
        campaigns: vec![event_value(3, HOSTILE)],
        malware: vec![
            EventMalware {
                id: 1,
                name: HOSTILE.to_owned(),
                threat_types: vec!["rat".to_owned(), "wiper".to_owned()],
            },
            EventMalware {
                id: 2,
                name: "Plain".to_owned(),
                threat_types: Vec::new(),
            },
        ],
        threat_types: vec![
            ace_service::ThreatType {
                id: 6,
                name: "rat".to_owned(),
            },
            ace_service::ThreatType {
                id: 11,
                name: HOSTILE.to_owned(),
            },
        ],
        users: vec![EventOwnerChoice {
            id: ace_service::UserId(uuid::Uuid::from_u128(0xB0)),
            username: "bob".to_owned(),
            display_name: Some(HOSTILE.to_owned()),
        }],
    }
}

/// The view functions: the edit page draws ace3's fields with the event's values chosen, CLOSED only for
/// a closed event and the times only for one that isn't, each malware row with NEW, (none) and ace3's
/// labels, the Add slot, a disabled owner kept, and why a save was refused; the form reads back as the
/// edit it asks for; the event page offers Edit Event, Add Tag(s), Remove Alert(s) and Set Disposition
/// by what the viewer holds; the list its Edit links and Add Tag(s); and the tag answer. Every value is
/// escaped and nothing is inline.
#[test]
fn the_edit_views_draw_ace3_s_form() {
    let mut event = hostile_event();
    event.campaign = Some(HOSTILE.to_owned());
    let choices = fixture_edit_choices();
    let form = EditForm::of(&event);
    assert_eq!(form.version, event.edit_version());
    assert_eq!(
        form.malware.len(),
        2,
        "the event's malware and the Add slot"
    );
    let html = drawn_safely(&EventEditPage {
        layout: Layout::signed_out("n"),
        view: edit_view(&event, &choices, &form, Some(HOSTILE.to_owned())),
    });
    assert!(inline_free(&html.replace(HOSTILE_ESCAPED, "")), "{html}");
    assert!(
        html.contains(r#"<form method="post" action="/events/7/edit" class="edit-event">"#),
        "{html}"
    );
    assert!(html.contains(&format!(
        r#"<input type="hidden" name="version" value="{}">"#,
        event.edit_version()
    )));
    assert!(html.contains(&format!("The event wasn't saved: {HOSTILE_ESCAPED}")));
    assert!(html.contains(&format!(
        r#"maxlength="{}">{HOSTILE_ESCAPED}</textarea>"#,
        ace_service::MAX_EVENT_NAME_CHARS
    )));
    // ace3: an open event isn't offered CLOSED
    assert!(html.contains(r#"<option value="OPEN" selected>OPEN</option>"#));
    assert!(html.contains(r#"<option value="IGNORE">IGNORE</option>"#));
    assert!(!html.contains(r#"value="CLOSED""#), "{html}");
    // the event's type, not in the table, is kept as it is
    assert!(html.contains(&format!(
        r#"<option value="{HOSTILE_ESCAPED}" selected>{HOSTILE_ESCAPED}</option>"#
    )));
    // the owner: None, the enabled users, and the event's own, disabled, kept
    assert!(html.contains(r#"<option value="None">None</option>"#));
    assert!(html.contains(&format!(
        r#"<option value="{}">{HOSTILE_ESCAPED}</option>"#,
        uuid::Uuid::from_u128(0xB0)
    )));
    assert!(
        html.contains(&format!(
            r#"<option value="{}" selected>{HOSTILE_ESCAPED} (disabled)</option>"#,
            uuid::Uuid::from_u128(0xA1)
        )),
        "{html}"
    );
    // the campaign, chosen by its name
    assert!(html.contains(&format!(
        r#"<option value="3" selected>{HOSTILE_ESCAPED}</option>"#
    )));
    assert!(html.contains(r#"<option value="NEW">NEW</option>"#));
    // the times, as datetime-local values
    assert!(html.contains(
        r#"<input type="datetime-local" step="1" id="alert_time" name="alert_time" value="2026-03-04T05:06:07">"#
    ));
    // the event's malware row, chosen, labelled with its threat types; and the Add slot, NEW, open
    assert!(html.contains(&format!(
        r#"<option value="1" selected>{HOSTILE_ESCAPED}: rat, wiper</option>"#
    )));
    assert!(html.contains(r#"<option value="2">Plain</option>"#));
    assert!(html.contains(r#"<select id="malware_selection_1" name="malware_selection_1">"#));
    assert!(html.contains(r#"<option value="NEW" selected>NEW</option>"#));
    assert!(html.contains("<details open>"));
    assert!(html.contains(r#"name="threats_1" value="11">"#));
    assert!(
        html.contains(r#"<button type="submit" name="action" value="more">Add a threat</button>"#)
    );
    assert!(html.contains(r#"<button type="submit" name="action" value="save">Save</button>"#));

    // a closed event: CLOSED offered, and no times
    let mut closed = event.clone();
    closed.status = "CLOSED".to_owned();
    let html = drawn_safely(&EventEditPage {
        layout: Layout::signed_out("n"),
        view: edit_view(&closed, &choices, &EditForm::of(&closed), None),
    });
    assert!(html.contains(r#"<option value="CLOSED" selected>CLOSED</option>"#));
    assert!(!html.contains("datetime-local"));
    assert!(html.contains("The event is closed, so its times don't change."));
    assert!(!html.contains("wasn't saved"));

    // the form as sent reads back as the edit it asks for
    let sent =
        |text: &str| -> Vec<(String, String)> { serde_urlencoded::from_str(text).expect("a form") };
    let form = EditForm::parse(&sent(
        "version=v&event_name=n&event_status=OPEN&event_owner=None&event_remediation=r&event_type=t\
         &event_vector=v&event_risk_level=0&event_prevention=p&event_comment=c&campaign_id=NEW\
         &new_campaign=APT&event_time=2026-01-01T00:00&alert_time=\
         &malware_selection_2=NEW&mal_name_2=Fresh&threats_2=6&threats_2=11\
         &malware_selection_0=1&malware_selection_1=&malware_selection_3=NEW&mal_name_3=",
    ))
    .expect("parses");
    let edit = form.edit().expect("an edit");
    assert_eq!(edit.version, "v");
    assert_eq!(edit.owner, None);
    assert_eq!(
        edit.campaign,
        ace_service::CampaignChoice::New("APT".to_owned())
    );
    assert_eq!(
        edit.times.event_time,
        Some("2026-01-01T00:00:00Z".parse().expect("a time"))
    );
    assert_eq!(edit.times.alert_time, None, "empty keeps the stored one");
    assert_eq!(
        edit.malware,
        [
            ace_service::MalwareChoice::Existing(1),
            ace_service::MalwareChoice::New {
                name: "Fresh".to_owned(),
                threat_types: vec![6, 11],
            },
        ],
        "in their rows' order; (none) taken off and the untouched Add slot left out"
    );
    for bad in [
        "event_owner=bob",
        "campaign_id=x",
        "event_time=soon",
        "malware_selection_0=x",
        "malware_selection_0=NEW&mal_name_0=a&threats_0=x",
    ] {
        let form = EditForm::parse(&sent(bad)).expect("parses");
        assert!(form.edit().is_err(), "{bad}");
    }
    assert!(EditForm::parse(&sent("malware_selection_x=1")).is_err());
    let too_many = (0..=ace_service::MAX_EDIT_MALWARE + 1)
        .map(|n| format!("malware_selection_{n}=1"))
        .collect::<Vec<_>>()
        .join("&");
    assert!(EditForm::parse(&sent(&too_many)).is_err());

    // the event page: what the viewer holds decides what it offers
    let html = drawn_safely(&EventPageHtml {
        layout: Layout::signed_out("n"),
        view: event_view(
            &event,
            EventMay {
                write: true,
                disposition: true,
            },
        ),
    });
    assert!(
        html.contains(r#"<a href="/events/7/edit">Edit Event</a>"#),
        "{html}"
    );
    assert!(html.contains(r#"<form method="post" action="/events/7/tags" class="inline">"#));
    assert!(html.contains(
        r#"<button type="submit" formaction="/events/7/alerts/remove">Remove Alert(s)</button>"#
    ));
    assert!(html.contains(
        r#"<button type="submit" formaction="/alerts/disposition">Set Disposition</button>"#
    ));
    assert!(html.contains(r#"<input type="hidden" name="next" value="/events/7">"#));
    assert!(html.contains(&format!(
        r#"<input type="checkbox" form="event-alerts" name="alert" value="{}""#,
        uuid::Uuid::from_u128(0xA)
    )));
    assert!(html.contains(r#"<option value="FALSE_POSITIVE">FALSE_POSITIVE</option>"#));
    // alert:write only: Set Disposition and the boxes, nothing of event:write's
    let html = drawn_safely(&EventPageHtml {
        layout: Layout::signed_out("n"),
        view: event_view(
            &event,
            EventMay {
                write: false,
                disposition: true,
            },
        ),
    });
    assert!(html.contains("Set Disposition") && html.contains(r#"form="event-alerts""#));
    assert!(!html.contains("Remove Alert(s)") && !html.contains("Edit Event"));
    assert!(!html.contains("Add Tag(s)"));
    // neither: no form and no boxes
    let html = drawn_safely(&EventPageHtml {
        layout: Layout::signed_out("n"),
        view: event_view(&event, EventMay::default()),
    });
    assert!(!html.contains("event-alerts") && !html.contains("Set Disposition"));

    // the list: Edit links and Add Tag(s) of the ticked rows for event:write
    let page = EventListPage {
        events: vec![event.clone()],
        next: None,
        total: 1,
    };
    let query = EventListQuery::default();
    let html = drawn_safely(&EventListPageHtml {
        layout: Layout::signed_out("n"),
        view: event_list_view(Some(&page), &query, &fixture_choices(), None, true),
    });
    assert!(
        html.contains(r#"<a href="/events/7/edit" title="Edit Event">Edit</a>"#),
        "{html}"
    );
    assert!(html.contains(
        r#"<button type="submit" form="export" formmethod="post" formaction="/events/tags">Add Tag(s)</button>"#
    ));
    assert!(
        html.contains(
            r#"<input type="hidden" form="export" name="next" value="/events?filtered=1&#38;"#
        ),
        "{html}"
    );
    let html = drawn_safely(&EventListPageHtml {
        layout: Layout::signed_out("n"),
        view: event_list_view(Some(&page), &query, &fixture_choices(), None, false),
    });
    assert!(!html.contains("/edit") && !html.contains("Add Tag(s)"));

    // the list's tag answer
    let html = drawn_safely(&TaggedPage {
        layout: Layout::signed_out("n"),
        view: TaggedView {
            tags: vec![HOSTILE.to_owned()],
            done: vec![(HOSTILE.to_owned(), "/events/7".to_owned())],
            failed: vec![(9, HOSTILE.to_owned())],
            next: "/events".to_owned(),
        },
    });
    assert!(inline_free(&html.replace(HOSTILE_ESCAPED, "")));
    assert!(html.contains("1 event tagged, 1 not."), "{html}");
    assert!(html.contains(&format!(r#"<a href="/events/7">{HOSTILE_ESCAPED}</a>"#)));
    assert!(html.contains(&format!("<li>9: {HOSTILE_ESCAPED}</li>")));
}

async fn event_uuid(stack: &Stack, id: i64) -> uuid::Uuid {
    sqlx::query_scalar("SELECT uuid FROM events.events WHERE id = $1")
        .bind(id)
        .fetch_one(stack.test_db.db().pool())
        .await
        .expect("reads")
}

/// The edit form's fields that the page drew, as a browser would send them back: each input's and
/// textarea's value, each select's chosen option, and each ticked box.
fn drawn_form(page: &str) -> Vec<(String, String)> {
    let unescape = |text: &str| {
        text.replace("&#34;", "\"")
            .replace("&#39;", "'")
            .replace("&#60;", "<")
            .replace("&#62;", ">")
            .replace("&#38;", "&")
    };
    let attr = |tag: &str, name: &str| {
        let key = format!(" {name}=\"");
        tag.find(&key).map(|at| {
            let rest = &tag[at + key.len()..];
            unescape(&rest[..rest.find('"').expect("closes")])
        })
    };
    let form = page
        .split(r#"class="edit-event">"#)
        .nth(1)
        .and_then(|rest| rest.split("</form>").next())
        .expect("the edit form");
    let mut fields = Vec::new();
    let mut select: Option<String> = None;
    for piece in form.split('<').skip(1) {
        let tag = piece.split('>').next().unwrap_or("");
        if tag.starts_with("select ") {
            select = attr(tag, "name");
        } else if tag.starts_with("/select") {
            select = None;
        } else if tag.starts_with("option ") && tag.ends_with(" selected") {
            if let (Some(name), Some(value)) = (&select, attr(tag, "value")) {
                fields.push((name.clone(), value));
            }
        } else if tag.starts_with("input ") {
            let checkbox = tag.contains(r#"type="checkbox""#);
            if checkbox && !tag.ends_with(" checked") {
                continue;
            }
            if let (Some(name), Some(value)) = (attr(tag, "name"), attr(tag, "value")) {
                fields.push((name, value));
            }
        } else if tag.starts_with("textarea ") {
            let text = piece.split_once('>').map_or("", |(_, text)| text);
            if let Some(name) = attr(tag, "name") {
                fields.push((name, unescape(text)));
            }
        }
    }
    fields
}

fn set(form: &mut Vec<(String, String)>, name: &str, value: &str) {
    form.retain(|(key, _)| key != name);
    form.push((name.to_owned(), value.to_owned()));
}

/// Through the server: signed out goes to the login; the edit, Remove Alert(s) and Add Tag(s) need
/// `event:write`, and Set Disposition `alert:write`; the edit page is the event as it is, Add a threat
/// draws it again with one more row and writes nothing, and Save edits it in one audited write and goes
/// back to its page; a refusal the form can fix draws it again with what was typed; a save over another
/// one is a 409; the alerts are removed and dispositioned, and the event tagged, from its page and the
/// list; and each refusal, a cross-site post among them, changes nothing.
#[tokio::test]
async fn an_event_is_edited_through_the_server() {
    let stack = stack().await;
    let alice = user(&stack, "alice").await;
    let session = session_of(&stack, "alice").await;
    let one = list_alert(&stack, HOSTILE, "2026-05-01T10:00:00Z", None).await;
    let two = list_alert(&stack, "two", "2026-05-02T10:00:00Z", None).await;
    let open = gui_event(&stack, HOSTILE, "2026-04-01", "OPEN").await;
    let other = gui_event(&stack, "other", "2026-04-02", "OPEN").await;
    for alert in [one, two] {
        sqlx::query("INSERT INTO events.event_alerts (event_id, root_id) VALUES ($1, $2)")
            .bind(open)
            .bind(alert)
            .execute(stack.test_db.db().pool())
            .await
            .expect("adds");
    }
    let get = |path: String| {
        let request = stack.get(&path).header("cookie", cookie(&session));
        async move { request.send().await.expect("answered") }
    };
    let post = |path: String, form: Vec<(String, String)>, origin: String| {
        let request = stack
            .http
            .post(format!("{}{path}", stack.url))
            .header("origin", origin)
            .header("cookie", cookie(&session))
            .form(&form);
        async move { request.send().await.expect("answered") }
    };
    let here = stack.url.clone();
    let pairs = |list: &[(&str, &str)]| {
        list.iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect::<Vec<_>>()
    };
    let edit_path = format!("/events/{open}/edit");

    // signed out
    let response = stack.get(&edit_path).send().await.expect("answered");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(location(&response).starts_with("/login?next=%2Fevents%2F"));

    // without event:write: refused, and nothing changes
    grant_to(&stack, &alice, "event", "read").await;
    let audit = stack.audit_count().await;
    assert_eq!(get(edit_path.clone()).await.status(), StatusCode::FORBIDDEN);
    for (path, form) in [
        (edit_path.clone(), pairs(&[("event_name", "x")])),
        (
            format!("/events/{open}/alerts/remove"),
            pairs(&[("alert", &one.to_string())]),
        ),
        (format!("/events/{open}/tags"), pairs(&[("tag", "x")])),
        (
            "/events/tags".to_owned(),
            pairs(&[("tag", "x"), ("id", &open.to_string())]),
        ),
        (
            "/alerts/disposition".to_owned(),
            pairs(&[("alert", &one.to_string()), ("disposition", "DAMAGE")]),
        ),
    ] {
        assert_eq!(
            post(path.clone(), form, here.clone()).await.status(),
            StatusCode::FORBIDDEN,
            "{path}"
        );
    }
    let page = get(format!("/events/{open}"))
        .await
        .text()
        .await
        .expect("a page");
    assert!(!page.contains("Edit Event") && !page.contains("event-alerts"));
    assert_eq!(stack.audit_count().await, audit);
    grant_to(&stack, &alice, "event", "write").await;
    let audit = audit + 1;

    // the event's page links the edit, and the list each row's
    let page = get(format!("/events/{open}"))
        .await
        .text()
        .await
        .expect("a page");
    assert!(page.contains(&format!(r#"<a href="/events/{open}/edit">Edit Event</a>"#)));
    assert!(page.contains("Remove Alert(s)") && !page.contains("Set Disposition"));
    let list = get("/events".to_owned())
        .await
        .text()
        .await
        .expect("a page");
    assert!(list.contains(&format!(
        r#"<a href="/events/{open}/edit" title="Edit Event">Edit</a>"#
    )));

    // the edit page: the event as it is
    let response = get(edit_path.clone()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let page = response.text().await.expect("a page");
    assert!(inline_free(&page.replace(HOSTILE_ESCAPED, "")));
    assert!(!page.contains(HOSTILE));
    assert!(
        !page.contains(r#"value="CLOSED""#),
        "an open event isn't offered CLOSED"
    );
    let mut form = drawn_form(&page);
    assert!(
        form.iter().any(|(k, v)| k == "event_name" && v == HOSTILE),
        "{form:?}"
    );
    assert!(
        form.iter()
            .any(|(k, v)| k == "malware_selection_0" && v == "NEW")
    );
    assert_eq!(
        get(format!("/events/{}/edit", i64::MAX)).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get("/events/nope/edit".to_owned()).await.status(),
        StatusCode::BAD_REQUEST
    );

    // Add a threat: the form again as sent, one more row, and nothing written
    set(&mut form, "event_comment", "typed, not saved");
    set(&mut form, "mal_name_0", "Fresh");
    let rat = sqlx::query_scalar::<_, i32>("SELECT id FROM events.threat_types WHERE name = 'rat'")
        .fetch_one(stack.test_db.db().pool())
        .await
        .expect("a type");
    form.push(("threats_0".to_owned(), rat.to_string()));
    let mut more = form.clone();
    more.push(("action".to_owned(), "more".to_owned()));
    let response = post(edit_path.clone(), more, here.clone()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let page = response.text().await.expect("a page");
    assert!(page.contains(">typed, not saved</textarea>"), "{page}");
    assert!(page.contains(r#"name="mal_name_0" value="Fresh""#));
    assert!(page.contains(&format!(r#"name="threats_0" value="{rat}" checked>"#)));
    assert!(
        page.contains(r#"name="malware_selection_1""#),
        "a second row"
    );
    assert_eq!(stack.audit_count().await, audit);

    // a refusal the form can fix: drawn again with what was typed, and why
    let mut bad = form.clone();
    set(&mut bad, "event_time", "2026-05-02T00:00");
    set(&mut bad, "alert_time", "2026-05-01T00:00");
    let response = post(edit_path.clone(), bad, here.clone()).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let page = response.text().await.expect("a page");
    assert!(
        page.contains("The event wasn't saved: one or more of the times is out of order"),
        "{page}"
    );
    assert!(page.contains(">typed, not saved</textarea>"));
    let mut bad = form.clone();
    set(&mut bad, "event_time", "whenever");
    let response = post(edit_path.clone(), bad, here.clone()).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        response
            .text()
            .await
            .expect("a page")
            .contains("isn&#39;t a time")
    );
    let mut bad = form.clone();
    set(&mut bad, "event_status", "CLOSED");
    assert_eq!(
        post(edit_path.clone(), bad, here.clone()).await.status(),
        StatusCode::BAD_REQUEST
    );
    // from another site
    assert_eq!(
        post(
            edit_path.clone(),
            form.clone(),
            "https://evil.example".to_owned()
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(stack.audit_count().await, audit);

    // Save: one audited write, back to the event's page
    set(&mut form, "event_name", "<b>renamed</b>");
    set(&mut form, "event_comment", "saved");
    set(&mut form, "campaign_id", "NEW");
    set(&mut form, "new_campaign", "APT-new");
    let mut save = form.clone();
    save.push(("action".to_owned(), "save".to_owned()));
    let response = post(edit_path.clone(), save.clone(), here.clone()).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&response), format!("/events/{open}"));
    assert_eq!(stack.audit_count().await, audit + 1);
    assert_eq!(last_action(&stack).await, "edit_event");
    let page = get(format!("/events/{open}"))
        .await
        .text()
        .await
        .expect("a page");
    assert!(
        page.contains("<h1>&#60;b&#62;renamed&#60;/b&#62;</h1>"),
        "{page}"
    );
    assert!(page.contains("<td>APT-new</td>"));
    assert!(page.contains(r#"<span class="badge">Fresh</span>"#));
    assert!(page.contains(r#"<span class="badge">rat</span>"#));

    // the same form again was drawn from the old version: a conflict, and nothing written
    let response = post(edit_path.clone(), save, here.clone()).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(
        response
            .text()
            .await
            .expect("a page")
            .contains("open its edit again")
    );
    assert_eq!(stack.audit_count().await, audit + 1);
    let audit = audit + 1;

    // Add Tag(s) on the event's page, split on whitespace
    let response = post(
        format!("/events/{open}/tags"),
        pairs(&[("tag", " kit  <i>x</i> ")]),
        here.clone(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&response), format!("/events/{open}"));
    let page = get(format!("/events/{open}"))
        .await
        .text()
        .await
        .expect("a page");
    assert!(page.contains(r#"<span class="badge">&#60;i&#62;x&#60;/i&#62;</span>"#));
    assert!(page.contains(r#"<span class="badge">kit</span>"#));
    assert_eq!(stack.audit_count().await, audit + 1);
    for form in [pairs(&[("tag", "  ")]), pairs(&[])] {
        assert_eq!(
            post(format!("/events/{open}/tags"), form, here.clone())
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    // and on the list's ticked rows, each its own write; an event that isn't there is said
    let response = post(
        "/events/tags".to_owned(),
        pairs(&[
            ("tag", "bulk"),
            ("id", &open.to_string()),
            ("id", &other.to_string()),
            ("id", &i64::MAX.to_string()),
            ("next", "/events?filtered=1"),
        ]),
        here.clone(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let page = response.text().await.expect("a page");
    assert!(inline_free(&page.replace(HOSTILE_ESCAPED, "")));
    assert!(page.contains("2 events tagged, 1 not."), "{page}");
    assert!(page.contains(&format!(r#"<a href="/events/{other}">"#)));
    assert!(page.contains(r#"<a href="/events?filtered=1">Back to the list</a>"#));
    assert_eq!(stack.audit_count().await, audit + 3);
    assert_eq!(
        post(
            "/events/tags".to_owned(),
            pairs(&[("tag", "x"), ("id", "nope")]),
            here.clone()
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    let audit = audit + 3;

    // Remove Alert(s) of the ticked alerts, back to the page's alerts
    let response = post(
        format!("/events/{open}/alerts/remove"),
        pairs(&[
            ("alert", &two.to_string()),
            ("disposition", "DAMAGE"),
            ("next", "/x"),
        ]),
        here.clone(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&response), format!("/events/{open}#alerts"));
    assert_eq!(alerts_in_event(&stack, open).await, BTreeSet::from([one]));
    assert_eq!(stack.audit_count().await, audit + 1);
    assert_eq!(last_action(&stack).await, "remove_alerts");
    for form in [pairs(&[]), pairs(&[("alert", "x")])] {
        assert_eq!(
            post(format!("/events/{open}/alerts/remove"), form, here.clone())
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        post(
            format!("/events/{}/alerts/remove", i64::MAX),
            pairs(&[("alert", &one.to_string())]),
            here.clone()
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    let audit = audit + 1;

    // Set Disposition, for alert:write: the alert list's route, back to the event's page
    grant_to(&stack, &alice, "alert", "write").await;
    let audit = audit + 1;
    let page = get(format!("/events/{open}"))
        .await
        .text()
        .await
        .expect("a page");
    assert!(page.contains(
        r#"<button type="submit" formaction="/alerts/disposition">Set Disposition</button>"#
    ));
    let response = post(
        "/alerts/disposition".to_owned(),
        pairs(&[
            ("alert", &one.to_string()),
            ("disposition", "DAMAGE"),
            ("next", &format!("/events/{open}")),
        ]),
        here.clone(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let page = response.text().await.expect("a page");
    assert!(page.contains("1 alert dispositioned"), "{page}");
    assert!(page.contains(&format!(r#"<a href="/events/{open}">"#)));
    assert_eq!(stack.audit_count().await, audit + 1);
    assert_eq!(last_action(&stack).await, "disposition");
    let page = get(format!("/events/{open}"))
        .await
        .text()
        .await
        .expect("a page");
    assert!(page.contains("<td>DAMAGE</td>"));

    // closed: the edit offers CLOSED and no times; by uuid too
    let uuid = event_uuid(&stack, open).await;
    let response = post(format!("/events/{open}/close"), pairs(&[]), here.clone()).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let page = get(format!("/events/{uuid}/edit"))
        .await
        .text()
        .await
        .expect("a page");
    assert!(
        page.contains(r#"<option value="CLOSED" selected>CLOSED</option>"#),
        "{page}"
    );
    assert!(!page.contains("datetime-local"));
}

fn command_run(id: i64, state: ace_service::CommandState, text: &str) -> ace_service::CommandRun {
    let at = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("a time");
    ace_service::CommandRun {
        id,
        command: text.to_owned(),
        state,
        user: None,
        username: text.to_owned(),
        started_by: RecordedActor {
            kind: "user".to_owned(),
            id: "u".to_owned(),
            name: Some(text.to_owned()),
        },
        timeout_seconds: 30,
        exit_code: (state == ace_service::CommandState::Completed).then_some(2),
        error: Some(text.to_owned()),
        cancel_requested: false,
        cancelled_by: None,
        created_at: at,
        started_at: Some(at),
        deadline_at: Some(at + chrono::Duration::seconds(30)),
        finished_at: None,
    }
}

/// PLAN.md 5.12: the console, a run's page and its fragment draw a run's command, user, error and output
/// only as text, and a run's fragment polls only while the run hasn't ended.
#[test]
fn the_cli_pages_draw_a_run_as_text() {
    use ace_gui::cli::{ConsolePage, RunFragment, RunPage, console_view, run_view};
    use ace_service::{CommandDetail, CommandPage, CommandState};
    let layout = || Layout::new("n0nce", Theme::Dark, Some("alice".to_owned()), "/admin/cli");
    let running = CommandDetail {
        run: command_run(7, CommandState::Running, HOSTILE),
        output: format!("{HOSTILE}\n\u{fffd}"),
        output_truncated: true,
    };
    let console = drawn_safely(&ConsolePage {
        layout: layout(),
        view: console_view(
            &CommandPage {
                commands: vec![
                    running.run.clone(),
                    command_run(6, CommandState::Completed, "--help"),
                ],
                next: Some(6),
            },
            false,
        ),
    });
    for part in [
        r#"<form method="post" action="/admin/cli" class="fields" autocomplete="off">"#,
        r#"<a href="/admin/cli/7">7</a>"#,
        &format!("<code>{HOSTILE_ESCAPED}</code>"),
        "completed (exit 2)",
        r#"<a href="/admin/cli?after=6">Next</a>"#,
        r#"max="3600""#,
    ] {
        assert!(console.contains(part), "{part}: {console}");
    }
    let page = drawn_safely(&RunPage {
        layout: layout(),
        run: run_view(&running),
        problem: Some(HOSTILE.to_owned()),
    });
    for part in [
        &format!("<code>ace {HOSTILE_ESCAPED}</code>"),
        &format!(r#"<pre class="cli-output">{HOSTILE_ESCAPED}"#),
        r#"data-refresh="/admin/cli/7/output""#,
        r#"data-on-interval__duration.2s="!document.hidden && @get(el.dataset.refresh)""#,
        r#"action="/admin/cli/7/cancel""#,
        "It wrote more than the 1 MiB kept",
    ] {
        assert!(page.contains(part), "{part}: {page}");
    }
    let ended = CommandDetail {
        run: command_run(6, CommandState::TimedOut, "sleep"),
        output: String::new(),
        output_truncated: false,
    };
    let fragment = drawn_safely(&RunFragment {
        run: run_view(&ended),
    });
    assert!(
        fragment.starts_with(r#"<div id="cli-output">"#),
        "{fragment}"
    );
    assert!(
        !fragment.contains("data-on-interval"),
        "an ended run doesn't poll"
    );
    assert!(!fragment.contains("/cancel"), "nor can it be cancelled");
    assert!(fragment.contains("(no output)"));
    assert!(fragment.contains("timed out"));
}

/// PLAN.md 5.12: the CLI through the server. A start and a cancel are this site's posts, each one
/// audited write; the pages need `admin:read` and `cli:execute`; a refusal draws the form again or says
/// why, and writes nothing.
#[tokio::test]
async fn the_cli_starts_follows_and_cancels_a_command() {
    let stack = stack().await;
    let operator = user(&stack, "operator").await;
    grant_to(&stack, &operator, "admin", "read").await;
    grant_to(&stack, &operator, "cli", "execute").await;
    let admin_only = user(&stack, "admin-only").await;
    grant_to(&stack, &admin_only, "admin", "read").await;
    user(&stack, "nobody").await;
    let session = |name: &'static str| {
        let stack = &stack;
        async move { session_set(stack.log_in(name, PASSWORD).await.headers()).expect("a session") }
    };
    let (op, adm, none) = (
        session("operator").await,
        session("admin-only").await,
        session("nobody").await,
    );

    // the hub offers the CLI to whoever holds cli:execute
    let hub = stack
        .get("/admin")
        .header("cookie", cookie(&op))
        .send()
        .await
        .expect("answered");
    assert!(
        hub.text()
            .await
            .expect("text")
            .contains(r#"href="/admin/cli""#)
    );
    let hub = stack
        .get("/admin")
        .header("cookie", cookie(&adm))
        .send()
        .await
        .expect("answered");
    assert!(
        !hub.text()
            .await
            .expect("text")
            .contains(r#"href="/admin/cli""#)
    );

    // a start from this site, which goes to the run's page
    let rows = stack.audit_count().await;
    let started = stack
        .post(
            "/admin/cli",
            &[("command", "ace --help"), ("timeout_seconds", "60")],
        )
        .header("cookie", cookie(&op))
        .send()
        .await
        .expect("answered");
    assert_eq!(started.status(), StatusCode::SEE_OTHER);
    let page = location(&started).to_owned();
    let id: i64 = page
        .strip_prefix("/admin/cli/")
        .expect("a run")
        .parse()
        .expect("an id");
    assert_eq!(stack.audit_count().await, rows + 1);
    assert_eq!(last_action(&stack).await, "start_command");
    let run = stack
        .get(&page)
        .header("cookie", cookie(&op))
        .send()
        .await
        .expect("answered");
    assert_eq!(run.status(), StatusCode::OK);
    let html = run.text().await.expect("text");
    assert!(html.contains("<code>ace --help</code>"), "{html}");
    assert!(html.contains("waiting for output"), "{html}");
    let console = stack
        .get("/admin/cli")
        .header("cookie", cookie(&op))
        .send()
        .await
        .expect("answered");
    assert_eq!(console.status(), StatusCode::OK);
    assert!(
        console
            .text()
            .await
            .expect("text")
            .contains(&format!(r#"href="/admin/cli/{id}""#))
    );

    // the fragment its page polls, while the run is queued
    let fragment = stack
        .get(&format!("/admin/cli/{id}/output"))
        .header("cookie", cookie(&op))
        .header("datastar-request", "true")
        .send()
        .await
        .expect("answered");
    assert_eq!(fragment.status(), StatusCode::OK);
    assert!(
        fragment
            .text()
            .await
            .expect("text")
            .contains("data-on-interval")
    );

    // refusals: a line the service won't take draws the form again with it, and writes nothing
    let rows = stack.audit_count().await;
    for (line, timeout) in [
        ("-c x node list", "10"),
        ("--help", "0"),
        ("--help", "soon"),
    ] {
        let refused = stack
            .post(
                "/admin/cli",
                &[("command", line), ("timeout_seconds", timeout)],
            )
            .header("cookie", cookie(&op))
            .send()
            .await
            .expect("answered");
        assert_eq!(
            refused.status(),
            StatusCode::BAD_REQUEST,
            "{line} {timeout}"
        );
        let html = refused.text().await.expect("text");
        assert!(html.contains("Nothing ran:"), "{html}");
        assert!(html.contains(&format!(r#"value="{timeout}""#)), "{html}");
    }
    // another site's post, a viewer without cli:execute or admin:read, and one signed out
    let cross = stack
        .http
        .post(format!("{}/admin/cli", stack.url))
        .header("origin", "https://evil.example")
        .header("cookie", cookie(&op))
        .form(&[("command", "--help")])
        .send()
        .await
        .expect("answered");
    assert_eq!(cross.status(), StatusCode::FORBIDDEN);
    for (token, path) in [
        (&adm, "/admin/cli".to_owned()),
        (&adm, page.clone()),
        (&none, "/admin/cli".to_owned()),
        (&none, page.clone()),
    ] {
        let refused = stack
            .get(&path)
            .header("cookie", cookie(token))
            .send()
            .await
            .expect("answered");
        assert_eq!(refused.status(), StatusCode::FORBIDDEN, "{path}");
    }
    for token in [&adm, &none] {
        let refused = stack
            .post("/admin/cli", &[("command", "--help")])
            .header("cookie", cookie(token))
            .send()
            .await
            .expect("answered");
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        let refused = stack
            .post(&format!("/admin/cli/{id}/cancel"), &[])
            .header("cookie", cookie(token))
            .send()
            .await
            .expect("answered");
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        let refused = stack
            .get(&format!("/admin/cli/{id}/output"))
            .header("cookie", cookie(token))
            .send()
            .await
            .expect("answered");
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    }
    let signed_out = stack.get(&page).send().await.expect("answered");
    assert_eq!(signed_out.status(), StatusCode::SEE_OTHER);
    assert!(location(&signed_out).starts_with("/login?next="));
    let signed_out = stack
        .get(&format!("/admin/cli/{id}/output"))
        .header("datastar-request", "true")
        .send()
        .await
        .expect("answered");
    assert_eq!(signed_out.status(), StatusCode::UNAUTHORIZED);
    for (path, status) in [
        ("/admin/cli/x".to_owned(), StatusCode::BAD_REQUEST),
        (format!("/admin/cli/{}", i64::MAX), StatusCode::NOT_FOUND),
        ("/admin/cli?after=x".to_owned(), StatusCode::BAD_REQUEST),
        (
            format!("/admin/cli/{}/output", i64::MAX),
            StatusCode::NOT_FOUND,
        ),
    ] {
        let answered = stack
            .get(&path)
            .header("cookie", cookie(&op))
            .send()
            .await
            .expect("answered");
        assert_eq!(answered.status(), status, "{path}");
    }
    assert_eq!(stack.audit_count().await, rows, "no refusal wrote");

    // a cancel ends the queued run, with its row; a second is a conflict on the run's page
    let cancelled = stack
        .post(&format!("/admin/cli/{id}/cancel"), &[])
        .header("cookie", cookie(&op))
        .send()
        .await
        .expect("answered");
    assert_eq!(cancelled.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&cancelled), page);
    assert_eq!(last_action(&stack).await, "cancel_command");
    let rows = stack.audit_count().await;
    let again = stack
        .post(&format!("/admin/cli/{id}/cancel"), &[])
        .header("cookie", cookie(&op))
        .send()
        .await
        .expect("answered");
    assert_eq!(again.status(), StatusCode::CONFLICT);
    assert!(
        again
            .text()
            .await
            .expect("text")
            .contains("Nothing was cancelled")
    );
    assert_eq!(stack.audit_count().await, rows);
    let fragment = stack
        .get(&format!("/admin/cli/{id}/output"))
        .header("cookie", cookie(&op))
        .send()
        .await
        .expect("answered");
    let html = fragment.text().await.expect("text");
    assert!(html.contains("cancelled before a pool took it"), "{html}");
    assert!(!html.contains("data-on-interval"), "it no longer polls");
}

/// PLAN.md 7.4's three views draw hostile text escaped: the user's attributes and groups, the
/// newly registered domain's error, and the clicker's clicks, with a link that isn't HTTPS left out.
#[test]
fn the_network_pool_s_new_views_escape_what_a_module_wrote() {
    let views = Views::builtin();
    let hostile = "<script>alert(1)</script>\"'&";
    let draw = |name: &str, details: serde_json::Value| {
        let html = views.draw(name, 1, &details);
        assert_eq!(html.fallback, None, "{name}");
        let html = html.html.as_str().to_owned();
        assert!(!html.contains("<script>"), "{name}: {html}");
        assert!(inline_free(&html), "{name}: {html}");
        html
    };
    let user = draw(
        "user_analysis",
        serde_json::json!({"ldap": {
            "displayName": hostile, "mail": format!("x@example.com\" data-x=\"{hostile}"),
            "entitlements": [{"group": format!("CN={hostile},OU=a,DC=b"), "privileged": false}],
        }, "manager_ldap": null}),
    );
    assert!(
        user.contains("&#60;script&#62;alert(1)&#60;/script&#62;"),
        "{user}"
    );
    assert!(!user.contains("\" data-x=\""), "{user}");
    let nrd = draw(
        "nrd_analysis",
        serde_json::json!({"is_nrd": true, "matched_at": null, "datetime_created": null,
            "age_created_in_days": null, "lookup_protocol": null, "lookup_error": hostile}),
    );
    assert!(nrd.contains("&#60;script&#62;"), "{nrd}");
    let clicker = draw(
        "splunk_clicker_detection_analysis",
        serde_json::json!({"query": null, "query_results": null, "query_error": hostile,
            "question": hostile, "query_summary": null, "query_start": null,
            "gui_link": "javascript:alert(1)", "gui_link_label": hostile,
            "search_id": null, "dispatch_state": null, "start_time": null,
            "running_start_time": null, "end_time": null, "clicker_plan": [], "clicker_index": 0,
            "clicker_source": "splunk", "matched_url_count": 1,
            "clicker_events": [{"source": hostile, "portal_url": null, "timestamp": hostile,
                "user": [hostile, "b"], "action_type": null, "url": hostile,
                "searched_value": hostile, "network_message_id": null}]}),
    );
    assert!(!clicker.contains("href=\"javascript:"), "{clicker}");
    assert!(clicker.contains("<td>&#60;script&#62;"), "{clicker}");
}

/// PLAN.md 7.5 batch 8: a lure URL, its anchor's text and the reasons built from them come from the
/// email's sender, so they're escaped, the bold of a highlight around the escaped text.
#[test]
fn the_lure_view_escapes_what_the_email_wrote() {
    let views = Views::builtin();
    let hostile = "<script>alert(1)</script>";
    let candidate = serde_json::json!({
        "url": format!("https://x.example/{hostile}"),
        "score": 45,
        "sources": ["body"],
        "anchor_text": hostile,
        "carries": [],
        "reasons": ["found in the email body", format!("clickable link with text '{hostile}'")],
        "highlights": [[], [hostile]],
    });
    let html = drawn(
        &views,
        &serde_json::from_value(serde_json::json!({
            "analysis_type": "lure_url_analysis", "schema_version": 1,
            "details": {"primary": candidate, "candidates": [candidate], "has_inner_email": true, "subject": hostile},
        }))
        .expect("a result"),
    );
    assert!(!html.contains("<script>"), "{html}");
    assert!(
        html.contains(
            "clickable link with text &#39;<b>&#60;script&#62;alert(1)&#60;/script&#62;</b>&#39;"
        ),
        "{html}"
    );
    assert!(html.contains("this email carries another"));
    assert!(
        !html.contains("other candidate"),
        "the primary is the only candidate"
    );
}
