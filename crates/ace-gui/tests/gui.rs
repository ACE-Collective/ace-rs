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
//! PLAN.md 7.9 (5.11's remediation and file_collection areas): the remediations, a remediation's page,
//! Add Remediation, the file collections and a collection's page, drawn directly with hostile values, and
//! through the server under `remediation:read`/`write` and `file_collection:read`/`write`, each write from
//! this site only with its audit row; and the event page's remediation coverage badges.
//!
//! PLAN.md 7.14: an alert's detection verdicts on its page, drawn directly with hostile text and ace3's menu,
//! and through the server under `alert:read` and `alert:write`, each form one audited write from this site
//! only, and each refusal changing nothing.
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
use ace_gui::alert::{
    AlertPage, AlertTreeFragment, GraphPage, OwnerNoticeFragment, PageOptions, TreeMode, tree_view,
    tree_view_in,
};
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
    stack_of(Catalog::new(vec![]), build).await
}

/// A stack whose modules are `catalog`'s.
async fn stack_of(catalog: Catalog, build: impl FnOnce(Service) -> Gui) -> Stack {
    stack_of_db(catalog, |service, _| build(service)).await
}

/// `stack_of`, building the GUI with the stack's database too.
async fn stack_of_db(catalog: Catalog, build: impl FnOnce(Service, &ace_core::Db) -> Gui) -> Stack {
    let test_db = TestDb::new().await;
    let orchestrator = Orchestrator::new(catalog, Modes::ace3());
    // ace3's dispositions with two of the site's own, one of which only ACE sets
    let overlay = ace_sdk::Overlay::from_yaml(
        "dispositions:\n  SITE_CHECKED: {rank: 45, css: site-checked_1, show_save_to_event: true}\n  \
         SITE_SWEEP: {rank: 5, css: dark, analyst_selectable: false}\n  DAMAGE: {css: warning}\n",
    )
    .expect("the overlay parses");
    let service = Service::new(test_db.db().clone(), orchestrator)
        .with_actions(test_actions())
        .with_dispositions(ace_service::Dispositions::configured(&overlay).expect("good sections"));
    let gui = build(service.clone(), test_db.db());
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
    let value = cookie.strip_prefix("ace_rs_session=")?.split(';').next()?;
    (!value.is_empty()).then(|| value.to_owned())
}

fn cookie(token: &str) -> String {
    format!("ace_rs_session={token}")
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
        &ace_service::Dispositions::ace3(),
        None,
    );
    let signed_in = ListPage::new(
        Layout::new("n0nce", Theme::Dark, Some("alice".to_owned()), "/"),
        view,
    )
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
        "ace_rs_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"
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
    assert!(cleared.starts_with("ace_rs_session=;"), "{cleared}");
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
    assert!(set.starts_with("__Host-ace_rs_session=ace-rs-s_"), "{set}");
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
        ("/icons/nothing.png", StatusCode::NOT_FOUND),
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
    assert_eq!(nonces.len(), 5, "a new nonce each time");
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
    let mut dirs = vec![root.join("src")];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir).expect("reads the source") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                dirs.push(path);
                continue;
            }
            let source = std::fs::read_to_string(path).expect("reads");
            safe += source.matches("HtmlSafe for").count();
        }
    }
    // ... and a guide's HTML, which only `help::render_markdown` makes, from the repository's own
    // Markdown with any raw HTML in it written as text (src/help.rs, PLAN.md 7.10 batch 9).
    assert_eq!(safe, 2, "two types are marked as already escaped");
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
        queue: "<q>ueue & \"co\"".to_owned(),
        tags: Vec::new(),
        svs: None,
        owner: None,
        owned_at: None,
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
        display_value: None,
        ignored: false,
        files: Vec::new(),
        file_type: None,
        relationships: Vec::new(),
        results: Vec::new(),
        failed: Some(Vec::new()),
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
        error: None,
        tags: Vec::new(),
        details: serde_json::json!({}),
        created_at: chrono::DateTime::from_timestamp(1_793_000_000, 0).expect("a time"),
        cached_at: None,
        pivot_links: Vec::new(),
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
        role: None,
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
            pivot_links: Vec::new(),
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
        root_detections: Vec::new(),
        truncated: false,
        origin: serde_json::Value::Null,
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

/// A result the analysis cache wrote in place of a task (PLAN.md decision 26) has a `cached` badge after
/// its summary, saying when the run it was kept from ended, as ace3's `from_cache_hit` and `cached_at`;
/// its page says the same above the details; a result a task made has neither.
#[test]
fn a_result_from_the_cache_says_so_and_when_it_ran() {
    let (mut tree, comments) = fixture_tree();
    let ran = chrono::DateTime::from_timestamp(1_790_000_000, 0).expect("a time");
    tree.observables[2].results[0].cached_at = Some(ran);
    let html = AlertTreeFragment {
        tree: tree_view(&tree, &comments, &ObservableActions::empty()),
    }
    .render()
    .expect("renders");
    let compact: String = html.lines().map(str::trim).collect();
    let line = r#"<li class="result" id="r11" data-module="rdap_analyzer"><a class="summary" href="/alerts/00000000-0000-0000-0000-000000005800/results/11" title="rdap_analyzer">rdap_analyzer</a> <span class="cached" title="From the analysis cache: the module's result from its run at 2026-09-21 14:13:20 UTC, not run again here">cached</span>"#;
    assert!(compact.contains(line), "{compact}");
    assert_eq!(compact.matches("class=\"cached\"").count(), 1, "{compact}");

    let layout = || Layout::new("n0nce", Theme::Light, Some("alice".to_owned()), "/alerts/x");
    let page = ace_gui::alert::ResultPage::new(layout(), &tree, 11, &Views::builtin())
        .expect("the result")
        .render()
        .expect("renders");
    let compact: String = page.lines().map(str::trim).collect();
    let message = r#"<p class="cached-message"><span class="cached">cached</span> From the analysis cache: rdap_analyzer's result from its run at 2026-09-21 14:13:20 UTC, which this alert didn't run again.</p>"#;
    assert!(compact.contains(message), "{compact}");
    assert!(
        compact.find(message) < compact.find(r#"<div class="analysis-view">"#),
        "{compact}"
    );
    let page = ace_gui::alert::ResultPage::new(layout(), &tree, 10, &Views::builtin())
        .expect("the result")
        .render()
        .expect("renders");
    assert!(!page.contains("cached"), "{page}");
}

/// A failed analysis (ace3's `Analysis.error`, its 2b9fcd2c): a result whose module said it failed has
/// an `error` badge with the reason as its title, and the reason beside it when it has no summary; a
/// module whose task failed without a result is listed under its observable; and the result's page
/// shows the reason above the details. All of it is a module's text, so all of it is escaped.
#[test]
fn a_failed_analysis_has_a_badge_its_reason_and_its_place_under_the_observable() {
    let (mut tree, comments) = fixture_tree();
    let hostile = "exited 2: <img src=x onerror=alert(1)>";
    // the email's result has a summary, so the badge alone; the IP's has none, so the reason too
    tree.observables[0].results[0].error = Some(hostile.to_owned());
    let long = format!("{}<b>", "x".repeat(250));
    tree.observables[2].results[0].error = Some(long.clone());
    // on the fqdn: one module killed at its deadline, and one that recorded no reason
    tree.observables[3].failed = Some(vec![
        ace_service::FailedModule {
            module: "fqdn_analyzer".to_owned(),
            error: Some("the task ran past its <deadline>".to_owned()),
            task: 7,
        },
        ace_service::FailedModule {
            module: "nrd_analyzer".to_owned(),
            error: None,
            task: 8,
        },
    ]);
    let view = tree_view(&tree, &comments, &ObservableActions::empty());
    let html = AlertTreeFragment { tree: view }.render().expect("renders");
    let compact: String = html.lines().map(str::trim).collect();
    let escaped = "exited 2: &#60;img src=x onerror=alert(1)&#62;";
    let order = [
        // a summary says why already: the badge, whose title is the whole reason
        format!(
            r#"<li class="result" id="r10" data-module="email_analyzer"><span class="failure" title="The analysis module failed: {escaped}">error</span><a class="summary" href="/alerts/00000000-0000-0000-0000-000000005800/results/10" title="email_analyzer">Email &#60;b&#62;Analysis&#60;/b&#62;</a> <span class="tag">"#
        ),
        // no summary: the module's name, and the reason, cut to 200 characters
        format!(
            r#"<li class="result" id="r11" data-module="rdap_analyzer"><span class="failure" title="The analysis module failed: {}&#60;b&#62;">error</span><a class="summary" href="/alerts/00000000-0000-0000-0000-000000005800/results/11" title="rdap_analyzer">rdap_analyzer</a> <span class="failure-reason">{}…</span>"#,
            "x".repeat(250),
            "x".repeat(199)
        ),
        // the modules that failed on the fqdn without a result, under it
        r#"<li class="observable" id="o4"><b class="type">fqdn</b> : <span class="value">evil.example.com&#39;&#62;&#60;img src=x&#62;</span><ul><li class="result failed" data-module="fqdn_analyzer"><span class="failure" title="The analysis module failed: the task ran past its &#60;deadline&#62;">error</span><span class="module">fqdn_analyzer</span> <span class="failure-reason">the task ran past its &#60;deadline&#62;</span></li><li class="result failed" data-module="nrd_analyzer"><span class="failure" title="The analysis module failed: the analysis module failed">error</span><span class="module">nrd_analyzer</span> <span class="failure-reason">the analysis module failed</span></li></ul></li>"#.to_owned(),
    ];
    let mut at = 0;
    for part in &order {
        let found = compact[at..]
            .find(part.as_str())
            .unwrap_or_else(|| panic!("{part}\nisn't after byte {at} of\n{compact}"));
        at += found + part.len();
    }
    assert_eq!(
        compact.matches("<li").count(),
        compact.matches("</li>").count()
    );
    assert_eq!(
        compact.matches("<ul").count(),
        compact.matches("</ul>").count()
    );
    for raw in ["<img src=x onerror", "<deadline>", "x<b>"] {
        assert!(!html.contains(raw), "{raw} unescaped in {html}");
    }
    // a result that didn't fail has no badge, and an observable nothing failed on no such line
    let (clean, comments) = fixture_tree();
    let html = AlertTreeFragment {
        tree: tree_view(&clean, &comments, &ObservableActions::empty()),
    }
    .render()
    .expect("renders");
    assert!(!html.contains("failure"), "{html}");

    // the result's page: the reason above the details, whole, and none on a result that didn't fail
    let layout = || Layout::new("n0nce", Theme::Light, Some("alice".to_owned()), "/alerts/x");
    let page = ace_gui::alert::ResultPage::new(layout(), &tree, 11, &Views::builtin())
        .expect("the result")
        .render()
        .expect("renders");
    let compact: String = page.lines().map(str::trim).collect();
    let message = format!(
        r#"<p class="warning failure-message" role="alert"><b>rdap_analyzer failed:</b> <span class="failure-text">{}&#60;b&#62;</span></p>"#,
        "x".repeat(250)
    );
    assert!(compact.contains(&message), "{compact}");
    assert!(
        compact.find(&message) < compact.find(r#"<div class="analysis-view">"#),
        "the reason comes before the details: {compact}"
    );
    assert!(!page.contains("x<b>"), "{page}");
    let page = ace_gui::alert::ResultPage::new(layout(), &clean, 11, &Views::builtin())
        .expect("the result")
        .render()
        .expect("renders");
    assert!(!page.contains("failure-message"), "{page}");
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
    // the page starts at the branches that carry a detection (the UI direction of 2026-11-15), so
    // its version is that tree's, and the whole tree's is another
    let branches = tree_view_in(
        &tree,
        &comments,
        &ObservableActions::empty(),
        TreeMode::Detections,
    );
    assert_eq!(
        AlertTreeFragment { tree: branches }
            .render_versioned()
            .expect("renders")
            .1,
        version,
        "the page's version is its tree's"
    );
    assert_ne!(
        AlertTreeFragment { tree: view }
            .render_versioned()
            .expect("renders")
            .1,
        version
    );
    let page = open.render().expect("renders");
    assert!(page.contains(&format!(
        r#"<section class="alert" data-init="@get('/alerts/{}/live?v={version}&amp;o=')">"#,
        tree.alert.summary.id
    )));
    // the ownership notice's place, empty and hidden until the stream fills it
    assert!(
        page.contains(r#"<p id="owner-notice" hidden></p>"#),
        "{page}"
    );
    assert!(
        page.contains("<h1>&#60;i&#62;Phish&#60;/i&#62;</h1>"),
        "{page}"
    );
    // a secondary section starts collapsed, with a line saying what it holds
    assert!(
        page.contains(r#"<details class="section" data-section-id="alert_details">"#),
        "{page}"
    );
    assert!(
        page.contains(
            r#"<summary>Alert Details <span class="hint">correlation mode · 4 observables · 1 detections · event time 2026-10-26 07:33:20 UTC (event)</span></summary>"#
        ),
        "{page}"
    );
    assert!(page.contains("Collapsed by default"));
    assert!(page.contains("<th>Submitted by</th><td>&#60;the submitter&#62;</td>"));
    // the alert's queue is among its details, as ace3's alert.html has it (PLAN.md 7.13), as text
    assert!(
        page.contains("<th>Queue</th><td>&#60;q&#62;ueue &#38; &#34;co&#34;</td>"),
        "{page}"
    );
    assert!(page.contains(r#"<div id="alert-tree" class="tree">"#));
    assert!(
        !page.contains("style="),
        "no inline style, which the policy refuses"
    );
    assert!(!page.contains("<script>"), "no inline script");
    // the viewer's pin opens it
    let pinned = AlertPage::new(
        Layout::new("n0nce", Theme::Light, Some("alice".to_owned()), "/alerts/x"),
        &tree,
        &comments,
        &ObservableActions::empty(),
        &[("alert_details".to_owned(), true)].into_iter().collect(),
    )
    .expect("a page")
    .render()
    .expect("renders");
    assert!(pinned.contains(r#"<details class="section" data-section-id="alert_details" open>"#));
    assert!(pinned.contains("Open by default"));
}

/// PLAN.md 7.6: what the core's hooks did shows as ace3's alert page shows it: the alert's own
/// detections, the Observable Modifier Rules card with what a rule's `ignore` took out, a display value,
/// and an ignored observable left out of the tree, each module's text escaped.
#[test]
fn the_alert_shows_what_the_hooks_did() {
    let (mut tree, comments) = fixture_tree();
    tree.root_detections.push(AlertDetection {
        description: "tag <phish> is configured to be alertable".to_owned(),
        details: None,
        module: None,
    });
    let rule = |name: &str, uuid: &str, actions: serde_json::Value| serde_json::json!({"name": name, "uuid": uuid, "actions_applied": actions});
    let mut modifier = module_result(20, "observable_modifier", Some("Applied 1 rule(s)"));
    modifier.analysis_type = "observable_modifier_analysis".to_owned();
    modifier.details = serde_json::json!({"matched_rules": [
        rule("<b>hide</b>", "u1", serde_json::json!({"ignore": true})),
    ]});
    // the fqdn: hidden from the tree, and listed under the rule that hid it
    tree.observables[3].ignored = true;
    tree.observables[3].results.push(modifier.clone());
    // the IP: a display value, and a rule that only tagged it
    tree.observables[2].display_value = Some("the <bad> one".to_owned());
    let mut tagged = modifier;
    tagged.id = 21;
    tagged.details = serde_json::json!({"matched_rules": [
        rule("a tagger", "u2", serde_json::json!({"add_tags": ["x"], "set_display_value": "v"})),
    ]});
    tree.observables[2].results.push(tagged);
    let page = AlertPage::new(
        Layout::new("n0nce", Theme::Light, Some("alice".to_owned()), "/alerts/x"),
        &tree,
        &comments,
        &ObservableActions::empty(),
        &std::collections::BTreeMap::new(),
    )
    .expect("a page");
    assert_eq!(page.ignored_count, 1);
    assert_eq!(
        page.modifier_rules
            .iter()
            .map(|r| (r.name.as_str(), r.observables, r.actions.as_str()))
            .collect::<Vec<_>>(),
        [
            ("<b>hide</b>", 1, "ignore"),
            ("a tagger", 1, "add_tags, set_display_value")
        ],
        "a rule that ignored something first"
    );
    let html = page.render().expect("renders");
    let compact: String = html.lines().map(str::trim).collect();
    assert!(
        compact.contains("detection: tag &#60;phish&#62; is configured to be alertable"),
        "{compact}"
    );
    assert!(
        compact
            .contains("Observable Modifier Rules (2 rules) <span class=\"badge\">1 ignored</span>")
    );
    assert!(compact.contains("&#60;b&#62;hide&#60;/b&#62;"));
    assert!(compact.contains("hidden from the analysis tree"));
    assert!(
        compact.contains(r#"<span class="value">the &#60;bad&#62; one (192.0.2.10)</span>"#),
        "{compact}"
    );
    assert!(
        !compact.contains(r#"id="o4""#),
        "an ignored observable isn't drawn in the tree"
    );
    assert!(!html.contains("<b>hide") && !html.contains("<bad>") && !html.contains("<phish>"));
    assert!(!html.contains("style="));
}

/// The owner's UI direction of 2026-11-15: the page leads with what decides the alert, its secondary
/// sections are collapsed, and its tree starts at the branches that carry a detection, with the whole
/// tree a link or a pin away and nothing removed.
#[test]
fn the_alert_page_leads_with_what_decides_the_alert() {
    let (tree, comments) = fixture_tree();
    let id = tree.alert.summary.id;
    let layout = || Layout::new("n0nce", Theme::Light, Some("alice".to_owned()), "/alerts/x");
    let none = std::collections::BTreeMap::new();
    let page = AlertPage::new(
        layout(),
        &tree,
        &comments,
        &ObservableActions::empty(),
        &none,
    )
    .expect("a page");
    assert_eq!(
        page.fired
            .iter()
            .map(|f| (f.description.as_str(), f.on.as_str(), f.others))
            .collect::<Vec<_>>(),
        [("a known <bad> sender", "email_from: a@example.com", 0)]
    );
    assert!(!page.tree.full && page.tree.prunable);
    assert_eq!((page.tree.shown, page.tree.total), (3, 4));
    let html = drawn_safely(&page);
    let compact: String = html.lines().map(str::trim).collect();
    // the order of the page: the title, what it is and whose, what fired, the key observables, the
    // collapsed details, the tree
    let order = [
        "<h1>&#60;i&#62;Phish&#60;/i&#62;</h1>",
        r#"<dt>Disposition</dt><dd><span class="badge disposition-"#,
        r#"<dt>Owner</dt><dd><span class="muted">nobody</span></dd>"#,
        "<dt>Queue</dt><dd>&#60;q&#62;ueue &#38; &#34;co&#34;</dd>",
        r#"<h2 id="fired-title">What fired</h2>"#,
        r#"<span class="fired-what">a known &#60;bad&#62; sender</span>"#,
        "on email_from: a@example.com",
        r#"<h2 id="type-summary-title">Key observables</h2>"#,
        &format!(
            r#"<b class="type">Mail From (email_from)</b> <a class="value" href="/alerts/{id}?tree=full#o2">a@example.com</a> <span class="badge tone-bad">1 detection</span>"#
        ),
        &format!(
            r#"<b class="type">file</b> <a class="value" href="/alerts/{id}?tree=full#o1">email.rfc822</a>"#
        ),
        r#"<details class="section" data-section-id="alert_details">"#,
        r#"<section class="overview" id="analysis">"#,
        r##"<p class="tree-scope">The branches with a detection: 3 of 4 observables. <a href="?tree=full#analysis">Show the whole tree</a></p>"##,
        r#"<li class="observable" id="o1">"#,
        r#"<li class="observable" id="o2">"#,
        "Detections only by default",
    ];
    let mut at = 0;
    for part in order {
        let found = compact[at..]
            .find(part)
            .unwrap_or_else(|| panic!("{part}\nisn't after byte {at} of\n{compact}"));
        at += found + part.len();
    }
    // the branches: the email, its result, the sender with the detection, and the IP whose result
    // names the sender again; the fqdn carries nothing and leads to nothing
    assert!(compact.contains(r#"id="o3""#) && compact.contains(r#"id="r11""#));
    assert!(!compact.contains(r#"id="o4""#), "{compact}");
    assert!(!compact.contains(" open>"), "no section starts open");
    assert!(
        !compact.contains("t=full"),
        "the stream follows the page's tree"
    );

    // nothing is removed: the whole tree is a link away, and says how to come back
    let whole = drawn_safely(
        &AlertPage::with(
            layout(),
            &tree,
            &comments,
            &ObservableActions::empty(),
            &none,
            PageOptions {
                tree: Some(TreeMode::Full),
                ..PageOptions::default()
            },
        )
        .expect("a page"),
    );
    let whole: String = whole.lines().map(str::trim).collect();
    assert!(whole.contains(r#"id="o4""#), "{whole}");
    assert!(
        whole.contains(
            r##"<p class="tree-scope">The whole tree, 4 observables. <a href="?tree=detections#analysis">Show only the branches with a detection</a></p>"##
        ),
        "{whole}"
    );
    assert!(
        whole.contains("&amp;o=&#38;t=full')\">"),
        "the stream is told which tree the page drew: {whole}"
    );
    // or a pin away: the viewer's choice for every alert, which a page's own link still overrides
    let pinned: std::collections::BTreeMap<String, bool> =
        [("analysis_tree".to_owned(), true)].into_iter().collect();
    let by_pin = AlertPage::new(
        layout(),
        &tree,
        &comments,
        &ObservableActions::empty(),
        &pinned,
    )
    .expect("a page");
    assert!(by_pin.tree.full);
    assert!(drawn_safely(&by_pin).contains("Whole tree by default"));
    let asked = AlertPage::with(
        layout(),
        &tree,
        &comments,
        &ObservableActions::empty(),
        &pinned,
        PageOptions {
            tree: Some(TreeMode::Detections),
            ..PageOptions::default()
        },
    )
    .expect("a page");
    assert!(!asked.tree.full);

    // a tree with no detection on any observable is drawn whole, with nothing to choose
    let mut plain = tree.clone();
    for observable in &mut plain.observables {
        observable.detections.clear();
    }
    let plain = AlertPage::new(
        layout(),
        &plain,
        &comments,
        &ObservableActions::empty(),
        &none,
    )
    .expect("a page");
    assert!(plain.tree.full && !plain.tree.prunable && plain.fired.is_empty());
    let plain = drawn_safely(&plain);
    assert!(plain.contains(r#"id="o4""#) && !plain.contains("tree-scope"));
    assert!(plain.contains("No detection is recorded on this alert."));
    assert!(!plain.contains("Detections only by default"));
}

/// A site's summary for one kind of hunt, as `ace_app::App::alert_summary` registers one.
#[derive(Template)]
#[template(
    source = r#"<section class="type-summary cloud-summary">{{ note }}</section>"#,
    ext = "html"
)]
struct CloudSummaryView<'a> {
    note: &'a str,
}

struct CloudSummary;

impl ace_gui::AlertSummary for CloudSummary {
    const ALERT_TYPE: &'static str = "hunter - splunk - aws";
    type View<'a> = CloudSummaryView<'a>;

    fn view<'a>(alert: &ace_gui::SummaryInput<'a>) -> Option<CloudSummaryView<'a>> {
        alert.origin["details"]["note"]
            .as_str()
            .map(|note| CloudSummaryView { note })
    }
}

/// The page's summary is chosen by the alert's type, its origin's `alert_type`, as ace3 chooses a
/// template (`GUIAlertPresenter.template_path`): a mailbox alert's email, a hunt alert's hunt, a
/// site's own for the types it names, and the key observables for everything else. Each draws what
/// the submitter and the modules wrote as text.
#[test]
fn an_alert_s_summary_is_chosen_by_its_type() {
    let builtin = ace_gui::AlertSummaries::builtin();
    assert_eq!(builtin.types().collect::<Vec<_>>(), ["hunter", "mailbox"]);
    for (alert_type, chosen) in [
        ("mailbox", Some("mailbox")),
        ("hunter", Some("hunter")),
        ("hunter - splunk - v2", Some("hunter")),
        ("hunter - splunk - aws - prod", Some("hunter")),
        // a type is matched at its ` - ` parts, not by its letters
        ("hunters - splunk", None),
        ("mailboxes", None),
        ("manual", None),
        ("", None),
    ] {
        assert_eq!(builtin.chosen(alert_type), chosen, "{alert_type}");
    }
    let site = builtin
        .clone()
        .with(ace_gui::SummaryEntry::of::<CloudSummary>());
    assert_eq!(
        site.chosen("hunter - splunk - aws - prod"),
        Some("hunter - splunk - aws"),
        "the longest registered type"
    );
    assert_eq!(site.chosen("hunter - splunk - gcp"), Some("hunter"));

    let (fixture, comments) = fixture_tree();
    let id = fixture.alert.summary.id;
    let page_of = |tree: &AlertTree, options: PageOptions<'_>| {
        let html = drawn_safely(
            &AlertPage::with(
                Layout::new("n0nce", Theme::Light, Some("alice".to_owned()), "/alerts/x"),
                tree,
                &comments,
                &ObservableActions::empty(),
                &std::collections::BTreeMap::new(),
                options,
            )
            .expect("a page"),
        );
        html.lines().map(str::trim).collect::<Vec<_>>().join("")
    };

    // no type: the default
    let default = page_of(&fixture, PageOptions::default());
    assert!(default.contains(r#"<h2 id="type-summary-title">Key observables</h2>"#));
    assert!(!default.contains("<dt>Type</dt>"));

    // a mailbox alert: the email, from what the mailbox module merged into the root's origin
    let mut mail = fixture.clone();
    mail.origin = serde_json::json!({"alert_type": "mailbox", "details": {"email": {
        "from": "\"<b>Billing</b>\" <billing@example.net>",
        "env_mail_from": "bounce@example.net",
        "to": ["pat@example.com"],
        "env_rcpt_to": ["pat@example.com", "sam@example.com"],
        "subject": "=?utf-8?q?raw?=",
        "decoded_subject": "<script>alert(1)</script> invoice",
        "message-id": " <m1@example.net> ",
        "spf_result": "pass",
        "dmarc_result": "fail",
        "authentication_failed": true,
        "headers": [["Date", "Mon, 26 Oct 2026 07:00:00 +0000"], ["X-<i>", "v</pre><b>"]],
        "log_entry": {
            "attachment_names": ["<img src=x>.html", "b.pdf"],
            "attachment_types": ["text/html"],
            "attachment_sizes": [10],
        },
    }}});
    // the email's result, and the body among the files it added
    mail.observables[0].results[0].analysis_type = "email_analysis".to_owned();
    let mut body = observable(5, "file", "b0");
    body.files.push(AlertFile {
        path: "email.rfc822.unknown_text_html_000.html".to_owned(),
        yara_meta: Vec::new(),
        role: None,
    });
    mail.observables.push(body);
    mail.additions.push(ace_service::Addition {
        result: 10,
        observable: 5,
    });
    let target = |recipient: &str, sources: &[&str]| ace_service::TargetCoverage {
        target: format!("<m1@example.net>|{recipient}"),
        sources: sources.iter().map(|s| (*s).to_owned()).collect(),
        failed: false,
        pending: false,
        remediating: false,
        not_found: false,
        attempted: !sources.is_empty(),
        undelivered: None,
        not_delivered: false,
    };
    let coverage = ace_service::RemediationTimeline {
        coverage: ace_service::Coverage {
            targets: vec![
                target("pat@example.com", &["ACE"]),
                target("<u>sam</u>@example.com", &[]),
            ],
        },
        ..ace_service::RemediationTimeline::default()
    };
    let page = page_of(
        &mail,
        PageOptions {
            remediation: Some(&coverage),
            ..PageOptions::default()
        },
    );
    contains_all(
        &page,
        &[
            r#"<section class="type-summary email-summary" aria-labelledby="type-summary-title">"#,
            r#"<p class="summary-lead">&#60;script&#62;alert(1)&#60;/script&#62; invoice</p>"#,
            r#"<span class="badge tone-bad">authentication failed</span>"#,
            r#"<span class="badge tone-ok">SPF: pass</span>"#,
            r#"<span class="badge tone-warn">DMARC: fail</span>"#,
            "<dt>From</dt><dd>&#34;&#60;b&#62;Billing&#60;/b&#62;&#34; &#60;billing@example.net&#62;</dd>",
            "<dt>Envelope sender</dt><dd>bounce@example.net</dd>",
            "<dt>To</dt><dd>pat@example.com</dd>",
            "<dt>Delivered to</dt><dd>pat@example.com, sam@example.com</dd>",
            "<dt>Date</dt><dd>Mon, 26 Oct 2026 07:00:00 +0000</dd>",
            "<dt>Message-ID</dt><dd>&#60;m1@example.net&#62;</dd>",
            &format!(
                r#"<dt>Body</dt><dd><a href="/alerts/{id}?tree=full#o5">email.rfc822.unknown_text_html_000.html</a>"#
            ),
            r#"<li>&#60;img src=x&#62;.html <span class="muted">text/html</span> <span class="muted">10 bytes</span></li>"#,
            "<li>b.pdf</li>",
            r#"<li>pat@example.com <span class="badge coverage-remediated">remediated</span> <span class="muted">by ACE</span></li>"#,
            r#"<li>&#60;u&#62;sam&#60;/u&#62;@example.com <span class="badge coverage-unremediated">not attempted</span></li>"#,
            &format!(r#"<a href="/remediations/targets?alert={id}">Remediation targets</a>"#),
            "X-&#60;i&#62;: v&#60;/pre&#62;&#60;b&#62;",
            // the header and the details say the type, and the alert's remediation has its panel
            "<dt>Type</dt><dd>mailbox</dd>",
            "<th>Alert type</th><td>mailbox</td>",
            r#"<details class="section remediation" id="remediation" data-section-id="remediation">"#,
        ],
    );
    assert!(!page.contains("Key observables"), "{page}");
    // a viewer who may not read remediation has the email, with no delivered copies and no panel
    let unread = page_of(&mail, PageOptions::default());
    assert!(
        unread.contains("email-summary")
            && !unread.contains("Delivered copies")
            && !unread.contains(r#"id="remediation""#),
        "{unread}"
    );
    // a mailbox alert with no email yet has the default
    let mut early = fixture.clone();
    early.origin = serde_json::json!({"alert_type": "mailbox"});
    assert!(page_of(&early, PageOptions::default()).contains("Key observables"));

    // a hunt alert: what the hunter submitted, the query with its window, and the matched event
    let mut hunt = fixture.clone();
    hunt.origin = serde_json::json!({
        "alert_type": "hunter - splunk - v2",
        "description": "<b>hunt</b>",
        "instructions": "look <i>here</i>",
        "tool": "hunter-splunk",
        "tool_instance": "splunk.example.com",
        "event_time": "2026-10-26T07:00:00+00:00",
        "event_time_source": "event",
        "queue": "default",
        "extensions": {"playbook_url": "javascript:alert(1)"},
        "details": {
            "search_link": "https://splunk.example.com/search?sid=1&x=<y>",
            "query": "search index=x earliest=10/26/2026:06:00:00 latest=10/26/2026:07:00:00 \"<script>\" | stats count",
            "events": [{"host": "<img src=x>", "n": 3, "list": ["a", "b"]}, {"host": "second"}],
        },
    });
    let page = page_of(&hunt, PageOptions::default());
    contains_all(
        &page,
        &[
            r#"<section class="type-summary hunt-summary" aria-labelledby="type-summary-title">"#,
            r#"<span class="muted">2 matched events</span>"#,
            r#"<p class="summary-note">look &#60;i&#62;here&#60;/i&#62;</p>"#,
            "<dt>Hunt</dt><dd>&#60;b&#62;hunt&#60;/b&#62;</dd>",
            "<dt>Alert type</dt><dd>hunter - splunk - v2</dd>",
            "<dt>Searched</dt><dd>hunter-splunk at splunk.example.com</dd>",
            "<dt>Event time</dt><dd>2026-10-26T07:00:00+00:00 (event)</dd>",
            "<dt>Time window</dt><dd><code>earliest=10/26/2026:06:00:00 latest=10/26/2026:07:00:00</code></dd>",
            r#"<a href="https://splunk.example.com/search?sid=1&#38;x=&#60;y&#62;" rel="noopener noreferrer" target="_blank">Open the search</a>"#,
            "&#34;&#60;script&#62;&#34; | stats count</pre>",
            "<dt>host</dt><dd>&#60;img src=x&#62;</dd>",
            "<dt>list</dt><dd>a, b</dd>",
            "<dt>n</dt><dd>3</dd>",
            "<summary>All 2 events</summary>",
        ],
    );
    // a link is only an http or https address
    assert!(
        !page.contains("javascript:") && !page.contains("Playbook"),
        "{page}"
    );
    assert!(!page.contains("Key observables"), "{page}");
    // an origin that names a hunter's type but holds neither a query nor an event has the default
    let mut thin = fixture.clone();
    thin.origin = serde_json::json!({"alert_type": "hunter - splunk", "tool": "hunter"});
    let thin = page_of(&thin, PageOptions::default());
    assert!(thin.contains("Key observables") && !thin.contains("hunt-summary"));

    // a site's summary takes the alerts of its type, and only those; an alert it has nothing to say
    // about has the default
    let mut cloud = hunt.clone();
    cloud.origin["alert_type"] = serde_json::json!("hunter - splunk - aws - prod");
    cloud.origin["details"]["note"] = serde_json::json!("<b>role</b> assumed");
    let options = || PageOptions {
        summaries: Some(&site),
        ..PageOptions::default()
    };
    let page = page_of(&cloud, options());
    assert!(
        page.contains(
            r#"<section class="type-summary cloud-summary">&#60;b&#62;role&#60;/b&#62; assumed</section>"#
        ) && !page.contains("hunt-summary"),
        "{page}"
    );
    assert!(page_of(&hunt, options()).contains("hunt-summary"));
    cloud.origin["details"]
        .as_object_mut()
        .expect("details")
        .remove("note");
    let page = page_of(&cloud, options());
    assert!(
        page.contains("Key observables") && !page.contains("cloud-summary"),
        "{page}"
    );
}

/// The page through the server: an alert's origin chooses its summary, a detection prunes its tree,
/// `?tree=full` draws the whole one, and each page's stream draws the tree its page did.
#[tokio::test]
async fn the_alert_page_reads_the_alert_s_type_and_draws_the_tree_asked_for() {
    let stack = stack().await;
    let alice = user(&stack, "alice").await;
    grant_alert_read(&stack, &alice).await;
    let (root, fqdn) = splunk_alert(&stack).await;
    let db = stack.test_db.db().pool();
    sqlx::query("UPDATE analysis.roots SET origin = $2 WHERE id = $1")
        .bind(root)
        .bind(serde_json::json!({
            "alert_type": "hunter - splunk - proxy",
            "description": "Proxy <hunt>",
            "tool": "hunter-splunk",
            "tool_instance": "splunk.example.com",
            "details": {"query": "search index=proxy earliest=-1h latest=now", "events": [{"dest": "www.example.com"}]},
        }))
        .execute(db)
        .await
        .expect("an origin");
    sqlx::query(
        "INSERT INTO analysis.detections (root_id, observable_id, description) VALUES ($1, $2, $3)",
    )
    .bind(root)
    .bind(fqdn.0)
    .bind("hunt <Proxy> matched")
    .execute(db)
    .await
    .expect("a detection");
    let session = session_of(&stack, "alice").await;
    let page = |path: String| {
        let request = stack.get(&path).header("cookie", cookie(&session));
        async move {
            let response = request.send().await.expect("answered");
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            response.text().await.expect("a page")
        }
    };
    let start = page(format!("/alerts/{root}")).await;
    assert!(
        start.contains(r#"class="type-summary hunt-summary""#)
            && start.contains("<dt>Hunt</dt><dd>Proxy &#60;hunt&#62;</dd>")
            && start.contains("<dt>Time window</dt><dd><code>earliest=-1h latest=now</code></dd>")
            && start.contains("<dt>dest</dt><dd>www.example.com</dd>")
            && start.contains("<th>Alert type</th><td>hunter - splunk - proxy</td>")
            && start.contains("<th>Instance</th><td>splunk.example.com</td>"),
        "{start}"
    );
    assert!(
        start.contains(r#"<span class="fired-what">hunt &#60;Proxy&#62; matched</span>"#)
            && start.contains("on fqdn: www.example.com"),
        "{start}"
    );
    // the fqdn carries the detection; its module's result and what that added don't
    assert!(
        start.contains("The branches with a detection: 1 of ")
            && !start.contains(r#"data-module="proxy_domain_lookup""#)
            && !start.contains("t=full"),
        "{start}"
    );
    let whole = page(format!("/alerts/{root}?tree=full")).await;
    assert!(
        whole.contains(r#"data-module="proxy_domain_lookup""#)
            && whole.contains("The whole tree, ")
            && whole.contains("&#38;t=full')\""),
        "{whole}"
    );
    // a parameter that names no tree is the viewer's default
    let other = page(format!("/alerts/{root}?tree=%3Cb%3E")).await;
    assert!(!other.contains(r#"data-module="proxy_domain_lookup""#) && !other.contains("<b>"));

    // each page's stream draws its page's tree: a stream that has neither page's version sends the
    // tree its `t` names
    let within = std::time::Duration::from_secs(10);
    let mut branches = stack
        .open_stream(&format!("/alerts/{root}/live?v=none&o="), &session)
        .await;
    assert_eq!(branches.status(), StatusCode::OK);
    let (sent, _) = read_stream(&mut branches, within, |text| text.contains("\n\n")).await;
    assert!(
        sent.contains("The branches with a detection") && !sent.contains("proxy_domain_lookup"),
        "{sent}"
    );
    let mut full = stack
        .open_stream(&format!("/alerts/{root}/live?v=none&o=&t=full"), &session)
        .await;
    let (sent, _) = read_stream(&mut full, within, |text| text.contains("\n\n")).await;
    assert!(
        sent.contains("The whole tree") && sent.contains("proxy_domain_lookup"),
        "{sent}"
    );
    // and one that has its page's version is quiet
    let version = |page: &str| {
        page.split("/live?v=")
            .nth(1)
            .and_then(|rest| rest.split("&amp;").next())
            .expect("a version")
            .to_owned()
    };
    for (page, t) in [(&start, ""), (&whole, "&t=full")] {
        let mut stream = stack
            .open_stream(
                &format!("/alerts/{root}/live?v={}&o={t}", version(page)),
                &session,
            )
            .await;
        let (nothing, _) = read_stream(&mut stream, std::time::Duration::from_millis(600), |_| {
            false
        })
        .await;
        assert!(!nothing.contains("datastar-patch-elements"), "{nothing}");
    }
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

    // What the core's hooks write (PLAN.md 7.6): a detection on the alert itself, a display value, and
    // an observable an `ignore` took out, which the tree no longer draws.
    let db = stack.test_db.db().pool();
    sqlx::query(
        "INSERT INTO analysis.detections (root_id, description)
         VALUES ($1, 'tag <phish> is configured to be alertable')",
    )
    .bind(root)
    .execute(db)
    .await
    .expect("a root detection");
    sqlx::query(
        "UPDATE analysis.observables SET display_value = 'the <proxy> host'
         WHERE root_id = $1 AND value = 'www.example.com'",
    )
    .bind(root)
    .execute(db)
    .await
    .expect("a display value");
    let hidden: String = sqlx::query_scalar(
        "UPDATE analysis.result_additions a SET ignored = true FROM analysis.observables o
         WHERE a.root_id = $1 AND o.id = a.observable_id AND o.type = 'ip'
           AND a.id = (SELECT min(b.id) FROM analysis.result_additions b
                       JOIN analysis.observables p ON p.id = b.observable_id
                       WHERE b.root_id = $1 AND p.type = 'ip')
         RETURNING o.value",
    )
    .bind(root)
    .fetch_one(db)
    .await
    .expect("an ignored addition");
    // with no result left holding it, the hook takes it out of the tree
    sqlx::query("UPDATE analysis.observables SET ignored = true WHERE root_id = $1 AND value = $2")
        .bind(root)
        .bind(&hidden)
        .execute(db)
        .await
        .expect("ignored");
    let page = stack
        .get(&path)
        .header("cookie", cookie(&alice_session))
        .send()
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(
        page.contains("detection: tag &#60;phish&#62; is configured to be alertable"),
        "{page}"
    );
    assert!(
        page.contains(r#"<span class="value">the &#60;proxy&#62; host (www.example.com)</span>"#)
    );
    assert!(
        !page.contains(&format!(r#"<span class="value">{hidden}</span>"#)),
        "the addition an ignore took out isn't drawn: {hidden}"
    );

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
            .and_then(|rest| rest.split(['\'', '&']).next())
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

/// The ownership-changed notice (the owner's decision of 2026-11-15, ace3's "Alert Ownership Changed!"):
/// its fragment names the new owner as text, and says nothing for an alert nobody owns or whose owner
/// the page knows.
#[test]
fn the_ownership_notice_names_the_new_owner_as_text() {
    let id = uuid::Uuid::from_u128(7);
    let at = chrono::DateTime::from_timestamp(1_793_000_000, 0).expect("a time");
    let mut alert = summary(id, "an alert");
    assert!(OwnerNoticeFragment::of(&alert, None).is_none(), "nobody's");
    alert.owner = Some(hostile_owner(9));
    alert.owned_at = Some(at);
    assert!(
        OwnerNoticeFragment::of(&alert, Some(uuid::Uuid::from_u128(9))).is_none(),
        "the owner the page was drawn with"
    );
    for known in [None, Some(uuid::Uuid::from_u128(8))] {
        let notice = OwnerNoticeFragment::of(&alert, known).expect("another owner");
        assert_eq!(notice.owner, HOSTILE);
        let html = notice.render().expect("renders");
        assert_eq!(
            html.trim_end(),
            format!(
                r#"<p id="owner-notice" class="notice owner-changed" role="alert"><strong>Alert Ownership Changed!</strong> <b>{HOSTILE_ESCAPED}</b> now owns this alert, since 2026-10-26 07:33:20 UTC. <a href="/alerts/{id}">Reload the page</a> to see it as it is now.</p>"#
            )
        );
        assert!(!html.contains("<script>") && inline_free(&html.replace(HOSTILE_ESCAPED, "")));
    }
    // an owner with no time is named without one
    alert.owned_at = None;
    let html = OwnerNoticeFragment::of(&alert, None)
        .expect("another owner")
        .render()
        .expect("renders");
    assert!(
        html.contains(&format!(
            "<b>{HOSTILE_ESCAPED}</b> now owns this alert. <a "
        )),
        "{html}"
    );
}

/// An open alert page learns that its alert changed hands, through the stream it already holds: a take,
/// an assignment and a disposition that takes the alert each send the notice, naming the owner as text,
/// once; the owner the page was drawn with and an alert that became nobody's send none; the tree isn't
/// sent again for it and the tree's version stays what a reconnect says; it opens no stream of its own;
/// and someone who can't read the alert never gets the owner: not at the door, and not on a stream
/// that was open when the permission went.
#[tokio::test]
async fn an_open_alert_page_is_told_when_its_owner_changes() {
    let stack = stack_with(LiveLimits {
        heartbeat: std::time::Duration::from_secs(60),
        ..LiveLimits::default()
    })
    .await;
    let db = stack.test_db.db();
    let alice = user(&stack, "alice").await;
    grant_alert_read(&stack, &alice).await;
    let jane = user(&stack, "jane").await;
    grant_alert_read(&stack, &jane).await;
    grant_to(&stack, &jane, "alert", "write").await;
    let bob = user(&stack, "bob").await;
    let id_of = |actor: &Actor| match actor {
        Actor::User { id, .. } => *id,
        _ => panic!("a user"),
    };
    let (alice_id, jane_id, bob_id) = (id_of(&alice), id_of(&jane), id_of(&bob));
    sqlx::query("UPDATE service.users SET display_name = $2 WHERE id = $1")
        .bind(jane_id.0)
        .bind(HOSTILE)
        .execute(db.pool())
        .await
        .expect("names her");
    let (root, _) = splunk_alert(&stack).await;
    let session = session_of(&stack, "alice").await;
    let page = |session: String| {
        let request = stack
            .get(&format!("/alerts/{root}"))
            .header("cookie", cookie(&session));
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
    // the page says in its stream's URL who owned the alert when it was drawn: nobody
    let drawn = page(session.clone()).await;
    let version = stack.page_version(root, &session).await;
    let live = format!("/alerts/{root}/live?v={version}&o=");
    assert!(
        drawn.contains(&format!("@get('{}')", live.replace('&', "&amp;")))
            && drawn.contains(r#"<p id="owner-notice" hidden></p>"#),
        "{drawn}"
    );
    let notices = |text: &str| text.matches(r#"id="owner-notice""#).count();
    let quiet = std::time::Duration::from_millis(700);
    let within = std::time::Duration::from_secs(10);

    let mut stream = stack.open_stream(&live, &session).await;
    assert_eq!(stream.status(), StatusCode::OK);
    let (nothing, _) = read_stream(&mut stream, quiet, |_| false).await;
    assert_eq!(nothing, "", "nobody owns it, as the page says");
    assert_eq!(stack.gui.open_streams(), 1);

    // jane takes it: the open page is told, with her name as text, and nothing else is sent
    let change = |actor: &Actor, owner: Option<UserId>| {
        let (service, actor) = (stack.service.clone(), actor.clone());
        async move {
            service
                .change_alert_owner(&actor, &[root], owner, &Default::default())
                .await
                .expect("changes the owner")
        }
    };
    change(&jane, Some(jane_id)).await;
    let (told, ended) = read_stream(&mut stream, within, |text| text.contains("\n\n")).await;
    assert!(!ended, "{told}");
    assert!(
        told.starts_with("event: datastar-patch-elements\n")
            && told.contains(&format!(
                r#"data: elements <p id="owner-notice" class="notice owner-changed" role="alert"><strong>Alert Ownership Changed!</strong> <b>{HOSTILE_ESCAPED}</b> now owns this alert, since "#
            ))
            && told.contains(&format!(r#"<a href="/alerts/{root}">Reload the page</a>"#)),
        "{told}"
    );
    assert!(
        !told.contains("<script>alert") && !told.contains("alert-tree") && !told.contains("\nid:"),
        "her name is text, the tree isn't sent again, and the tree's version stays the stream's id: {told}"
    );
    assert_eq!(notices(&told), 1);
    let (again, _) = read_stream(&mut stream, quiet, |_| false).await;
    assert_eq!(again, "", "told once");
    assert_eq!(
        stack.gui.open_streams(),
        1,
        "the notice came on the page's one stream"
    );
    assert_eq!(stack.service.watching(), (1, true));

    // a reload draws her as the owner, and a stream from that page is quiet
    let reloaded = page(session.clone()).await;
    let hers = format!("/alerts/{root}/live?v={version}&o={}", jane_id.0);
    assert!(
        reloaded.contains(&format!("@get('{}')", hers.replace('&', "&amp;"))),
        "{reloaded}"
    );
    let mut current = stack.open_stream(&hers, &session).await;
    let (nothing, _) = read_stream(&mut current, quiet, |_| false).await;
    assert_eq!(nothing, "", "the page was drawn with this owner");
    drop(current);
    // a stream that opens behind the page, as after a change between its read and the stream, is told
    // as it opens; an `o` that isn't a uuid is nobody
    for behind in [
        live.clone(),
        format!("/alerts/{root}/live?v={version}&o=%3Cscript%3E"),
    ] {
        let mut late = stack.open_stream(&behind, &session).await;
        let (caught_up, _) = read_stream(&mut late, within, |text| text.contains("\n\n")).await;
        assert!(
            notices(&caught_up) == 1 && caught_up.contains(HOSTILE_ESCAPED),
            "{behind}: {caught_up}"
        );
        assert!(!caught_up.contains("<script>"), "{caught_up}");
    }

    // unassigned: nothing to say, as in ace3, whose poll ignores an alert with no owner
    change(&jane, None).await;
    let (nothing, _) = read_stream(&mut stream, quiet, |_| false).await;
    assert_eq!(nothing, "", "nobody owns it");
    // assigned to alice herself by jane: she is told it's hers
    change(&jane, Some(alice_id)).await;
    let (told, _) = read_stream(&mut stream, within, |text| text.contains("\n\n")).await;
    assert!(
        notices(&told) == 1 && told.contains("<b>alice</b> now owns this alert"),
        "{told}"
    );
    // a disposition that takes the alert: jane confirms taking it from alice
    stack
        .service
        .disposition(&jane, root, "FALSE_POSITIVE", Some(alice_id))
        .await
        .expect("dispositions and takes it");
    let (told, _) = read_stream(&mut stream, within, |text| text.contains("\n\n")).await;
    assert!(
        notices(&told) == 1 && told.contains(HOSTILE_ESCAPED),
        "{told}"
    );

    // bob can't read alerts: the stream refuses him, with nothing about the owner
    let bobs = session_of(&stack, "bob").await;
    let refused = stack.open_stream(&live, &bobs).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let body = refused.text().await.expect("a body");
    assert!(
        !body.contains("owner-notice") && !body.contains("jane") && !body.contains("alice"),
        "{body}"
    );
    let anonymous = stack
        .get(&live)
        .header("datastar-request", "true")
        .send()
        .await
        .expect("answered");
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

    // alice loses alert:read while her page is open, and then the alert changes hands: her stream ends
    // without saying whose it is now
    stack
        .service
        .grant(
            &bootstrap(),
            &Holder::User(alice_id),
            &PermissionPattern::new("alert", "read").expect("a pattern"),
            Effect::Deny,
        )
        .await
        .expect("denies");
    change(&jane, Some(bob_id)).await;
    let (last, ended) = read_stream(&mut stream, within, |_| false).await;
    assert!(ended, "the stream ended: {last}");
    assert!(
        !last.contains("owner-notice") && !last.contains("bob"),
        "{last}"
    );
    drop(stream);
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
    // a section starts collapsed until the viewer pins it open
    assert!(
        page(&stack)
            .await
            .contains(r#"data-section-id="alert_details">"#)
    );

    let audits = stack.audit_count().await;
    let pin = stack
        .post(
            "/preferences/alert-section",
            &[
                ("section", "alert_details"),
                ("open", "true"),
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
            .contains(r#"data-section-id="alert_details" open>"#)
    );
    assert_eq!(
        stack.service.alert_sections(&alice).await.expect("reads"),
        [("alert_details".to_owned(), true)].into_iter().collect()
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
        "message_id_archived_2",
        "pdftotext_qr_code_pdf",
        "pdf_link_text_links",
        "exif_doc_docx",
        "qrcode_qr_code_pdf",
        "ocr_text_plain",
        "ssdeep_edited_little",
        "java_class_decompiler_class",
        "upx_cmd_upx",
        "autoit_hello_autoit",
        "de4dot_hello_dotnet",
        "ilspy_hello_dotnet",
        "dmg_analyzer_script_app",
        "cve_2021_30657_analyzer_script_app",
        "pcap_analyzer_network",
        "pcap_dns_network",
        "pcap_tls_http_tls",
        "pcap_http_http_tls",
        "pcap_files_many_files",
        "pcap_tls_decryption_http_tls",
        "tls_keylog_sslkeylog",
        "observable_detection_flagged",
        "observable_detection_not_flagged",
        "user_defined_tagging_tagged",
        "user_defined_tagging_untagged",
        "site_tagger_two_rows",
        "observable_modifier_recipient_domain",
        "javascript_deobfuscation_blob_redirect",
        "phishkit_url_scan",
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
                        "<h3>ace_rs_fixture_zip_attachment</h3>",
                        "<h3>ace_rs_fixture_zip_any</h3>",
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
                    "<pre class=\"wrap\">alert http $HOME_NET any -&#62; $EXTERNAL_NET any (msg:&#34;ACE_RS TEST fixture beacon&#34;;",
                ],
            ),
            "nrd_fqdn_ace4_fresh_com" => {
                // the age is counted to the day the fixture was written, so it is read from it
                let age = result.details["age_created_in_days"]
                    .as_str()
                    .expect("an age");
                contains_all(
                    &html,
                    &[
                        "<tr><th>is_nrd</th><td>true</td></tr>",
                        "<tr><th>datetime_created</th><td>2026-11-01 12:30:00+00:00</td></tr>",
                        &format!("<tr><th>age_created_in_days</th><td>{age}</td></tr>"),
                        "<tr><th>lookup_protocol</th><td>rdap</td></tr>",
                    ],
                );
            }
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
                &["<tr><th>hash</th><td>c09769d5f85a2ad6ec1e1cc8196b0c413fa45"],
            ),
            "pdftotext_qr_code_pdf" => contains_all(
                &html,
                &[
                    "<tr><th>output_path</th><td>5ae85ff95b5a1314ed5c8432f8320c91847d4bc6ee64f0c8269a6a7145759a81</td></tr>",
                ],
            ),
            "pdf_link_text_links" => contains_all(
                &html,
                &[
                    "<tr><th>link</th><td>page 1: https://example.com/invoice; text: View invoice online; line: View invoice online</td></tr>",
                    "<tr><th>link</th><td>page 1: https://example.com/contents; text: Pay now</td></tr>",
                    "<tr><th>link</th><td>page 1: https://example.com/nothing</td></tr>",
                ],
            ),
            // a tag's value is escaped, as anything from the file is
            "exif_doc_docx" => {
                contains_all(
                    &html,
                    &[
                        "<tr><th>tag</th><td>File:FileType = DOCX</td></tr>",
                        "<tr><th>tag</th><td>XMP:Creator = &#60;script&#62;Anderson&#60;/script&#62;</td></tr>",
                    ],
                );
                assert!(!html.contains("<script>Anderson"), "{html}");
            }
            "qrcode_qr_code_pdf" => contains_all(
                &html,
                &["<tr><th>extracted_text</th><td>https://sever.emmetcrcs.org/#</td></tr>"],
            ),
            "ocr_text_plain" => contains_all(&html, &["<tr><th>ocr</th><td>text found</td></tr>"]),
            "ssdeep_edited_little" => {
                contains_all(&html, &["<tr><th>match</th><td>base_text (97%)</td></tr>"])
            }
            "java_class_decompiler_class" => contains_all(
                &html,
                &[
                    "<tr><th>decompiled_file</th><td>VxUGJsAplRNavewkjKujp.class-0-decompiled.java</td></tr>",
                ],
            ),
            "upx_cmd_upx" => contains_all(
                &html,
                &["<tr><th>output_file</th><td>cmd-upx.exe.upx.exe</td></tr>"],
            ),
            "autoit_hello_autoit" => contains_all(
                &html,
                &[
                    "<tr><th>output_dir</th><td>hello_autoit.exe.autoit</td></tr>",
                    "<tr><th>script</th><td>script_1.au3</td></tr>",
                ],
            ),
            // what de4dot prints holds a file's name, which is escaped
            "de4dot_hello_dotnet" => {
                contains_all(
                    &html,
                    &[
                        "<tr><th>deobfuscated</th><td>yes</td></tr>",
                        "Detected Unknown Obfuscator (/tmp/ace-rs-task/&#60;b&#62;hello_dotnet.dll)",
                    ],
                );
                assert!(!html.contains("<b>hello"), "{html}");
            }
            "ilspy_hello_dotnet" => contains_all(&html, &["<tr><th>exit_code</th><td>0</td></tr>"]),
            // what dmg2img prints holds the file's name, which is escaped
            "dmg_analyzer_script_app" => {
                contains_all(
                    &html,
                    &[
                        "<tr><th>image_file</th><td>script_app.img</td></tr>",
                        "<tr><th>file</th><td>2026-11-10 18:28:44 .....          105         4096  Installer/Payload.app/Contents/MacOS/Payload</td></tr>",
                        "/tmp/ace-rs-task/&#60;b&#62;script_app.dmg --&#62; image.img",
                    ],
                );
                assert!(!html.contains("<b>script_app"), "{html}");
            }
            "cve_2021_30657_analyzer_script_app" => contains_all(
                &html,
                &["<tr><th>suspect_file</th><td>Payload (text/x-shellscript)</td></tr>"],
            ),
            "pcap_analyzer_network" => contains_all(
                &html,
                &[
                    "<p>network.pcap · pcap · 870 B · Ethernet, 1 interface · 5 packets · 2026-01-01 00:00:00 to 00:00:04 UTC (4.0 s)</p>",
                    "<h3>Hostnames</h3>",
                    "<tr><td>pcap-workstation</td><td>dhcp</td><td>02:00:00:aa:00:01</td></tr>",
                    "<tr><td>10.20.30.40</td><td>4</td><td>456</td></tr>",
                    "<tr><td>udp</td><td>10.20.30.40:53001</td><td>10.20.30.1:53</td><td>2</td><td>261 bytes</td><td>2</td><td>1</td></tr>",
                ],
            ),
            "pcap_dns_network" => contains_all(
                &html,
                &[
                    "<tr><td>www.pcap-dns.example</td><td>198.51.100.7, cdn.pcap-dns.example</td><td>1</td><td>1</td></tr>",
                ],
            ),
            "pcap_tls_http_tls" => contains_all(
                &html,
                &[
                    "<p>http_tls.pcapng · pcapng · 11.38 KB · Ethernet, 1 interface · 41 packets",
                    "written by Dumpcap (Wireshark) 4.4.19</p>",
                    "<td>127.0.0.1:18443</td><td>pcap-tls12.example</td><td>t12d2708h1_a2460661a67a_eed5f1524d5c</td>",
                    "pcap-tls.example (SAN: pcap-tls12.example, pcap-tls13.example) \u{2014} self-signed",
                ],
            ),
            "pcap_http_http_tls" => contains_all(
                &html,
                &[
                    "<tr><td>GET</td><td>http://pcap-http.example:18080/payload.txt</td><td>200</td><td>text/plain</td><td>pcap-fixture-agent/1.0</td></tr>",
                ],
            ),
            "pcap_files_many_files" => contains_all(
                &html,
                &[
                    "<h3>Carved Files</h3>",
                    "<td>http</td><td>copy.txt</td><td>63</td>",
                    "<td>imf</td><td>carved over smtp.eml</td>",
                ],
            ),
            "pcap_tls_decryption_http_tls" => contains_all(
                &html,
                &[
                    "<h3>Key Sources</h3>",
                    "<td>sslkeylog.txt</td><td>76f3b3e668343641d138e1121f7be54778c87bf38fe98f27723be8be971ff8e3</td>",
                    "<td>https://pcap-tls13.example:18444/secret13.txt</td>",
                ],
            ),
            "tls_keylog_sslkeylog" => {
                contains_all(&html, &["<tr><td>CLIENT_RANDOM</td><td>1</td></tr>"])
            }
            "observable_detection_flagged" => {
                contains_all(&html, &["<tr><th>for_detection</th><td>yes</td></tr>"])
            }
            "observable_detection_not_flagged" => {
                contains_all(&html, &["<tr><th>for_detection</th><td>no</td></tr>"])
            }
            "user_defined_tagging_tagged" => contains_all(
                &html,
                &[
                    "<tr><th>tag</th><td>phish_infra</td></tr>",
                    "<tr><th>tag</th><td>watchlist</td></tr>",
                ],
            ),
            "user_defined_tagging_untagged" => {
                contains_all(&html, &["<tr><th>tags_added</th><td>none</td></tr>"])
            }
            "site_tagger_two_rows" => contains_all(
                &html,
                &[
                    "<tr><th>tag</th><td>first</td></tr>",
                    "<tr><th>tag</th><td>third</td></tr>",
                ],
            ),
            // ace3's tree of the e2e email, under tests/e2e/site/overlay.yaml's rules
            "observable_modifier_recipient_domain" => contains_all(
                &html,
                &[
                    "<tr><th>rule</th><td>e2e recipient domain (2f0c8a9e-6b0d-4c55-9a51-0e1d2c3b4a01): \
                     add_detection_points: the observable modifier marked a recipient&#39;s domain; \
                     add_tags: modifier_recipient_domain; set_display_type: Recipient Domain; \
                     set_display_value: recipient</td></tr>",
                ],
            ),
            "javascript_deobfuscation_blob_redirect" => contains_all(
                &html,
                &[
                    "<tr><th>event_count</th><td>6</td></tr>",
                    "<tr><th>extracted_file</th><td>blob_redirect.js.blob_0.html</td></tr>",
                    "<tr><th>webcrack_status</th><td>applied</td></tr>",
                ],
            ),
            // what the kit's page served is escaped, as anything from a scan is
            "phishkit_url_scan" => contains_all(
                &html,
                &[
                    "<tr><th>scan_result</th><td>successfully scanned url(https://kit.evil.example/start)</td></tr>",
                    "downloads/invoice.zip</td></tr>",
                    "&#34;final_route&#34;: &#34;none&#34;",
                ],
            ),
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

    // a capture's URLs, user agents and file names are the sender's (7.5 batch 13)
    let http = view_fixture("pcap_http_http_tls");
    let mut details = http.details.clone();
    details["rows"][0]["user_agent"] = serde_json::json!(hostile);
    details["capture"]["file_name"] = serde_json::json!(hostile);
    let html = views
        .draw("pcap_http_analysis", 1, &details)
        .html
        .as_str()
        .to_owned();
    assert!(!html.contains("<script>"), "{html}");
    assert!(
        html.contains("<td>&#60;script&#62;alert(1)&#60;/script&#62;"),
        "{html}"
    );
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
        pivot_links: Vec::new(),
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
    // back on the whole tree, where the observable is drawn whether or not it carries a detection
    assert_eq!(
        location(&added),
        format!("/alerts/{root}?tree=full#o{}", fqdn.0)
    );
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

/// A site's directive, such as `locate_file` (PLAN.md decision 31).
const LOCATE_FILE: ace_service::Directive = ace_service::Directive::new(
    "locate_file",
    "locate the on-disk host(s) and path(s) of this file by its SHA256",
);

/// Add Directive (PLAN.md decision 31): the menu's link on every observable, its form of the binary's
/// directives (ace3's and the site's) under `alert:read`, and its post under `observable:write`, which adds
/// the ticked ones, audits it, analyzes the alert again and goes back to the observable in the tree. A
/// directive the binary doesn't list is refused.
#[tokio::test]
async fn add_directive_adds_the_ticked_directives() {
    let stack = stack_from(|service| {
        Gui::new(
            service.with_directives(
                ace_sdk::directives::directive_list(&[LOCATE_FILE]).expect("a valid list"),
            ),
            Transport::Plain,
        )
    })
    .await;
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
    let path = format!("/alerts/{root}/observables/{}/directives", fqdn.0);
    assert!(
        alert.contains(&format!(r#"<a href="{path}">Add Directive</a>"#)),
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
            r#"<input type="checkbox" name="directive" value="crawl"> <code>crawl</code> <span class="muted">crawl the URL</span>"#,
            r#"<input type="checkbox" name="directive" value="locate_file"> <code>locate_file</code>"#,
            r#"<button type="submit">Add Directive</button>"#,
        ],
    );
    // the five built in and the site's one, and none that only ACE adds
    assert_eq!(form.matches(r#"name="directive""#).count(), 6);
    assert!(!form.contains("exclude_all"));

    // alice can read the alert but not change its observables
    let audits = stack.audit_count().await;
    let refused = stack
        .post(&path, &[("directive", "crawl")])
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
        .post(
            &path,
            &[("directive", "locate_file"), ("directive", "crawl")],
        )
        .header("cookie", cookie(&carol_session))
        .send()
        .await
        .expect("answered");
    assert_eq!(added.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&added),
        format!("/alerts/{root}?tree=full#o{}", fqdn.0)
    );
    assert_eq!(stack.audit_count().await, audits + 1);
    let directives: Vec<String> =
        sqlx::query_scalar("SELECT directives FROM analysis.observables WHERE id = $1")
            .bind(fqdn.0)
            .fetch_one(stack.test_db.db().pool())
            .await
            .expect("reads");
    assert_eq!(directives, ["locate_file", "crawl"]);
    // the form shows them set, and they can't be ticked off
    let form = stack
        .get(&path)
        .header("cookie", cookie(&carol_session))
        .send()
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(
        form.contains(r#"value="locate_file" checked disabled> <code>locate_file</code>"#),
        "{form}"
    );
    assert!(form.contains("(already set)"));

    // a directive the binary doesn't list, none, no such observable, another site, no alert:read and no
    // session
    for bad in [
        vec![("directive", "exclude_all")],
        vec![("directive", "<b>x</b>")],
        vec![("other", "crawl")],
        vec![],
    ] {
        let response = stack
            .post(&path, &bad)
            .header("cookie", cookie(&carol_session))
            .send()
            .await
            .expect("answered");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{bad:?}");
        let page = response.text().await.expect("a page");
        assert!(!page.contains("<b>x</b>"), "{page}");
    }
    for missing in [
        format!("/alerts/{root}/observables/999999/directives"),
        format!("/alerts/{root}/observables/x/directives"),
        format!(
            "/alerts/{}/observables/{}/directives",
            uuid::Uuid::nil(),
            fqdn.0
        ),
    ] {
        let response = stack
            .post(&missing, &[("directive", "crawl")])
            .header("cookie", cookie(&carol_session))
            .send()
            .await
            .expect("answered");
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{missing}");
    }
    let cross_site = stack
        .post(&path, &[("directive", "crawl")])
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
        .post(&path, &[("directive", "crawl")])
        .send()
        .await
        .expect("answered");
    assert_eq!(anonymous.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&anonymous), "/login");
    assert_eq!(stack.audit_count().await, audits + 1);
}

/// The form drawn alone: every directive the observable has that the list doesn't offer is named, and a
/// form with nothing left to tick has no button.
#[test]
fn the_directive_form_names_what_it_does_not_offer() {
    let (tree, _) = fixture_tree();
    let mut observable = tree.observables[0].clone();
    observable.directives = vec!["crawl".to_owned(), "original_email".to_owned()];
    let only = ace_service::DirectiveList::builtin();
    let (choices, others) = ace_gui::actions::directive_choices(&only, &observable);
    assert_eq!(others, ["original_email"]);
    assert_eq!(choices.iter().filter(|c| c.set).count(), 1);
    let page = |choices: Vec<ace_gui::actions::DirectiveChoice>| {
        ace_gui::actions::DirectivePage {
            layout: Layout::new("n0nce", Theme::Dark, Some("alice".to_owned()), "/"),
            alert_id: tree.alert.summary.id,
            alert_title: "<title>".to_owned(),
            observable_id: observable.id,
            label: observable.display_label(),
            value: "<script>alert(1)</script>".to_owned(),
            choices,
            others: others.clone(),
            refused: vec!["<b>refused</b>".to_owned()],
        }
        .render()
        .expect("renders")
    };
    let html = page(choices.clone());
    assert!(inline_free(&html));
    assert!(
        html.contains("so it isn't ticked: <code>&#60;b&#62;refused&#60;/b&#62;</code>"),
        "{html}"
    );
    assert!(
        html.contains("Also set: <code>original_email</code>"),
        "{html}"
    );
    assert!(!html.contains("<script>alert(1)</script>"));
    assert!(html.contains(r#"<button type="submit">Add Directive</button>"#));
    let all_set = choices
        .into_iter()
        .map(|choice| ace_gui::actions::DirectiveChoice {
            set: true,
            ..choice
        })
        .collect();
    let html = page(all_set);
    assert!(!html.contains(">Add Directive</button>"));
    assert!(html.contains("The observable has every directive this list offers."));
}

/// PLAN.md decision 60: the Add Directive form's link ticks the boxes it names in advance, and only
/// that: following it adds nothing, a name the list doesn't offer ticks nothing and is named back
/// escaped, one the observable has stays ticked and disabled, and the analyst's post adds what's ticked
/// with its permission check and audit row, as any other.
#[tokio::test]
async fn a_link_ticks_the_add_directive_form_in_advance() {
    let stack = stack_from(|service| {
        Gui::new(
            service.with_directives(
                ace_sdk::directives::directive_list(&[LOCATE_FILE]).expect("a valid list"),
            ),
            Transport::Plain,
        )
    })
    .await;
    let carol = user(&stack, "carol").await;
    grant_alert_read(&stack, &carol).await;
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
    let session = session_of(&stack, "carol").await;
    let (root, fqdn) = splunk_alert(&stack).await;
    let target = ace_gui::actions::ActionTarget {
        alert: root,
        observable: fqdn.0,
        kind: "fqdn",
        value: "www.example.com",
        has_file: false,
    };
    let path = format!("/alerts/{root}/observables/{}/directives", fqdn.0);
    assert_eq!(ace_gui::actions::add_directive_href(&target, &[]), path);
    let form = |href: String| {
        let request = stack.get(&href).header("cookie", cookie(&session));
        async move {
            let response = request.send().await.expect("answered");
            assert_eq!(response.status(), StatusCode::OK, "{href}");
            let page = response.text().await.expect("a page");
            assert!(inline_free(&page));
            page
        }
    };
    let directives = || async {
        sqlx::query_scalar::<_, Vec<String>>(
            "SELECT directives FROM analysis.observables WHERE id = $1",
        )
        .bind(fqdn.0)
        .fetch_one(stack.test_db.db().pool())
        .await
        .expect("reads")
    };
    let audits = stack.audit_count().await;

    // a box ticked by the link, the others not, and nothing added by following it
    let href = ace_gui::actions::add_directive_href(&target, &["locate_file"]);
    assert_eq!(href, format!("{path}?directive=locate_file"));
    let page = form(href).await;
    contains_all(
        &page,
        &[
            &format!(r#"<form method="post" action="{path}" class="section">"#),
            r#"<input type="checkbox" name="directive" value="locate_file" checked> <code>locate_file</code>"#,
            r#"<input type="checkbox" name="directive" value="crawl"> <code>crawl</code>"#,
            r#"<button type="submit">Add Directive</button>"#,
        ],
    );
    assert_eq!(page.matches(" checked").count(), 1, "{page}");
    assert!(!page.contains(r#"class="warning""#), "{page}");
    // two at once
    let page = form(ace_gui::actions::add_directive_href(
        &target,
        &["crawl", "locate_file"],
    ))
    .await;
    assert_eq!(page.matches(" checked>").count(), 2, "{page}");
    assert_eq!(stack.audit_count().await, audits);
    assert!(directives().await.is_empty());

    // a name the list doesn't offer, one only ACE adds among them, ticks nothing and is named back
    let page = form(format!(
        "{path}?directive=no_such_directive&directive=exclude_all&directive=no_such_directive"
    ))
    .await;
    assert!(!page.contains(" checked"), "{page}");
    assert_eq!(page.matches(r#"name="directive""#).count(), 6);
    assert!(
        page.contains(
            "so it isn't ticked: <code>no_such_directive</code>, <code>exclude_all</code></p>"
        ),
        "{page}"
    );
    // a hostile one is escaped, and cut short
    let hostile = format!("<script>alert(1)</script>\"><img src=x>{}", "a".repeat(200));
    let page = form(format!(
        "{path}?directive={}",
        ace_gui::actions::encode(&hostile)
    ))
    .await;
    assert!(!page.contains("<script>alert(1)"), "{page}");
    assert!(!page.contains("<img src=x>"), "{page}");
    assert!(
        page.contains(
            "<code>&#60;script&#62;alert(1)&#60;/script&#62;&#34;&#62;&#60;img src=x&#62;aaa"
        ),
        "{page}"
    );
    assert!(!page.contains(&"a".repeat(64)), "cut to 64 characters");
    assert!(!page.contains(" checked"), "{page}");

    // the analyst's post of the ticked form adds it, under observable:write, with its audit row
    let added = stack
        .post(&path, &[("directive", "locate_file")])
        .header("cookie", cookie(&session))
        .send()
        .await
        .expect("answered");
    assert_eq!(added.status(), StatusCode::SEE_OTHER);
    assert_eq!(stack.audit_count().await, audits + 1);
    assert_eq!(directives().await, ["locate_file"]);
    let sources: Vec<String> = sqlx::query_scalar(
        "SELECT source::text FROM analysis.directive_sources WHERE observable_id = $1 AND directive = 'locate_file'",
    )
    .bind(fqdn.0)
    .fetch_all(stack.test_db.db().pool())
    .await
    .expect("reads");
    assert_eq!(sources, ["analyst"]);

    // one the observable has already is ticked and disabled, as without the link
    let page = form(ace_gui::actions::add_directive_href(
        &target,
        &["locate_file", "crawl"],
    ))
    .await;
    contains_all(
        &page,
        &[
            r#"value="locate_file" checked disabled> <code>locate_file</code>"#,
            r#"value="crawl" checked> <code>crawl</code>"#,
        ],
    );
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
        &ace_service::Dispositions::ace3(),
        None,
    );
    let ids: Vec<&str> = view.list.headers.iter().map(|header| header.id).collect();
    assert_eq!(
        ids,
        ["disposition", "description", "date", "queue", "owner"],
        "the viewer's order, status hidden, and the queue and the owner, which the stored order predates, last"
    );
    // the Queue column (PLAN.md 7.13): its header sorts by it, ascending first, and a row's queue is a
    // link that narrows the list to it, keeping the other filters, as a click on a disposition does
    let queue = view
        .list
        .headers
        .iter()
        .find(|h| h.id == "queue")
        .expect("queue");
    assert_eq!((queue.label.as_str(), queue.arrow), ("Queue", ""));
    let sorts = queue.href.as_deref().expect("it sorts");
    assert!(
        sorts.contains("sort=queue") && sorts.contains("dir=asc") && !sorts.contains("after="),
        "{sorts}"
    );
    let cell = view.list.rows[0]
        .cells
        .iter()
        .find(|cell| cell.id == "queue")
        .expect("a queue cell");
    assert_eq!(cell.text, "<q>ueue & \"co\"");
    let narrows = cell.href.as_deref().expect("a link");
    assert!(
        narrows.contains("f=description") && narrows.contains("f=%21disposition"),
        "{narrows}"
    );
    let decoded = ListQuery::parse(
        &serde_urlencoded::from_str::<Vec<(String, String)>>(narrows.trim_start_matches("/?"))
            .expect("pairs"),
    )
    .expect("a list")
    .query
    .filters;
    assert_eq!(
        decoded.last(),
        Some(&FilterEntry::text("Queue", false, &["<q>ueue & \"co\""])),
        "the link holds the queue itself"
    );
    assert_eq!(view.chips.len(), 2);
    assert!(view.chips[1].inverted);
    let html = ListPage::new(
        Layout::new("n0nce", Theme::Light, Some("alice".to_owned()), "/"),
        view.clone(),
    )
    .render()
    .expect("renders");
    assert!(!html.contains("<script>alert"), "{html}");
    assert!(!html.contains("<img"), "{html}");
    assert!(!html.contains("<warning>"));
    assert!(!html.contains("<q>"), "{html}");
    assert!(
        html.contains(">&#60;q&#62;ueue &#38; &#34;co&#34;</a></td>"),
        "{html}"
    );
    // the hostile title's handler is text: every_template_escapes_html checks the templates themselves
    assert!(!html.contains("style="), "{html}");
    assert_eq!(row_ids(&html), [one.to_string(), two.to_string()]);
    // the disposition links narrow the list to it, the title to the alert
    assert!(html.contains(&format!(r#"<a href="/alerts/{one}">"#)));
    assert!(
        html.contains(r#"class="badge disposition-light">OPEN</a>"#)
            && html.contains(r#"class="badge disposition-success">FALSE_POSITIVE</a>"#),
        "{html}"
    );
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
        list: alert_list(
            &page,
            &query,
            &columns,
            chrono_tz::Tz::UTC,
            &ace_service::Dispositions::ace3(),
        ),
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

    // range selection (ace3 5fb36276): the page loads its one script after Datastar, from this origin
    // with the nonce and deferred, and nothing inline. The script finds a row's box by what the bulk
    // form posts, and sends the page one event, whose handler is fixed text over the ids it names.
    let scripts = script_tags(&html);
    assert_eq!(scripts.len(), 2, "Datastar and the list's: {scripts:?}");
    let select = asset_named(
        scripts[1]
            .split("src=\"/static/")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("a source"),
    )
    .expect("an embedded asset");
    assert!(select.name.starts_with("select."), "{}", select.name);
    assert_eq!(
        scripts[1],
        format!(r#"<script nonce="n0nce" src="{}" defer>"#, select.url())
    );
    assert!(
        html.contains(
            r#"data-on:ace-select="$_sel = $_sel.filter(id => !evt.detail.on.includes(id) && !evt.detail.off.includes(id)).concat(evt.detail.on)""#
        ),
        "{html}"
    );
    for id in [one, two] {
        assert!(
            html.contains(&format!(
                r#"<input type="checkbox" form="bulk" name="alert" value="{id}" aria-label="Tick this alert""#
            )),
            "{html}"
        );
    }
    let script = std::str::from_utf8(select.bytes).expect("text");
    contains_all(
        script,
        &[
            // the boxes it reads are the rows' own, and the event is the one the page handles
            r##"var BOXES = '#alert-list input[type="checkbox"][name="alert"]';"##,
            r#"document.getElementById("alert-page")"#,
            r#"new CustomEvent("ace-select", { detail: { on: on, off: off } })"#,
        ],
    );
    // it writes nothing into the page and evaluates no text, so no alert's text can become markup or code
    for never in [
        "innerHTML",
        "outerHTML",
        "insertAdjacent",
        "document.write",
        "eval(",
        "Function(",
        "setAttribute",
        "fetch(",
        "XMLHttpRequest",
        "http://",
        "https://",
    ] {
        assert!(!script.contains(never), "select.js has {never}");
    }
    // a refresh brings rows, never a script or the handler: both stay on the page around it
    assert!(script_tags(&fragment).is_empty(), "{fragment}");
    assert!(!fragment.contains("ace-select"), "{fragment}");
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
    let (status, page) = get("/?f=reviewed:CORRECT".to_owned()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("a disposition has no review yet"), "{page}");
    assert_eq!(row_ids(&page).len(), 5);
    let (status, page) = get("/?f=tag:a,,b".to_owned()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("That filter couldn"), "{page}");
    assert_eq!(row_ids(&page).len(), 5);
    let (status, _) = get("/?sort=status".to_owned()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // range selection through the server: the page's policy is as strict as every page's, its script
    // is served from the binary under its hash, and a signed-out visitor is sent to the login
    let response = stack
        .get("/?f=disposition:OPEN")
        .header("cookie", cookie(&session))
        .send()
        .await
        .expect("answered");
    assert_eq!(response.status(), StatusCode::OK);
    let policy = response.headers()["content-security-policy"]
        .to_str()
        .expect("text")
        .to_owned();
    let page = response.text().await.expect("a page");
    let nonce = page
        .split("data-nonce=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("the nonce");
    assert_eq!(policy, ace_gui::content_security_policy(nonce));
    assert!(!policy.contains("unsafe"), "{policy}");
    assert!(inline_free(&page), "{page}");
    let scripts = script_tags(&page);
    assert_eq!(scripts.len(), 2, "{scripts:?}");
    let url = scripts[1]
        .split("src=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("a source");
    assert_eq!(
        scripts[1],
        format!(r#"<script nonce="{nonce}" src="{url}" defer>"#)
    );
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
    assert_eq!(
        &bytes[..],
        include_bytes!("../static/select.js"),
        "the list's script is the repository's file"
    );
    let hash = hex::encode(Sha256::digest(&bytes));
    assert_eq!(url, format!("/static/select.{}.js", &hash[..16]));
    let stale = stack
        .get("/static/select.js")
        .send()
        .await
        .expect("answered");
    assert_eq!(stale.status(), StatusCode::NOT_FOUND);
    let anonymous = stack.get("/").send().await.expect("answered");
    assert_eq!(anonymous.status(), StatusCode::SEE_OTHER);
    // no other page loads it
    let (_, saved) = get("/filters/saved".to_owned()).await;
    assert_eq!(script_tags(&saved).len(), 1, "{saved}");

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
    // the site's dispositions: one it doesn't have, and one only ACE sets, are refused whole
    for bad in ["MALICIOUS", "SIMULATED", "SITE_SWEEP"] {
        let response = post(vec![
            ("disposition", bad.to_owned()),
            ("alert", one.to_string()),
        ])
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{bad}");
    }
    assert_eq!(stack.audit_count().await, audit + 2);
    // one with show_save_to_event offers Save to Event for the alerts dispositioned, to a viewer with
    // event:write only; and an alert whose disposition only ACE sets is refused on its own
    let with = |disposition: &str, ids: &[uuid::Uuid]| {
        let mut form = vec![
            ("disposition", disposition.to_owned()),
            ("next", "/".to_owned()),
        ];
        form.extend(ids.iter().map(|id| ("alert", id.to_string())));
        form
    };
    let page = post(with("SITE_CHECKED", &[one]))
        .await
        .text()
        .await
        .expect("a page");
    assert!(page.contains("1 alert dispositioned"), "{page}");
    assert!(!page.contains("Save to Event"), "no event:write: {page}");
    stack
        .service
        .grant(
            &bootstrap(),
            &Holder::User(*id),
            &PermissionPattern::new("event", "write").expect("a pattern"),
            Effect::Allow,
        )
        .await
        .expect("grants");
    sqlx::query("UPDATE analysis.roots SET disposition = 'SITE_SWEEP' WHERE id = $1")
        .bind(two)
        .execute(stack.test_db.db().pool())
        .await
        .expect("as ACE would");
    let answer = post(with("SITE_CHECKED", &[one, two])).await;
    assert_eq!(answer.status(), StatusCode::OK);
    let page = answer.text().await.expect("a page");
    assert!(page.contains("1 alert dispositioned, 1 not"), "{page}");
    assert!(page.contains("set only by ACE"), "{page}");
    assert!(
        page.contains(r#"<form method="get" action="/events/add" class="save-to-event">"#),
        "{page}"
    );
    assert!(
        page.contains(&format!(
            r#"<input type="hidden" name="alert" value="{one}">"#
        )),
        "{page}"
    );
    assert!(
        !page.contains(&format!(r#"name="alert" value="{two}""#)),
        "{page}"
    );
    let page = post(with("FALSE_POSITIVE", &[one]))
        .await
        .text()
        .await
        .expect("a page");
    assert!(
        !page.contains("Save to Event"),
        "FALSE_POSITIVE doesn't offer it: {page}"
    );
    // the list's menu offers what an analyst may choose, the filter's suggestions every disposition
    let list = stack
        .http
        .get(format!("{}/", stack.url))
        .header("cookie", cookie(&session))
        .send()
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    let menu = list
        .split(r#"<select id="bulk-disposition" name="disposition">"#)
        .nth(1)
        .and_then(|rest| rest.split("</select>").next())
        .expect("the bulk menu");
    assert!(
        menu.contains(r#"<option value="SITE_CHECKED">SITE_CHECKED</option>"#),
        "{menu}"
    );
    assert!(
        menu.contains(r#"<option value="DAMAGE">DAMAGE</option>"#),
        "{menu}"
    );
    assert!(
        !menu.contains("SIMULATED") && !menu.contains("SITE_SWEEP"),
        "{menu}"
    );
    assert!(
        menu.find("OPEN") < menu.find("FALSE_POSITIVE")
            && menu.find("DAMAGE") < menu.find("SITE_CHECKED"),
        "ace3's order, the site's own after: {menu}"
    );
    let suggested = list
        .split(r#"<datalist id="filter-values">"#)
        .nth(1)
        .and_then(|rest| rest.split("</datalist>").next())
        .expect("the suggestions");
    assert!(
        suggested.contains(r#"<option value="SIMULATED">"#),
        "{suggested}"
    );
    assert!(
        suggested.contains(r#"<option value="SITE_SWEEP">"#),
        "{suggested}"
    );
    // a badge in the site's css: DAMAGE is warning here
    sqlx::query("UPDATE analysis.roots SET disposition = 'DAMAGE' WHERE id = $1")
        .bind(one)
        .execute(stack.test_db.db().pool())
        .await
        .expect("dispositions");
    let list = stack
        .http
        .get(format!("{}/?f=disposition:DAMAGE", stack.url))
        .header("cookie", cookie(&session))
        .send()
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(
        list.contains(r#"class="badge disposition-warning">DAMAGE</a>"#),
        "{list}"
    );
    // css is any class token, as ace3's is any text: the site's own class, which the stylesheet has no
    // rule for, so it shows as the plain badge
    sqlx::query("UPDATE analysis.roots SET disposition = 'SITE_CHECKED' WHERE id = $1")
        .bind(one)
        .execute(stack.test_db.db().pool())
        .await
        .expect("dispositions");
    let list = stack
        .http
        .get(format!("{}/?f=disposition:SITE_CHECKED", stack.url))
        .header("cookie", cookie(&session))
        .send()
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(
        list.contains(r#"class="badge disposition-site-checked_1">SITE_CHECKED</a>"#),
        "{list}"
    );
    let audit = stack.audit_count().await;
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
    assert_eq!(stack.audit_count().await, audit);
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

    // the columns: move the disposition first, past the owner (7.17), the queue, the alert and the
    // date, hide the date, and reset
    for (column, action) in [
        ("disposition", "up"),
        ("disposition", "up"),
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
        [
            "disposition",
            "date",
            "description",
            "queue",
            "owner",
            "status"
        ]
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
    assert_eq!(
        headers,
        ["disposition", "description", "queue", "owner", "status"]
    );
    for bad in [
        // ace3's remediation column isn't here
        vec![("column", "remediation"), ("action", "up")],
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

/// 7.13's queue pieces through the server, where ace3 has them: the list's Queue column and order, the
/// alert page's queue, the `Last 24h` and `Last 7d` quick filters a person new to the list gets when the
/// page is drawn (never from its refresh), and the `$USER_QUEUE` tip on the saved filters page.
#[tokio::test]
async fn the_queue_is_on_the_list_and_the_alert_and_new_people_get_ace3_s_quick_filters() {
    let stack = stack().await;
    let alice = user(&stack, "alice").await;
    grant_alert_read(&stack, &alice).await;
    let session = session_of(&stack, "alice").await;
    let db = stack.test_db.db();
    let hostile = "<q>ueue & \"co\"";
    let mut made = Vec::new();
    for (title, queue, age) in [
        ("in triage, old", "triage", "30 days"),
        ("in triage, new", "triage", "1 hour"),
        ("in default", "default", "2 hours"),
        ("in a hostile queue", hostile, "3 days"),
    ] {
        let id = list_alert(&stack, title, "2026-01-01T10:00:00Z", None).await;
        sqlx::query(
            "UPDATE analysis.roots SET queue = $2, alerted_at = now() - $3::interval WHERE id = $1",
        )
        .bind(id)
        .bind(queue)
        .bind(age)
        .execute(db.pool())
        .await
        .expect("sets its queue");
        made.push(id);
    }
    let (triage_old, triage_new, default, odd) = (made[0], made[1], made[2], made[3]);
    sqlx::query("UPDATE service.users SET queue = 'triage' WHERE username = 'alice'")
        .execute(db.pool())
        .await
        .expect("alice works triage");
    let get = |path: String| {
        let request = stack.get(&path).header("cookie", cookie(&session));
        async move {
            let response = request.send().await.expect("answered");
            let status = response.status();
            (status, response.text().await.expect("a page"))
        }
    };
    let ids = |list: &[uuid::Uuid]| list.iter().map(|id| id.to_string()).collect::<Vec<_>>();
    let saved = || async {
        stack
            .service
            .saved_filters(&alice, FilterScreen::Alerts)
            .await
            .expect("lists")
    };

    // the refresh writes nothing: a list that only refreshes seeds no filter
    let audits = stack.audit_count().await;
    let request = stack
        .get("/alerts/list")
        .header("cookie", cookie(&session))
        .header("datastar-request", "true");
    assert_eq!(
        request.send().await.expect("answered").status(),
        StatusCode::OK
    );
    assert!(saved().await.is_empty());
    assert_eq!(stack.audit_count().await, audits);

    // the page, drawn for someone new: the two quick filters, with one audit row, once
    let (status, page) = get("/".to_owned()).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(stack.audit_count().await, audits + 1);
    let filters = saved().await;
    assert_eq!(
        filters
            .iter()
            .map(|filter| (filter.name.as_str(), filter.quick_filter_order))
            .collect::<Vec<_>>(),
        [("Last 24h", Some(0)), ("Last 7d", Some(1))]
    );
    // each is a badge on the page that drew them, a link to the list in the viewer's queue and window
    let badge = |name: &str| {
        let link = page
            .split(&format!(">{name}</a>"))
            .next()
            .and_then(|before| before.rsplit("href=\"").next())
            .and_then(|rest| rest.split('"').next())
            .unwrap_or_else(|| panic!("no {name} badge in {page}"));
        link.replace("&#38;", "&")
    };
    let (day, week) = (badge("Last 24h"), badge("Last 7d"));
    assert!(day.contains("USER_QUEUE") && day.contains("-24h"), "{day}");
    let (_, listed) = get(day).await;
    assert_eq!(row_ids(&listed), ids(&[triage_new]));
    let (_, listed) = get(week).await;
    assert_eq!(
        row_ids(&listed),
        ids(&[triage_new]),
        "the old one is past it"
    );
    get("/".to_owned()).await;
    assert_eq!(stack.audit_count().await, audits + 1, "seeded once");
    assert_eq!(saved().await.len(), 2);

    // the Queue column: after the alert, before the disposition, each queue a link that narrows to it
    let headers: Vec<&str> = page
        .split("<th data-col-id=\"")
        .skip(1)
        .filter_map(|rest| rest.split('"').next())
        .collect();
    assert_eq!(
        headers,
        [
            "date",
            "description",
            "queue",
            "owner",
            "disposition",
            "status"
        ]
    );
    assert!(!page.contains("<q>"), "{page}");
    assert!(
        page.contains(">&#60;q&#62;ueue &#38; &#34;co&#34;</a></td>"),
        "{page}"
    );
    let (_, narrowed) = get("/?f=queue:triage".to_owned()).await;
    assert_eq!(row_ids(&narrowed), ids(&[triage_new, triage_old]));
    // and its order, both ways, by the queue's bytes then the id: "<q>…" sorts before "default"
    let (first, second) = if triage_old < triage_new {
        (triage_old, triage_new)
    } else {
        (triage_new, triage_old)
    };
    let (status, sorted) = get("/?sort=queue&dir=asc".to_owned()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(row_ids(&sorted), ids(&[odd, default, first, second]));
    assert!(sorted.contains("Queue↑"), "{sorted}");
    let (_, sorted) = get("/?sort=queue".to_owned()).await;
    assert_eq!(row_ids(&sorted), ids(&[second, first, default, odd]));
    // paged one at a time, the cursor carries the queue, hostile text and all
    let mut seen = Vec::new();
    let mut path = "/?sort=queue&dir=asc&size=1".to_owned();
    loop {
        let (status, page) = get(path.clone()).await;
        assert_eq!(status, StatusCode::OK, "{path}: {page}");
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
        assert!(seen.len() <= 4, "paging ends");
    }
    assert_eq!(seen, ids(&[odd, default, first, second]));

    // the alert's page has its queue among its details, as text
    let (status, alert) = get(format!("/alerts/{odd}")).await;
    assert_eq!(status, StatusCode::OK, "{alert}");
    assert!(
        alert.contains("<th>Queue</th><td>&#60;q&#62;ueue &#38; &#34;co&#34;</td>"),
        "{alert}"
    );
    let (_, alert) = get(format!("/alerts/{triage_new}")).await;
    assert!(alert.contains("<th>Queue</th><td>triage</td>"), "{alert}");

    // the saved filters page has ace3's tip under its table
    let (status, manage) = get("/filters/saved".to_owned()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        manage.contains("Tip: use <code>$USER_QUEUE</code> as a Queue value"),
        "{manage}"
    );
    assert!(manage.contains(">Last 24h</a>") && manage.contains(">Last 7d</a>"));

    // deleted, they stay deleted
    for filter in &filters {
        let deleted = stack
            .post(
                &format!("/filters/saved/{}/delete", filter.id),
                &[("next", "/")],
            )
            .header("cookie", cookie(&session))
            .send()
            .await
            .expect("answered");
        assert_eq!(deleted.status(), StatusCode::SEE_OTHER);
    }
    let (_, page) = get("/".to_owned()).await;
    assert!(!page.contains(">Last 24h</a>"), "{page}");
    assert!(saved().await.is_empty());

    // someone without alert:read is refused the page and is given nothing
    user(&stack, "bob").await;
    let bobs = session_of(&stack, "bob").await;
    let refused = stack
        .get("/")
        .header("cookie", cookie(&bobs))
        .send()
        .await
        .expect("answered");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let seeds = sqlx_count(
        &stack.test_db,
        "SELECT count(*) FROM service.saved_filter_seeds",
    )
    .await;
    assert_eq!(seeds, 1, "alice's");
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
        queue: "<b>tier2</b>".to_owned(),
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
        // the default queue (PLAN.md 7.13), its text escaped
        r#"<input id="profile-queue" type="text" name="queue" value="&#60;b&#62;tier2&#60;/b&#62;" maxlength="64" required>"#,
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
        token: "ace-rs-k_the-token".to_owned(),
    };
    assert!(!format!("{made:?}").contains("the-token"), "Debug hides it");
    let made = made.render().expect("renders");
    assert!(
        made.contains(
            r#"<input id="new-key" class="token" type="text" value="ace-rs-k_the-token" readonly"#
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
            "a blank queue",
            profile(&[
                ("display_name", "Alice"),
                ("timezone", "UTC"),
                ("queue", "   "),
            ]),
            StatusCode::BAD_REQUEST,
            "Not saved: a queue needs a name.",
        ),
        (
            "a queue too long",
            profile(&[
                ("display_name", "Alice"),
                ("timezone", "UTC"),
                ("queue", &"q".repeat(65)),
            ]),
            StatusCode::BAD_REQUEST,
            "is longer than 64 characters",
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
        ("queue", " tier2 "),
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
    assert_eq!(
        account.queue, "tier2",
        "the default queue, trimmed (PLAN.md 7.13)"
    );
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
            "No key was made: alert:* covers alert:create, alert:queue, alert:write, which you don&#39;t hold.",
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
        assert!(!page.contains("ace-rs-k_"), "{what}: {page}");
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
    assert!(token.starts_with("ace-rs-k_"), "{page}");
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
        page.contains("Not changed: alert:* covers alert:create, alert:queue, alert:write"),
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
    // ace3's tip under the table (PLAN.md 7.13), with its `$USER` half (7.17)
    assert!(
        page.contains(
            "Tip: use <code>$USER_QUEUE</code> as a Queue value or <code>$USER</code> as an Owner value \
             to make a shared link adapt to whoever opens it."
        ),
        "{page}"
    );
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
        alerts: true,
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
        ["alert:create", "alert:queue", "alert:read", "alert:write"],
        "the catalog's order"
    );
    assert!(!alerts.escalates);
    assert_eq!(
        alerts.summary(false),
        "Gives alert:create, alert:queue, alert:read, alert:write."
    );
    assert_eq!(
        alerts.summary(true),
        "Takes away alert:create, alert:queue, alert:read, alert:write, whatever else allows them."
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
    assert!(
        hub.contains(r#"<a href="/admin" aria-current="page">Admin</a>"#),
        "{hub}"
    );
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
            ("queue", "<i>tier2</i>"),
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
    assert_eq!(
        carol.queue, "<i>tier2</i>",
        "her default queue (PLAN.md 7.13)"
    );
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
    assert!(
        listed.contains("<td>&#60;i&#62;tier2&#60;/i&#62;</td>"),
        "{listed}"
    );

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
            ("queue", "triage"),
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
        assert!(!text.contains("ace-rs-k_"), "{what}");
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
    assert!(token.starts_with("ace-rs-k_"));
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
        hub.contains(r#"<a href="/signatures" aria-current="page">Signatures</a>"#),
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
        view: event_list_view(
            Some(&page),
            &query,
            &fixture_choices(),
            None,
            true,
            &ace_service::Dispositions::ace3(),
        ),
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
    assert!(html.contains(r#"<td><span class="badge disposition-danger">DAMAGE</span></td>"#));
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
            &ace_service::Dispositions::ace3(),
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
            &ace_service::Dispositions::ace3(),
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
                &ace_service::Dispositions::ace3(),
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
            &ace_service::Dispositions::ace3(),
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
        assert!(page.contains(r#"<td><span class="badge disposition-warning">DAMAGE</span></td>"#));
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
            &ace_service::Dispositions::ace3(),
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
            &ace_service::Dispositions::ace3(),
        ),
    });
    assert!(html.contains("Set Disposition") && html.contains(r#"form="event-alerts""#));
    assert!(!html.contains("Remove Alert(s)") && !html.contains("Edit Event"));
    assert!(!html.contains("Add Tag(s)"));
    // neither: no form and no boxes
    let html = drawn_safely(&EventPageHtml {
        layout: Layout::signed_out("n"),
        view: event_view(
            &event,
            EventMay::default(),
            &ace_service::Dispositions::ace3(),
        ),
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
        view: event_list_view(
            Some(&page),
            &query,
            &fixture_choices(),
            None,
            true,
            &ace_service::Dispositions::ace3(),
        ),
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
        view: event_list_view(
            Some(&page),
            &query,
            &fixture_choices(),
            None,
            false,
            &ace_service::Dispositions::ace3(),
        ),
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
    assert!(page.contains(r#"<td><span class="badge disposition-warning">DAMAGE</span></td>"#));

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
/// newly registered domain's fields, and the clicker's clicks, with a link that isn't HTTPS left out.
/// A failed lookup or search is the result's error, which the result's page draws, escaped
/// (`a_failed_analysis_has_a_badge_its_reason_and_its_place_under_the_observable`).
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
            "age_created_in_days": null, "lookup_protocol": hostile}),
    );
    assert!(nrd.contains("&#60;script&#62;"), "{nrd}");
    let clicker = draw(
        "splunk_clicker_detection_analysis",
        serde_json::json!({"query": null, "query_results": null,
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

// ---- Administration's Observables (PLAN.md 7.6) ----

/// A module that reads 7.6's `observable_detection` list, so the binary has it. No mode names it.
struct DetectionReader;

impl ace_sdk::Module for DetectionReader {
    const NAME: &'static str = "test_detection_reader";
    const INPUTS: &'static [ace_results::ObservableKind] = &[ace_results::ObservableKind::Fqdn];
    const LISTS: &'static [ace_sdk::lists::ListSpec] = &[ace_sdk::lists::ListSpec {
        name: "observable_detection",
        description: "the observables ACE detects",
        typed: true,
    }];
    type Output = ace_results::types::snort::SnortSignatureAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ace_sdk::ModuleError> {
        Ok(DetectionReader)
    }
}

impl ace_sdk::Lookup for DetectionReader {
    const TCP_PORTS: &'static [u16] = &[];

    async fn analyze(
        &self,
        _: &ace_sdk::TaskContext<()>,
    ) -> Result<ace_sdk::Outcome<Self::Output>, ace_sdk::ModuleError> {
        Ok(ace_sdk::Outcome::Skipped("a stub".to_owned()))
    }
}

async fn detection_stack() -> Stack {
    stack_of(
        Catalog::new(vec![ace_sdk::Manifest::lookup::<DetectionReader>()]),
        |service| Gui::with_limits(service, Transport::Plain, LiveLimits::default()),
    )
    .await
}

fn detection_fixture(id: i64, kind: &str, value: &str) -> ace_service::Detection {
    let at = chrono::DateTime::parse_from_rfc3339("2030-01-02T03:04:05Z")
        .expect("a time")
        .to_utc();
    ace_service::Detection {
        id,
        observable_type: kind.to_owned(),
        value: value.to_owned(),
        expires_at: Some(at),
        expired: true,
        context: HOSTILE.to_owned(),
        created_by: RecordedActor {
            kind: "user".to_owned(),
            id: "u".to_owned(),
            name: Some(HOSTILE.to_owned()),
        },
        created_at: at,
        modified_by: RecordedActor {
            kind: "user".to_owned(),
            id: "u".to_owned(),
            name: None,
        },
        modified_at: at,
        comments: vec![ObservableComment {
            id: 1,
            kind: kind.to_owned(),
            value: value.to_owned(),
            author: CommentAuthor {
                id: ace_service::UserId(uuid::Uuid::from_u128(1)),
                username: "alice".to_owned(),
                display_name: Some(HOSTILE.to_owned()),
            },
            created_by: RecordedActor {
                kind: "user".to_owned(),
                id: "u".to_owned(),
                name: None,
            },
            comment: HOSTILE.to_owned(),
            created_at: at,
            edited_at: None,
        }],
    }
}

/// The Observables page's view, called directly: ace3's filters, pager and table, each detection's
/// expiry and delete as forms that carry the filters back, hostile text escaped and nothing inline, and
/// without `detection:write` no forms. An expiry is typed as UTC.
#[test]
fn the_observables_page_draws_detections_as_text() {
    use ace_gui::detection::{DetectionSettingsPage, detection_view, parse_expiry};
    use ace_service::{DetectionFilter, DetectionPage, DetectionStatus, DetectionTypes};
    let filter = DetectionFilter {
        search: Some(HOSTILE.to_owned()),
        observable_type: Some("fqdn".to_owned()),
        status: DetectionStatus::All,
        page: 2,
        page_size: 25,
    };
    let page = || DetectionPage {
        items: vec![detection_fixture(7, "fqdn", HOSTILE)],
        total: 60,
        page: 2,
        page_size: 25,
        total_pages: 3,
    };
    let types = || DetectionTypes {
        present: vec!["fqdn".to_owned()],
        all: vec!["file".to_owned(), "fqdn".to_owned(), "ipv4".to_owned()],
    };
    let layout = || {
        Layout::new(
            "n0nce",
            Theme::Dark,
            Some("alice".to_owned()),
            "/admin/detection",
        )
    };
    let html = drawn_safely(&DetectionSettingsPage {
        layout: layout(),
        view: detection_view(&filter, page(), types(), true),
    });
    let query = "q=%22%3E%3Cscript%3Ealert%28%27x%27%29%3C%2Fscript%3E%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E%26amp%3B&#38;type=fqdn&#38;status=all&#38;page_size=25";
    for part in [
        "Showing 26–26 of 60",
        "Page 2 of 3",
        &format!(r#"<a href="/admin/detection?{query}&#38;page=1">First</a>"#),
        &format!(r#"<a href="/admin/detection?{query}&#38;page=3">Last</a>"#),
        r#"<option value="all" selected>all</option>"#,
        r#"<option value="25" selected>25</option>"#,
        r#"<option value="fqdn" selected>fqdn</option>"#,
        r#"<form method="post" action="/admin/detection" class="detection-add" autocomplete="off">"#,
        r#"<option value="ipv4">ipv4</option>"#,
        r#"action="/admin/detection/7/expiration""#,
        r#"<button type="submit" name="action" value="never">never</button>"#,
        r#"action="/admin/detection/7/delete""#,
        r#"<input type="hidden" name="page" value="2">"#,
        &format!(r#"<input type="hidden" name="q" value="{HOSTILE_ESCAPED}">"#),
        &format!("<code>{HOSTILE_ESCAPED}</code>"),
        "2030-01-02 03:04:05 UTC",
        r#"<span class="badge">expired</span>"#,
    ] {
        assert!(html.contains(part), "{part}: {html}");
    }

    // a reader sees no forms, and an empty listing says so
    let empty = DetectionPage {
        items: Vec::new(),
        total: 0,
        page: 1,
        page_size: 50,
        total_pages: 1,
    };
    let html = drawn_safely(&DetectionSettingsPage {
        layout: layout(),
        view: detection_view(&DetectionFilter::default(), empty, types(), false),
    });
    assert!(
        !html.contains(r#"method="post" action="/admin/detection"#),
        "{html}"
    );
    assert!(html.contains("No matching detections"));
    assert!(html.contains("No detections found."));
    assert!(!html.contains("First"), "one page has no pager");

    // with no ruleset built the page says so, and nothing of an export shows
    assert!(html.contains("No ruleset has been built"), "{html}");

    // the YARA export of the detections (PLAN.md 7.16): the ruleset, each type's counts, and what was left
    // out with why, the compiler's error and the value as text
    let at_time = chrono::DateTime::parse_from_rfc3339("2030-01-02T03:04:05Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let mut view = detection_view(&DetectionFilter::default(), page(), types(), false);
    view.export = ace_gui::detection::export_view(ace_service::DetectionExport {
        ruleset: Some(ace_service::DetectionExportRuleset {
            key: "0123456789abcdef0123456789abcdef".to_owned(),
            commit: "c0ffee00c0ffee00c0ffee00".to_owned(),
            built_at: at_time,
        }),
        exported: 3,
        types: vec![ace_service::DetectionExportType {
            observable_type: "fqdn".to_owned(),
            detections: 3,
            strings: 6,
        }],
        skipped: vec![
            ace_service::DetectionExportSkipped {
                id: 9,
                observable_type: "url".to_owned(),
                value: Some(HOSTILE.to_owned()),
                error: HOSTILE.to_owned(),
            },
            ace_service::DetectionExportSkipped {
                id: 10,
                observable_type: "url".to_owned(),
                value: None,
                error: "the value is over 4096 bytes".to_owned(),
            },
        ],
        error: Some(HOSTILE.to_owned()),
    });
    let html = drawn_safely(&DetectionSettingsPage {
        layout: layout(),
        view,
    });
    for part in [
        "<h2>YARA export</h2>",
        "Ruleset <code>0123456789ab</code> of commit <code>c0ffee00c0ff</code>, built 2030-01-02 03:04:05 UTC, holds 3 detections as rules.",
        "<tr><td>fqdn</td><td>3</td><td>6</td></tr>",
        &format!(
            "<tr><td>url</td><td><code>{HOSTILE_ESCAPED}</code></td><td>{HOSTILE_ESCAPED}</td></tr>"
        ),
        r#"<tr><td>url</td><td><span class="muted">removed since</span></td><td>the value is over 4096 bytes</td></tr>"#,
        &format!(r#"<p class="error" role="alert">Nothing was exported: {HOSTILE_ESCAPED}</p>"#),
    ] {
        assert!(html.contains(part), "{part}: {html}");
    }
    assert!(!html.contains("No ruleset has been built"));

    let at = |s| parse_expiry(s).map(|t| t.to_rfc3339());
    assert_eq!(
        at("2030-01-02 03:04:05"),
        Some("2030-01-02T03:04:05+00:00".to_owned())
    );
    assert_eq!(
        at("2030-01-02T03:04"),
        Some("2030-01-02T03:04:00+00:00".to_owned())
    );
    assert_eq!(
        at(" 2030-01-02 03:04:05 UTC "),
        Some("2030-01-02T03:04:05+00:00".to_owned())
    );
    assert_eq!(
        at("2030-01-02"),
        Some("2030-01-02T00:00:00+00:00".to_owned())
    );
    assert_eq!(at("tomorrow"), None);
}

/// PLAN.md 7.12: the Monitoring page's view, called directly: the scheduled tasks, each a link to its
/// runs, with a failed last run and one that's behind marked; the runs; and the checks' records. A run's
/// error and summary and a record's identifier and value are text other code wrote, drawn as text.
#[test]
fn the_monitoring_page_draws_runs_and_records_as_text() {
    use ace_gui::monitoring::{MAX_RECORDS_SHOWN, MonitoringPage, monitoring_view};
    use ace_service::{MonitorRecord, MonitoringState, ScheduledRun, ScheduledTask};
    use serde_json::json;
    let at = chrono::DateTime::parse_from_rfc3339("2030-01-02T03:04:05Z")
        .expect("a time")
        .to_utc();
    let task = |name: &str, outcome: Option<&str>, overdue: i64, running: bool| ScheduledTask {
        name: name.to_owned(),
        schedule: "*/5 * * * *".to_owned(),
        due_at: at,
        running,
        overdue_seconds: overdue,
        last_outcome: outcome.map(str::to_owned),
        last_started_at: Some(at),
        last_ended_at: outcome.map(|_| at),
        last_error: (outcome == Some("failed")).then(|| HOSTILE.to_owned()),
        last_node: Some("host/1".to_owned()),
        failures_since_success: if outcome == Some("failed") { 3 } else { 0 },
    };
    let run = |outcome: Option<&str>| ScheduledRun {
        id: 1,
        task: "bucket_gc".to_owned(),
        scheduled_for: at,
        node: HOSTILE.to_owned(),
        started_at: at,
        ended_at: outcome.map(|_| at),
        outcome: outcome.map(str::to_owned),
        error: (outcome == Some("failed")).then(|| HOSTILE.to_owned()),
        summary: Some(json!({"pool": HOSTILE, "deleted": 2})),
    };
    let record = |identifier: &str| MonitorRecord {
        task: "monitor_queue".to_owned(),
        path: "workload.queue".to_owned(),
        identifier: Some(identifier.to_owned()),
        value: json!({"module": identifier, "queued": 3}),
        emitted_at: at,
    };
    let state = MonitoringState {
        tasks: vec![
            task("bucket_gc", Some("failed"), 11_520, false),
            task("monitor_queue", Some("succeeded"), 30, true),
            task("never_ran", None, 0, false),
        ],
        runs: vec![run(Some("failed")), run(Some("succeeded")), run(None)],
        records: vec![record(HOSTILE)],
    };
    let layout = || {
        Layout::new(
            "n0nce",
            Theme::Dark,
            Some("alice".to_owned()),
            "/admin/monitoring",
        )
    };
    let html = drawn_safely(&MonitoringPage {
        layout: layout(),
        view: monitoring_view(state, Some("bucket_gc")),
    });
    // the value as JSON text, escaped: serde_json's own escaping of the quote, then the template's
    let value = json!({"module": HOSTILE, "queued": 3}).to_string();
    let escaped = |text: &str| {
        text.replace('&', "&#38;")
            .replace('<', "&#60;")
            .replace('>', "&#62;")
            .replace('"', "&#34;")
            .replace('\'', "&#39;")
    };
    for part in [
        "<h1>Monitoring</h1>",
        r#"<td><a href="/admin/monitoring?task=bucket_gc">bucket_gc</a></td>"#,
        "<td><code>*/5 * * * *</code></td>",
        r#"<span class="nowrap">2030-01-02 03:04:05 UTC</span> <span class="badge">overdue 3h 12m</span>"#,
        r#"<td><span class="badge">failed</span></td>"#,
        "<td>3</td>",
        &format!("<td>{HOSTILE_ESCAPED}</td>"),
        // a task that is running and not a minute behind
        r#"<span class="nowrap">2030-01-02 03:04:05 UTC</span> <span class="badge">running</span></td>"#,
        "<td>succeeded</td>",
        "<h2>Runs of bucket_gc</h2>",
        r#"<p><a href="/admin/monitoring">Every task's runs</a></p>"#,
        "<td>running</td>",
        &format!(
            "<td><code>{}</code></td>",
            escaped(&json!({"pool": HOSTILE, "deleted": 2}).to_string())
        ),
        "<td><code>workload.queue</code></td>",
        &format!("<td><code>{}</code></td>", escaped(&value)),
    ] {
        assert!(html.contains(part), "{part}: {html}");
    }
    assert!(!html.contains("aren't shown"));

    // nothing scheduled and nothing found says so; more records than the page draws are counted
    let html = drawn_safely(&MonitoringPage {
        layout: layout(),
        view: monitoring_view(MonitoringState::default(), None),
    });
    for part in [
        "No task has been scheduled yet.",
        "No runs.",
        "No check has run yet.",
        "<h2>Runs</h2>",
    ] {
        assert!(html.contains(part), "{part}: {html}");
    }
    let many = MonitoringState {
        records: (0..MAX_RECORDS_SHOWN + 7)
            .map(|n| record(&format!("m{n}")))
            .collect(),
        ..MonitoringState::default()
    };
    let view = monitoring_view(many, None);
    assert_eq!(
        (view.records.len(), view.records_left_out),
        (MAX_RECORDS_SHOWN, 7)
    );
    let html = drawn_safely(&MonitoringPage {
        layout: layout(),
        view,
    });
    assert!(html.contains("7 more aren't shown."), "{html}");

    // the page is where an operator learns of the per-root metrics events: their target, their
    // messages and every field the core emits in each, by the name it emits it under
    let module = ace_core::metrics::ModuleMetrics {
        event_type: ace_core::metrics::EVENT_TYPE_MODULE,
        timestamp: chrono::Utc::now(),
        root_uuid: uuid::Uuid::from_u128(7),
        pass: 1,
        module: "file_type".to_owned(),
        analysis_time_seconds: 0.5,
        percentage: 100.0,
        exec_count: 1,
        cache: Some(ace_core::metrics::CacheMetrics {
            cache_hit_count: 1,
            cache_miss_count: 1,
            cache_write_count_insert: 1,
            cache_write_bytes_compressed_sum: 100,
            cache_lookup_ms_sum: 1.0,
            cache_lookup_ms_max: 1.0,
        }),
    };
    let event = ace_core::metrics::RootMetrics {
        event_type: ace_core::metrics::EVENT_TYPE_ROOT,
        timestamp: chrono::Utc::now(),
        root_uuid: uuid::Uuid::from_u128(7),
        pass: 1,
        total_analysis_time_seconds: 0.5,
        pass_open_seconds: Some(1.5),
        alert_type: None,
        is_alert: false,
        queue: "default".to_owned(),
        observable_count: 0,
        observable_type_counts: std::collections::BTreeMap::new(),
        task_count: 0,
        failed_task_count: 0,
        outcome: ace_core::metrics::OUTCOME_COMPLETED,
        modules: vec![module.clone()],
    };
    let (root_table, module_table) = html
        .split_once(r#"<table class="keys metrics-module-fields">"#)
        .expect("a table of the module event's fields");
    let root_table = root_table
        .split_once(r#"<table class="keys metrics-fields">"#)
        .expect("a table of the root event's fields")
        .1;
    for (json, table, count) in [
        (event.to_json(), root_table, 14),
        (module.to_json(), module_table, 14),
    ] {
        let fields: serde_json::Value = serde_json::from_str(&json).expect("JSON");
        let fields = fields.as_object().expect("an object");
        assert_eq!(fields.len(), count, "{json}");
        for field in fields.keys() {
            assert!(
                table.contains(&format!("<tr><td><code>{field}</code></td><td>")),
                "the page doesn't describe the event's {field}"
            );
        }
        assert_eq!(
            table.matches("<tr><td><code>").count(),
            fields.len(),
            "the page describes a field the event doesn't have"
        );
    }
    contains_all(
        &html,
        &[
            &format!("<code>{}</code>", ace_core::metrics::TARGET),
            &format!("<code>{}</code>", ace_core::metrics::MESSAGE_PREFIX),
            &format!("<code>{}</code>", ace_core::metrics::MODULE_MESSAGE_PREFIX),
            "<code>ace_monitor</code>",
        ],
    );
}

/// PLAN.md 7.12: the Monitoring page through the server. It needs `admin:read` and `monitoring:read`, and
/// the hub offers it to whoever holds `monitoring:read`. It lists the scheduled tasks, their runs and the
/// checks' records, a task's runs alone when asked, and a query it can't read takes its default.
#[tokio::test]
async fn monitoring_is_read_through_the_admin_area() {
    let stack = detection_stack().await;
    let page = stack
        .get("/admin/monitoring")
        .send()
        .await
        .expect("answered");
    assert_eq!(page.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&page), "/login?next=%2Fadmin%2Fmonitoring");

    let watcher = user(&stack, "watcher").await;
    grant_to(&stack, &watcher, "admin", "read").await;
    grant_to(&stack, &watcher, "monitoring", "read").await;
    let admin_only = user(&stack, "admin-only").await;
    grant_to(&stack, &admin_only, "admin", "read").await;
    // monitoring:read alone doesn't enter the area
    let outsider = user(&stack, "outsider").await;
    grant_to(&stack, &outsider, "monitoring", "read").await;
    let (wt, adm, out) = (
        session_of(&stack, "watcher").await,
        session_of(&stack, "admin-only").await,
        session_of(&stack, "outsider").await,
    );
    let get = |session: &str, path: &str| stack.get(path).header("cookie", cookie(session)).send();
    let text = |response: reqwest::Response| async move { response.text().await.expect("a page") };

    let refused = get(&out, "/admin/monitoring").await.expect("answered");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert!(text(refused).await.contains("admin:read"));
    let refused = get(&adm, "/admin/monitoring").await.expect("answered");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert!(text(refused).await.contains("monitoring:read"));
    let hub = text(get(&adm, "/admin").await.expect("answered")).await;
    assert!(!hub.contains(r#"href="/admin/monitoring""#), "{hub}");
    let hub = text(get(&wt, "/admin").await.expect("answered")).await;
    assert!(
        hub.contains(r#"<a href="/admin/monitoring"><b>Monitoring</b>"#),
        "{hub}"
    );

    let empty = get(&wt, "/admin/monitoring").await.expect("answered");
    assert_eq!(empty.status(), StatusCode::OK);
    let empty = text(empty).await;
    assert!(
        empty.contains("No task has been scheduled yet.")
            && empty.contains("No check has run yet.")
    );

    let pool = stack.test_db.db().pool();
    sqlx::query(
        "INSERT INTO scheduler.tasks (name, schedule, due_at)
         VALUES ('bucket_gc', '0 * * * *', now() + interval '1 hour'),
                ('monitor_queue', '* * * * *', now() - interval '2 hours')",
    )
    .execute(pool)
    .await
    .expect("tasks");
    for (task, outcome, error) in [
        ("bucket_gc", "succeeded", None),
        ("monitor_queue", "succeeded", None),
        ("bucket_gc", "failed", Some(HOSTILE)),
    ] {
        sqlx::query(
            "INSERT INTO scheduler.runs (task, scheduled_for, node, ended_at, outcome, error, summary)
             VALUES ($1, now(), 'host/1', now(), $2, $3, $4)",
        )
        .bind(task)
        .bind(outcome)
        .bind(error)
        .bind(serde_json::json!({"records": 1}))
        .execute(pool)
        .await
        .expect("a run");
    }
    sqlx::query(
        "INSERT INTO monitoring.records (task, path, identifier, value)
         VALUES ('monitor_queue', 'workload.queue', $1, $2)",
    )
    .bind(HOSTILE)
    .bind(serde_json::json!({"queued": 3}))
    .execute(pool)
    .await
    .expect("a record");

    let rows = stack.audit_count().await;
    let all = text(get(&wt, "/admin/monitoring").await.expect("answered")).await;
    for part in [
        r#"<td><a href="/admin/monitoring?task=bucket_gc">bucket_gc</a></td>"#,
        r#"<td><span class="badge">failed</span></td>"#,
        r#"<span class="badge">overdue 2h 0m</span>"#,
        &format!("<td>{HOSTILE_ESCAPED}</td>"),
        "<h2>Runs</h2>",
        "<td><code>workload.queue</code></td>",
        "<td><code>{&#34;queued&#34;:3}</code></td>",
    ] {
        assert!(all.contains(part), "{part}: {all}");
    }
    assert_eq!(
        all.matches("<td>host/1</td>").count(),
        3,
        "every task's runs"
    );
    let one = text(
        get(&wt, "/admin/monitoring?task=monitor_queue&runs=1")
            .await
            .expect("answered"),
    )
    .await;
    assert!(one.contains("<h2>Runs of monitor_queue</h2>"), "{one}");
    assert_eq!(one.matches("<td>host/1</td>").count(), 1);
    // a query that doesn't read takes its default: every task's runs
    let odd = get(&wt, "/admin/monitoring?task=%3Cscript%3E&runs=many")
        .await
        .expect("answered");
    assert_eq!(odd.status(), StatusCode::OK);
    let odd = text(odd).await;
    assert!(
        odd.contains("<h2>Runs</h2>") && !odd.contains("<script>alert"),
        "{odd}"
    );
    assert_eq!(odd.matches("<td>host/1</td>").count(), 3);
    assert_eq!(stack.audit_count().await, rows, "the page writes nothing");
}

/// PLAN.md 7.6: the Observables page through the server. It needs `admin:read` and `detection:read`,
/// and the hub offers it to whoever holds `detection:read`; adding, setting an expiry and removing are
/// this site's posts under `detection:write`, each one audited write that goes back to the page with its
/// filters; a refusal draws the page again with the service's reason and what was typed, or says why,
/// and writes nothing.
#[tokio::test]
async fn detections_are_added_expired_and_removed_through_the_admin_area() {
    let stack = detection_stack().await;
    let page = stack
        .get("/admin/detection")
        .send()
        .await
        .expect("answered");
    assert_eq!(page.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&page), "/login?next=%2Fadmin%2Fdetection");

    let editor = user(&stack, "editor").await;
    grant_to(&stack, &editor, "admin", "read").await;
    grant_to(&stack, &editor, "detection", "read").await;
    grant_to(&stack, &editor, "detection", "write").await;
    let reader = user(&stack, "reader").await;
    grant_to(&stack, &reader, "admin", "read").await;
    grant_to(&stack, &reader, "detection", "read").await;
    let admin_only = user(&stack, "admin-only").await;
    grant_to(&stack, &admin_only, "admin", "read").await;
    user(&stack, "nobody").await;
    let (ed, rd, adm, none) = (
        session_of(&stack, "editor").await,
        session_of(&stack, "reader").await,
        session_of(&stack, "admin-only").await,
        session_of(&stack, "nobody").await,
    );
    let get = |session: &str, path: &str| stack.get(path).header("cookie", cookie(session)).send();
    let text = |response: reqwest::Response| async move { response.text().await.expect("a page") };

    // who sees what
    let refused = get(&none, "/admin/detection").await.expect("answered");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert!(text(refused).await.contains("admin:read"));
    let refused = get(&adm, "/admin/detection").await.expect("answered");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert!(text(refused).await.contains("detection:read"));
    let hub = text(get(&adm, "/admin").await.expect("answered")).await;
    assert!(!hub.contains(r#"href="/admin/detection""#), "{hub}");
    let hub = text(get(&rd, "/admin").await.expect("answered")).await;
    assert!(
        hub.contains(r#"<a href="/admin/detection"><b>Observables</b>"#),
        "{hub}"
    );
    let read = get(&rd, "/admin/detection").await.expect("answered");
    assert_eq!(read.status(), StatusCode::OK);
    let read = text(read).await;
    assert!(read.contains("No detections found."));
    assert!(
        !read.contains(r#"method="post" action="/admin/detection"#),
        "a reader has no forms"
    );

    // a post the reader, a cross-site page or an outsider makes writes nothing
    let rows = stack.audit_count().await;
    let add_form = [
        ("observable_type", "fqdn"),
        ("value", HOSTILE),
        ("expires", ""),
        ("context", ""),
        ("q", "evil"),
        ("status", "all"),
        ("page_size", "25"),
        ("page", "1"),
    ];
    let refused = stack
        .post("/admin/detection", &add_form)
        .header("cookie", cookie(&rd))
        .send()
        .await
        .expect("answered");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert!(text(refused).await.contains("detection:write"));
    let cross_site = stack
        .http
        .post(format!("{}/admin/detection", stack.url))
        .header("cookie", cookie(&ed))
        .header("origin", "https://evil.example")
        .form(&add_form)
        .send()
        .await
        .expect("answered");
    assert_eq!(cross_site.status(), StatusCode::FORBIDDEN);
    let refused = stack
        .post("/admin/detection", &add_form)
        .header("cookie", cookie(&none))
        .send()
        .await
        .expect("answered");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(stack.audit_count().await, rows, "nothing refused has a row");

    // an add goes back to the page with its filters
    let post = |path: String, form: Vec<(&'static str, String)>| {
        let stack = &stack;
        let ed = ed.clone();
        async move {
            let form: Vec<(&str, &str)> = form.iter().map(|(k, v)| (*k, v.as_str())).collect();
            stack
                .post(&path, &form)
                .header("cookie", cookie(&ed))
                .send()
                .await
                .expect("answered")
        }
    };
    let owned = |form: &[(&'static str, &str)]| -> Vec<(&'static str, String)> {
        form.iter().map(|(k, v)| (*k, (*v).to_owned())).collect()
    };
    let added = post("/admin/detection".to_owned(), owned(&add_form)).await;
    assert_eq!(added.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&added),
        "/admin/detection?q=evil&status=all&page_size=25&page=1&done=added"
    );
    assert_eq!(stack.audit_count().await, rows + 1);
    assert_eq!(last_action(&stack).await, "create_detection");
    let shown = text(
        get(&ed, "/admin/detection?done=added")
            .await
            .expect("answered"),
    )
    .await;
    assert!(shown.contains("The detection is added."), "{shown}");
    assert!(shown.contains(&format!("<code>{HOSTILE_ESCAPED}</code>")));
    assert!(shown.contains("manually added by editor"), "{shown}");
    let id: i64 = sqlx::query_scalar(
        "SELECT id FROM lists.entries WHERE list = 'observable_detection' AND value = $1",
    )
    .bind(HOSTILE)
    .fetch_one(stack.test_db.db().pool())
    .await
    .expect("the entry");

    // the YARA export (PLAN.md 7.16): no ruleset yet, then one whose export left this detection out
    assert!(shown.contains("<h2>YARA export</h2>"), "{shown}");
    assert!(shown.contains("No ruleset has been built"), "{shown}");
    sqlx::query(
        "INSERT INTO yara.rulesets
             (key, commit, tree, sources_sha256, yara_x_version, files, left_out, qa_rules,
              signatures, detection_export)
         VALUES (repeat('b', 64), 'c0ffee', 'tree', 'sources', $1, '[]', '[]', '[]', '[]', $2)",
    )
    .bind(ace_core::rulesets::YARA_X_VERSION)
    .bind(serde_json::json!({
        "types": [{"type": "ipv4", "detections": 2, "strings": 4}],
        "skipped": [{"id": id, "type": "fqdn", "error": HOSTILE}],
        "error": null,
    }))
    .execute(stack.test_db.db().pool())
    .await
    .expect("a ruleset");
    let shown = text(get(&ed, "/admin/detection").await.expect("answered")).await;
    for part in [
        "Ruleset <code>bbbbbbbbbbbb</code> of commit <code>c0ffee</code>",
        "holds 2 detections as rules",
        "<tr><td>ipv4</td><td>2</td><td>4</td></tr>",
        &format!(
            "<tr><td>fqdn</td><td><code>{HOSTILE_ESCAPED}</code></td><td>{HOSTILE_ESCAPED}</td></tr>"
        ),
    ] {
        assert!(shown.contains(part), "{part}: {shown}");
    }
    sqlx::query("DELETE FROM yara.rulesets")
        .execute(stack.test_db.db().pool())
        .await
        .expect("removes it");

    // refusals draw the page again with the reason and what was typed
    for (form, status, says) in [
        (
            vec![
                ("observable_type", "no_such_type"),
                ("value", "typed.example"),
            ],
            StatusCode::BAD_REQUEST,
            "no observable type",
        ),
        (
            vec![("observable_type", "file"), ("value", "typed.example")],
            StatusCode::BAD_REQUEST,
            "not a file value",
        ),
        (
            vec![
                ("observable_type", "fqdn"),
                ("value", "typed.example"),
                ("expires", "soon"),
            ],
            StatusCode::BAD_REQUEST,
            "An expiry is a UTC time",
        ),
        (
            vec![("observable_type", "fqdn"), ("value", HOSTILE)],
            StatusCode::CONFLICT,
            "a detection already exists",
        ),
    ] {
        let refused = post("/admin/detection".to_owned(), owned(&form)).await;
        assert_eq!(refused.status(), status, "{says}");
        let page = text(refused).await;
        assert!(page.contains(says), "{says}: {page}");
        assert!(
            page.contains(r#"value="typed.example""#) || says.starts_with("a detection"),
            "{page}"
        );
    }
    assert_eq!(stack.audit_count().await, rows + 1);

    // an expiry, never, the same again, one that passed and one that isn't a time
    let expiration = format!("/admin/detection/{id}/expiration");
    let set = post(
        expiration.clone(),
        owned(&[("expires", "2999-01-02 03:04:05"), ("action", "set")]),
    )
    .await;
    assert_eq!(set.status(), StatusCode::SEE_OTHER);
    assert!(
        location(&set).ends_with("done=expiration"),
        "{}",
        location(&set)
    );
    assert_eq!(last_action(&stack).await, "set_detection_expiration");
    let never = post(expiration.clone(), owned(&[("action", "never")])).await;
    assert!(location(&never).ends_with("done=expiration"));
    let again = post(expiration.clone(), owned(&[("action", "never")])).await;
    assert!(location(&again).ends_with("done=unchanged"));
    assert_eq!(stack.audit_count().await, rows + 3);
    let passed = post(
        expiration.clone(),
        owned(&[("expires", "2001-01-01"), ("action", "set")]),
    )
    .await;
    assert_eq!(passed.status(), StatusCode::BAD_REQUEST);
    assert!(text(passed).await.contains("in the future"));
    let garbled = post(
        expiration.clone(),
        owned(&[("expires", ""), ("action", "set")]),
    )
    .await;
    assert_eq!(garbled.status(), StatusCode::BAD_REQUEST);
    for (path, status) in [
        (
            "/admin/detection/abc/expiration".to_owned(),
            StatusCode::BAD_REQUEST,
        ),
        (
            format!("/admin/detection/{}/expiration", i64::MAX),
            StatusCode::NOT_FOUND,
        ),
    ] {
        let refused = post(path.clone(), owned(&[("action", "never")])).await;
        assert_eq!(refused.status(), status, "{path}");
    }
    assert_eq!(stack.audit_count().await, rows + 3);

    // and a delete
    let delete = format!("/admin/detection/{id}/delete");
    let deleted = post(delete.clone(), owned(&[("status", "expired")])).await;
    assert_eq!(deleted.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&deleted),
        "/admin/detection?status=expired&page_size=50&page=1&done=deleted"
    );
    assert_eq!(last_action(&stack).await, "delete_detection");
    let gone = post(delete, Vec::new()).await;
    assert_eq!(gone.status(), StatusCode::NOT_FOUND);
    let bad = post("/admin/detection/abc/delete".to_owned(), Vec::new()).await;
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
    assert_eq!(stack.audit_count().await, rows + 4);
}

// PLAN.md 7.9: the remediation and file_collection areas, and the event page's coverage.

static TEST_COLLECTOR: ace_sdk::actions::ActionSpec = ace_sdk::actions::ActionSpec::new(
    ace_sdk::actions::ActionKind::FileCollection,
    "edr",
    "Test EDR",
    "Collects files in tests.",
    "file_location",
);

/// ace3's test remediator and a test collector.
fn test_actions() -> ace_core::actions::ActionCatalog {
    ace_core::actions::ActionCatalog::new(&[&ace_sdk::actions::TEST_REMEDIATOR, &TEST_COLLECTOR])
        .expect("a catalog")
}

fn remediation_fixture(
    id: i64,
    value: &str,
    status: &str,
    result: Option<&str>,
) -> ace_service::Remediation {
    ace_service::Remediation {
        id,
        remediator: "test".to_owned(),
        display_name: Some("Test Remediator".to_owned()),
        observable_type: "test".to_owned(),
        observable_value: value.to_owned(),
        action: "remove".to_owned(),
        status: status.to_owned(),
        result: result.map(str::to_owned),
        result_message: Some(HOSTILE.to_owned()),
        analyst: Some(HOSTILE.to_owned()),
        attempts: 1,
        created_at: "2026-11-01T10:00:00Z".parse().expect("a time"),
        updated_at: None,
    }
}

/// The areas' pages, drawn directly: a value, a message and an analyst are text; a writer gets each row's
/// forms and a reader none; the filters come back as the form's fields and as the pager's share links.
#[test]
fn the_remediation_areas_draw_hostile_values_as_text() {
    use ace_gui::remediation::{
        CollectionPage, CollectionsPage, CollectorChoice, RemediationPage, RemediationsPage,
        RequestPage, TargetsPage, TargetsView, collection_view, collections_view, list_request,
        remediation_view, remediations_view, request_view, target_key, target_row,
    };
    use ace_service::filters::FilterScreen;
    let layout = |path: &str| Layout::new("n0nce", Theme::Dark, Some("alice".to_owned()), path);
    let request = list_request(
        FilterScreen::Remediations,
        Some("f=value:a%2Cb&f=!result:FAILED&after=9"),
    )
    .expect("reads");
    assert!(!request.folded);
    let page = || ace_service::RemediationPage {
        remediations: vec![
            remediation_fixture(8, HOSTILE, "COMPLETED", Some("SUCCESS")),
            remediation_fixture(7, "DELAYED", "IN_PROGRESS", Some("DELAYED")),
        ],
        total: 12,
        next: Some(7),
    };
    let html = drawn_safely(&RemediationsPage {
        quick: Default::default(),
        layout: layout("/remediations"),
        view: remediations_view(&request, page(), true),
    });
    for part in [
        &format!("<code>{HOSTILE_ESCAPED}</code>") as &str,
        r#"action="/remediations/8/restore""#,
        r#"action="/remediations/8/retry""#,
        r#"action="/remediations/7/cancel""#,
        r#"action="/remediations/7/delete""#,
        r#"<a href="/remediations/targets">Add Remediation</a>"#,
        r#"name="value" value="a,b""#,
        "12 matching",
        r#"href="/remediations?f=value%3Aa%2Cb&#38;f=%21result%3AFAILED">First</a>"#,
        r#"href="/remediations?f=value%3Aa%2Cb&#38;f=%21result%3AFAILED&#38;after=7">Next</a>"#,
        r#"href="/api/remediation/v1/remediations/export/csv?f=value%3Aa%2Cb&#38;f=%21result%3AFAILED""#,
    ] {
        assert!(html.contains(part), "{part}: {html}");
    }
    let read = drawn_safely(&RemediationsPage {
        quick: Default::default(),
        layout: layout("/remediations"),
        view: remediations_view(&request, page(), false),
    });
    assert!(
        !read.contains(r#"method="post""#.trim_end_matches('"'))
            || !read.contains("/remediations/8/retry"),
        "{read}"
    );
    assert!(!read.contains("Add Remediation"));

    // a remediation's page with its tries
    let attempt = ace_service::ActionAttempt {
        status: "COMPLETED".to_owned(),
        result: "SUCCESS".to_owned(),
        message: HOSTILE.to_owned(),
        // the mailbox an alias resolved to, which the history names (ace3's resolved_target)
        resolved_target: Some(format!("owner{HOSTILE}@example.com")),
        created_at: "2026-11-01T10:01:00Z".parse().expect("a time"),
    };
    let html = drawn_safely(&RemediationPage {
        layout: layout("/remediations/8"),
        view: remediation_view(
            remediation_fixture(8, HOSTILE, "COMPLETED", Some("SUCCESS")),
            vec![attempt.clone()],
            true,
        ),
    });
    assert!(html.contains("2026-11-01 10:01:00"), "{html}");
    assert!(html.contains("<th>Acted on</th>"), "{html}");
    assert!(
        html.contains(r#"name="back" value="/remediations""#),
        "{html}"
    );

    // the add form's targets, whose checkbox carries the target
    let target = ace_service::RemediationTarget {
        key: ace_service::TargetKey {
            remediator: "test".to_owned(),
            observable_type: "test".to_owned(),
            observable_value: format!("a:b{HOSTILE}"),
        },
        display_name: Some("Test Remediator".to_owned()),
        current: None,
    };
    let row = target_row(target.clone());
    assert_eq!(
        target_key(&row.key),
        Some(target.key.clone()),
        "a value's colons stay"
    );
    let html = drawn_safely(&TargetsPage {
        layout: layout("/remediations/targets"),
        view: TargetsView {
            types: vec!["test"],
            selected_type: "test".to_owned(),
            values: HOSTILE.to_owned(),
            alerts: Vec::new(),
            targets: Some(vec![row]),
            can_write: true,
            problem: Some(HOSTILE.to_owned()),
        },
    });
    assert!(
        html.contains(r#"<button type="submit" name="action" value="restore">Restore</button>"#)
    );
    assert!(
        html.contains(&format!("{HOSTILE_ESCAPED}</textarea>")),
        "{html}"
    );

    // the file collections, each with its alerts and file
    let collection = || ace_service::FileCollection {
        id: 3,
        collector: "edr".to_owned(),
        display_name: Some("Test EDR".to_owned()),
        observable_type: "file_location".to_owned(),
        observable_value: HOSTILE.to_owned(),
        status: "COMPLETED".to_owned(),
        result: Some("SUCCESS".to_owned()),
        result_message: None,
        attempts: 2,
        max_attempts: Some(10),
        alerts: vec![uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2)],
        requested_by: None,
        file: Some(("a".repeat(64), 5, HOSTILE.to_owned())),
        created_at: "2026-11-01T10:00:00Z".parse().expect("a time"),
        updated_at: None,
    };
    let crequest = list_request(FilterScreen::FileCollections, None).expect("reads");
    let html = drawn_safely(&CollectionsPage {
        quick: Default::default(),
        layout: layout("/file-collections"),
        view: collections_view(
            &crequest,
            ace_service::FileCollectionPage {
                collections: vec![collection()],
                total: 1,
                next: None,
            },
            true,
        ),
        can_create: true,
    });
    for part in [
        r#"<a href="/file-collections/new">Request File Collection</a>"#,
        r#"<a href="/alerts/00000000-0000-0000-0000-000000000001">"#,
        r#"<a href="/alerts/00000000-0000-0000-0000-000000000002">"#,
        "2/10",
        r#"action="/file-collections/3/retry""#,
        r#"action="/file-collections/3/delete""#,
    ] {
        assert!(html.contains(part), "{part}: {html}");
    }
    assert!(
        !html.contains("/file-collections/3/cancel"),
        "a completed one isn't cancelled"
    );
    let cannot = drawn_safely(&CollectionsPage {
        quick: Default::default(),
        layout: layout("/file-collections"),
        view: collections_view(
            &crequest,
            ace_service::FileCollectionPage {
                collections: vec![],
                total: 0,
                next: None,
            },
            false,
        ),
        can_create: false,
    });
    assert!(!cannot.contains("/file-collections/new"), "{cannot}");
    drawn_safely(&CollectionPage {
        layout: layout("/file-collections/3"),
        view: collection_view(collection(), vec![attempt], false),
    });

    // the request form: the collectors, and the alerts it was given, as text
    let html = drawn_safely(&RequestPage {
        layout: layout("/file-collections/new"),
        view: request_view(
            vec![CollectorChoice {
                name: "edr",
                display_name: "Test EDR",
                observable_type: "file_location",
            }],
            &[
                HOSTILE.to_owned(),
                "00000000-0000-0000-0000-000000000001".to_owned(),
            ],
        ),
    });
    for part in [
        r#"<form method="post" action="/file-collections" class="detection-add">"#,
        r#"<option value="edr">Test EDR (file_location)</option>"#,
        &format!("{HOSTILE_ESCAPED}\n00000000-0000-0000-0000-000000000001</textarea>") as &str,
    ] {
        assert!(html.contains(part), "{part}: {html}");
    }
    let none = drawn_safely(&RequestPage {
        layout: layout("/file-collections/new"),
        view: request_view(vec![], &[]),
    });
    assert!(
        none.contains("This server runs no file collector."),
        "{none}"
    );
    assert!(!none.contains(r#"action="/file-collections""#), "{none}");

    // a filter the screen hasn't, or a value of the wrong shape, isn't a list
    for bad in ["f=nope:x", "f=id:x", "after=x", "status=WHENEVER"] {
        assert!(
            list_request(FilterScreen::Remediations, Some(bad)).is_err(),
            "{bad}"
        );
    }
    let folded = list_request(
        FilterScreen::FileCollections,
        Some("collector=edr&alert=&status=new"),
    )
    .expect("reads");
    assert!(folded.folded);
    assert_eq!(folded.filters.len(), 2, "{folded:?}");
}

/// The areas through the server: signed out goes to the login; reading needs each area's `:read` and
/// each form its `:write`; Add Remediation queues the ticked targets as one audited write; a row's form
/// cancels, retries, restores and deletes, each audited, and comes back to the list it was on; the
/// filter form folds into a share link; a cross-site post writes nothing; and an event's page shows its
/// alerts' coverage badges to whoever holds `remediation:read`.
#[tokio::test]
async fn remediations_and_collections_are_worked_through_the_gui() {
    let stack = stack().await;
    let page = stack.get("/remediations").send().await.expect("answered");
    assert_eq!(page.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&page), "/login?next=%2Fremediations");
    let editor = user(&stack, "editor").await;
    for (major, minor) in [
        ("remediation", "read"),
        ("remediation", "write"),
        ("file_collection", "read"),
        ("file_collection", "write"),
        ("file_collection", "create"),
        ("event", "read"),
        ("alert", "read"),
    ] {
        grant_to(&stack, &editor, major, minor).await;
    }
    let reader = user(&stack, "reader").await;
    grant_to(&stack, &reader, "remediation", "read").await;
    grant_to(&stack, &reader, "event", "read").await;
    user(&stack, "nobody").await;
    let (ed, rd, none) = (
        session_of(&stack, "editor").await,
        session_of(&stack, "reader").await,
        session_of(&stack, "nobody").await,
    );
    let get = |session: &str, path: &str| stack.get(path).header("cookie", cookie(session)).send();
    let text = |response: reqwest::Response| async move { response.text().await.expect("a page") };

    let refused = get(&none, "/remediations").await.expect("answered");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert!(text(refused).await.contains("remediation:read"));
    let refused = get(&rd, "/file-collections").await.expect("answered");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let refused = get(&none, "/remediations/targets").await.expect("answered");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let listed = text(get(&rd, "/remediations").await.expect("answered")).await;
    assert!(listed.contains("No remediations."), "{listed}");
    assert!(
        listed.contains(r#"<a href="/remediations" aria-current="page">Remediations</a>"#),
        "the nav links it"
    );
    assert!(!listed.contains(r#"href="/file-collections""#), "{listed}");

    // Add Remediation: find the targets of values, tick them, remove
    let found = get(
        &ed,
        "/remediations/targets?type=test&values=SUCCESS%0ADELAYED",
    )
    .await
    .expect("answered");
    assert_eq!(found.status(), StatusCode::OK);
    let found = text(found).await;
    assert!(found.contains(r#"value="test:test:SUCCESS""#), "{found}");
    let bad = get(&ed, "/remediations/targets?type=no_such_type&values=x")
        .await
        .expect("answered");
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
    let rows = stack.audit_count().await;
    let form = [
        ("action", "remove"),
        ("target", "test:test:SUCCESS"),
        ("target", "test:test:DELAYED"),
    ];
    for (session, origin, status) in [
        (&rd, None, StatusCode::FORBIDDEN),
        (&ed, Some("https://evil.example"), StatusCode::FORBIDDEN),
    ] {
        let request = stack
            .http
            .post(format!("{}/remediations", stack.url))
            .header("origin", origin.unwrap_or(&stack.url))
            .header("cookie", cookie(session))
            .form(&form);
        assert_eq!(request.send().await.expect("answered").status(), status);
    }
    assert_eq!(stack.audit_count().await, rows, "nothing refused has a row");
    let queued = stack
        .post("/remediations", &form)
        .header("cookie", cookie(&ed))
        .send()
        .await
        .expect("answered");
    assert_eq!(queued.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&queued), "/remediations?done=queued");
    assert_eq!(last_action(&stack).await, "queue_remediations");
    let none_ticked = stack
        .post("/remediations", &[("action", "remove")])
        .header("cookie", cookie(&ed))
        .send()
        .await
        .expect("answered");
    assert_eq!(none_ticked.status(), StatusCode::BAD_REQUEST);
    let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM queue.actions ORDER BY id")
        .fetch_all(stack.test_db.db().pool())
        .await
        .expect("reads");
    let list = text(
        get(&ed, "/remediations?done=queued")
            .await
            .expect("answered"),
    )
    .await;
    assert!(list.contains("The remediations are queued."), "{list}");
    assert!(
        list.contains(&format!(r#"action="/remediations/{}/cancel""#, ids[0])),
        "{list}"
    );

    // the filter form folds into a share link, and a bad one is refused
    let folded = get(&ed, "/remediations?value=SUCC&status=")
        .await
        .expect("answered");
    assert_eq!(folded.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&folded), "/remediations?f=value%3ASUCC");
    let bad = get(&ed, "/remediations?f=nope:x").await.expect("answered");
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);

    // a row's forms, back to the list they were on
    let write = |path: String, back: &'static str| {
        let stack = &stack;
        let ed = ed.clone();
        async move {
            stack
                .post(&path, &[("back", back)])
                .header("cookie", cookie(&ed))
                .send()
                .await
                .expect("answered")
        }
    };
    let cancelled = write(
        format!("/remediations/{}/cancel", ids[1]),
        "/remediations?f=value%3ADELAYED",
    )
    .await;
    assert_eq!(cancelled.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&cancelled),
        "/remediations?f=value%3ADELAYED&done=cancelled"
    );
    let elsewhere = write(
        format!("/remediations/{}/retry", ids[1]),
        "https://evil.example/",
    )
    .await;
    assert_eq!(
        location(&elsewhere),
        "/remediations?done=retried",
        "only its own list"
    );
    let again = write(format!("/remediations/{}/cancel", ids[0]), "/remediations").await;
    assert_eq!(again.status(), StatusCode::SEE_OTHER);
    let conflict = write(format!("/remediations/{}/cancel", ids[0]), "/remediations").await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    let missing = write("/remediations/999999/delete".to_owned(), "/remediations").await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    let nonsense = write("/remediations/x/delete".to_owned(), "/remediations").await;
    assert_eq!(nonsense.status(), StatusCode::BAD_REQUEST);
    let deleted = write(format!("/remediations/{}/delete", ids[0]), "/remediations").await;
    assert_eq!(location(&deleted), "/remediations?done=deleted");
    let one = get(&ed, &format!("/remediations/{}", ids[1]))
        .await
        .expect("answered");
    assert_eq!(one.status(), StatusCode::OK);
    assert!(text(one).await.contains("cancelled by editor"));
    assert_eq!(
        get(&ed, "/remediations/999999")
            .await
            .expect("answered")
            .status(),
        StatusCode::NOT_FOUND
    );

    // the file collections
    let alert = list_alert(&stack, "an alert", "2026-11-01T10:00:00Z", None).await;
    let mut tx = stack.test_db.db().begin().await.expect("begins");
    let collection = ace_core::actions::request_collection(
        &mut tx,
        &test_actions(),
        &ace_core::actions::NewCollection {
            handler: "edr",
            observable_type: "file_location",
            observable_value: "host@C:\\evil.ps1",
            root: Some(alert),
            requested_by: None,
            user: None,
        },
    )
    .await
    .expect("requests")
    .id();
    tx.commit().await.expect("commits");
    let collections = text(get(&ed, "/file-collections").await.expect("answered")).await;
    assert!(
        collections.contains(&format!(r#"<a href="/alerts/{alert}">"#)),
        "{collections}"
    );
    let cancelled = write(
        format!("/file-collections/{collection}/cancel"),
        "/file-collections",
    )
    .await;
    assert_eq!(location(&cancelled), "/file-collections?done=cancelled");
    let page = text(
        get(&ed, &format!("/file-collections/{collection}"))
            .await
            .expect("answered"),
    )
    .await;
    assert!(page.contains("CANCELLED"), "{page}");

    // Request File Collection: the form, then a request, then the same file joins it (#1101)
    let refused = get(&rd, "/file-collections/new").await.expect("answered");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert!(text(refused).await.contains("file_collection:create"));
    let form = text(
        get(&ed, &format!("/file-collections/new?alert={alert}"))
            .await
            .expect("answered"),
    )
    .await;
    assert!(
        form.contains(r#"<option value="edr">Test EDR (file_location)</option>"#),
        "{form}"
    );
    assert!(form.contains(&format!("{alert}</textarea>")), "{form}");
    assert!(
        collections.contains(r#"<a href="/file-collections/new">Request File Collection</a>"#),
        "{collections}"
    );
    let other = list_alert(&stack, "another alert", "2026-11-01T11:00:00Z", None).await;
    let rows = stack.audit_count().await;
    let ask = |value: &'static str, alerts: String| {
        vec![
            ("collector", "edr".to_owned()),
            ("value", value.to_owned()),
            ("alerts", alerts),
        ]
    };
    let asked = ask("host@C:\\evil.ps1", format!("{alert}\r\n"));
    for (session, origin, status) in [
        (&rd, None, StatusCode::FORBIDDEN),
        (&ed, Some("https://evil.example"), StatusCode::FORBIDDEN),
    ] {
        let request = stack
            .http
            .post(format!("{}/file-collections", stack.url))
            .header("origin", origin.unwrap_or(&stack.url))
            .header("cookie", cookie(session))
            .form(&asked);
        assert_eq!(request.send().await.expect("answered").status(), status);
    }
    assert_eq!(stack.audit_count().await, rows, "nothing refused has a row");
    let post = |form: Vec<(&'static str, String)>| {
        let stack = &stack;
        let ed = ed.clone();
        async move {
            let form: Vec<(&str, &str)> = form.iter().map(|(k, v)| (*k, v.as_str())).collect();
            stack
                .post("/file-collections", &form)
                .header("cookie", cookie(&ed))
                .send()
                .await
                .expect("answered")
        }
    };
    let requested = post(asked.clone()).await;
    assert_eq!(requested.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&requested), "/file-collections?done=requested");
    assert_eq!(last_action(&stack).await, "request_file_collection");
    let joined = post(ask("host@C:\\evil.ps1", format!("{other}"))).await;
    assert_eq!(location(&joined), "/file-collections?done=joined");
    let listed = text(
        get(&ed, "/file-collections?done=joined")
            .await
            .expect("answered"),
    )
    .await;
    assert!(
        listed.contains("the alerts now belong to it as well"),
        "{listed}"
    );
    let alerts: Vec<uuid::Uuid> = sqlx::query_scalar(
        "SELECT r.root_id FROM queue.action_roots r JOIN queue.actions a ON a.id = r.action_id
         WHERE a.status <> 'COMPLETED' AND a.observable_value = 'host@C:\\evil.ps1'
         ORDER BY r.created_at",
    )
    .fetch_all(stack.test_db.db().pool())
    .await
    .expect("reads");
    assert_eq!(alerts, [alert, other], "one collection, each alert's");
    assert_eq!(stack.audit_count().await, rows + 2);
    for form in [
        vec![
            ("collector", "unknown".to_owned()),
            ("value", "h@C:\\x".to_owned()),
        ],
        ask("no host", String::new()),
        ask("h@C:\\x", "not-an-alert".to_owned()),
    ] {
        let refused = post(form).await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    }
    let missing = post(ask("h@C:\\x", uuid::Uuid::nil().to_string())).await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        stack.audit_count().await,
        rows + 2,
        "nothing refused has a row"
    );

    // an event's page: the coverage badge, to whoever reads remediations
    let event = gui_event(&stack, "remediated", "2026-11-01", "OPEN").await;
    sqlx::query("INSERT INTO events.event_alerts (event_id, root_id) VALUES ($1, $2)")
        .bind(event)
        .bind(alert)
        .execute(stack.test_db.db().pool())
        .await
        .expect("adds");
    let mut tx = stack.test_db.db().begin().await.expect("begins");
    ace_core::tree::upsert_observable(
        &mut tx,
        alert,
        &ace_results::NewObservable::new(
            ace_results::ObservableKind::EmailDelivery,
            "<m@x>|bob@example.com",
        ),
    )
    .await
    .expect("adds");
    tx.commit().await.expect("commits");
    sqlx::query(
        "INSERT INTO queue.actions (kind, handler, observable_type, observable_value, action, status, result)
         VALUES ('remediation', 'test', 'email_delivery', '<m@x>|bob@example.com', 'remove', 'COMPLETED', 'SUCCESS')",
    )
    .execute(stack.test_db.db().pool())
    .await
    .expect("a removal");
    let shown = text(
        get(&rd, &format!("/events/{event}"))
            .await
            .expect("answered"),
    )
    .await;
    assert!(
        shown.contains(r#"<span class="badge coverage-remediated" title="bob@example.com: ACE">remediated 1/1 · ACE</span>"#),
        "{shown}"
    );
    assert!(
        shown.contains(&format!(r#"href="/remediations/targets?alert={alert}""#)),
        "{shown}"
    );
    let viewer = user(&stack, "viewer").await;
    grant_to(&stack, &viewer, "event", "read").await;
    let vw = session_of(&stack, "viewer").await;
    let hidden = text(
        get(&vw, &format!("/events/{event}"))
            .await
            .expect("answered"),
    )
    .await;
    assert!(!hidden.contains("coverage-"), "{hidden}");
    assert!(!hidden.contains("/remediations/targets"), "{hidden}");
}

// PLAN.md decision 38: the alert's remediation timeline, ace3's Remediation Timeline.

/// The panel draws ace3's timeline rows: an alias's removal names its owner, a delivery the journal
/// says wasn't made and a forward read as the journal's wording, a removal the owner's own covered
/// reads NOT_FOUND through the owner, a pending row is marked, ACE's rows link their remediation and a
/// vendor's its https:// link only; every value a vendor or an attacker sets is escaped.
#[test]
fn the_alert_page_draws_its_remediation_timeline() {
    use ace_service::{RemediationTimeline, TimelineEvent};
    let (tree, comments) = fixture_tree();
    let at = |s: &str| {
        chrono::DateTime::parse_from_rfc3339(s)
            .expect("a time")
            .with_timezone(&chrono::Utc)
    };
    let event = |target: &str, description: &str, after: &str| TimelineEvent {
        source: "ACE".to_owned(),
        description: description.to_owned(),
        timestamp: at(after),
        event_time: Some(at("2026-11-01T11:58:30Z")),
        target: Some(target.to_owned()),
        message: None,
        portal_url: None,
        remediation: Some(41),
        delivery: None,
        pending: false,
    };
    let hostile_mailbox = format!("owner{HOSTILE}@example.com");
    let timeline = RemediationTimeline {
        coverage: ace_service::Coverage {
            targets: vec![ace_service::TargetCoverage {
                target: "<m1@example.net>|alias@example.com".to_owned(),
                sources: ["ACE".to_owned()].into(),
                attempted: true,
                ..ace_service::TargetCoverage::default()
            }],
        },
        events: vec![
            TimelineEvent {
                message: Some(format!(
                    "alias@example.com is an alias of {hostile_mailbox}: {HOSTILE}"
                )),
                ..event(
                    &format!("alias@example.com \u{2192} {hostile_mailbox}"),
                    &format!("Remove (Success) via {hostile_mailbox}"),
                    "2026-11-01T12:00:30Z",
                )
            },
            event(
                "other@example.com \u{2192} owner@example.com",
                "Remove (Not_found) via owner@example.com",
                "2026-11-01T12:00:40Z",
            ),
            event(
                "fwd@example.com",
                "Remove (not delivered to this address; forwarded to owner@example.com)",
                "2026-11-01T12:00:50Z",
            ),
            event(
                "ghost@example.com",
                "Remove (no journal record of a copy delivered to this address)",
                "2026-11-01T12:01:00Z",
            ),
            TimelineEvent {
                source: format!("vendor{HOSTILE}"),
                portal_url: Some("https://portal.example/m?a=1&b=2".to_owned()),
                remediation: None,
                ..event("owner@example.com", HOSTILE, "2026-11-01T13:00:00Z")
            },
            TimelineEvent {
                source: "Vendor".to_owned(),
                portal_url: Some("javascript:alert(1)".to_owned()),
                remediation: None,
                ..event("owner@example.com", "moved to junk", "2026-11-01T13:00:01Z")
            },
            TimelineEvent {
                source: "Vendor".to_owned(),
                remediation: None,
                pending: true,
                delivery: Some(format!("<m{HOSTILE}@example.net>|late@example.com")),
                ..event("late@example.com", "Watching", "2026-11-01T12:01:00Z")
            },
        ],
        truncated: false,
    };
    let html = drawn_safely(
        &AlertPage::with(
            Layout::new("n0nce", Theme::Light, Some("alice".to_owned()), "/alerts/x"),
            &tree,
            &comments,
            &ObservableActions::empty(),
            &std::collections::BTreeMap::new(),
            PageOptions {
                remediation: Some(&timeline),
                ..PageOptions::default()
            },
        )
        .expect("a page"),
    );
    let page: String = html.lines().map(str::trim).collect();
    let hostile_mailbox_escaped = format!("owner{HOSTILE_ESCAPED}@example.com");
    contains_all(
        &page,
        &[
            r#"<summary>Remediation <span class="badge coverage-remediated" title="alias@example.com: ACE">remediated 1/1 · ACE</span> <span class="hint">(6 events, 1 pending)</span></summary>"#,
            "<thead><tr><th>When (UTC)</th><th>Target</th><th>Source</th><th>Action</th><th>After</th><th></th></tr></thead>",
            // an alias's removal, through its owner, with the remediator's words as its tooltip
            &format!(
                r#"<td>alias@example.com → {hostile_mailbox_escaped}</td><td>ACE</td><td title="alias@example.com is an alias of {hostile_mailbox_escaped}: {HOSTILE_ESCAPED}">Remove (Success) via {hostile_mailbox_escaped}</td><td class="nowrap" title="after the message's time, 2026-11-01 11:58:30 UTC">2m</td><td><a href="/remediations/41">history</a></td></tr>"#
            ),
            "<td>other@example.com → owner@example.com</td><td>ACE</td><td>Remove (Not_found) via owner@example.com</td>",
            "<td>fwd@example.com</td><td>ACE</td><td>Remove (not delivered to this address; forwarded to owner@example.com)</td>",
            "<td>ghost@example.com</td><td>ACE</td><td>Remove (no journal record of a copy delivered to this address)</td>",
            // a vendor's event: its words escaped, its https link opened apart
            &format!(
                r#"<td>Vendor{HOSTILE_ESCAPED}</td><td>{HOSTILE_ESCAPED}</td><td class="nowrap" title="after the message's time, 2026-11-01 11:58:30 UTC">1h 1m</td><td><a href="https://portal.example/m?a=1&#38;b=2" rel="noreferrer noopener" target="_blank">open</a></td></tr>"#
            ),
            // a link that isn't https:// isn't drawn
            r#"<td>moved to junk</td><td class="nowrap" title="after the message's time, 2026-11-01 11:58:30 UTC">1h 1m</td><td></td></tr>"#,
            // a pending row: marked, no duration, its delivery as the target's tooltip
            &format!(
                r#"<tr class="pending"><td class="nowrap">2026-11-01 12:01:00</td><td title="&#60;m{HOSTILE_ESCAPED}@example.net&#62;|late@example.com">late@example.com</td><td>Vendor</td><td><span class="badge">pending</span> Watching</td><td class="nowrap"></td><td></td></tr>"#
            ),
            &format!(
                r#"<a href="/remediations/targets?alert={}">Find this alert's remediation targets</a>"#,
                tree.alert.summary.id
            ),
        ],
    );
    assert!(!page.contains("javascript:"), "{page}");

    // rows with no badge (every target had nothing to remove) still draw the panel
    let explained = RemediationTimeline {
        events: vec![event(
            "fwd@example.com",
            "Remove (not delivered to this address; forwarded to another mailbox)",
            "2026-11-01T12:00:50Z",
        )],
        ..RemediationTimeline::default()
    };
    let page = AlertPage::with(
        Layout::new("n0nce", Theme::Light, Some("alice".to_owned()), "/alerts/x"),
        &tree,
        &comments,
        &ObservableActions::empty(),
        &std::collections::BTreeMap::new(),
        PageOptions {
            remediation: Some(&explained),
            ..PageOptions::default()
        },
    )
    .expect("a page")
    .render()
    .expect("renders");
    assert!(
        page.contains(r#"<summary>Remediation <span class="hint">(1 event)</span></summary>"#),
        "{page}"
    );
    // a timeline with rows opens its panel (the owner, 2026-11-21), unless the analyst closed it
    assert!(
        page.contains(r#"id="remediation" data-section-id="remediation" open>"#),
        "{page}"
    );
    let closed = AlertPage::with(
        Layout::new("n0nce", Theme::Light, Some("alice".to_owned()), "/alerts/x"),
        &tree,
        &comments,
        &ObservableActions::empty(),
        &std::collections::BTreeMap::from([("remediation".to_owned(), false)]),
        PageOptions {
            remediation: Some(&explained),
            ..PageOptions::default()
        },
    )
    .expect("a page")
    .render()
    .expect("renders");
    assert!(
        closed.contains(r#"id="remediation" data-section-id="remediation">"#),
        "{closed}"
    );
    // nothing remediated: no panel
    let page = AlertPage::with(
        Layout::new("n0nce", Theme::Light, Some("alice".to_owned()), "/alerts/x"),
        &tree,
        &comments,
        &ObservableActions::empty(),
        &std::collections::BTreeMap::new(),
        PageOptions {
            remediation: Some(&RemediationTimeline::default()),
            ..PageOptions::default()
        },
    )
    .expect("a page")
    .render()
    .expect("renders");
    assert!(!page.contains(r#"id="remediation""#), "{page}");
}

/// Through the server: a viewer with `remediation:read` has the alert's timeline from the database,
/// one without it the page with no panel, and an alert with nothing remediated has none.
#[tokio::test]
async fn the_alert_page_shows_its_timeline_to_whoever_reads_remediations() {
    let stack = stack().await;
    let alert = list_alert(&stack, "a phish", "2026-11-01T10:00:00Z", None).await;
    let quiet = list_alert(&stack, "nothing removed", "2026-11-01T10:00:00Z", None).await;
    let db = stack.test_db.db();
    let mut tx = db.begin().await.expect("begins");
    for value in ["<m@x>|alias@example.com", "<m@x>|owner@example.com"] {
        ace_core::tree::upsert_observable(
            &mut tx,
            alert,
            &ace_results::NewObservable::new(ace_results::ObservableKind::EmailDelivery, value),
        )
        .await
        .expect("adds");
    }
    tx.commit().await.expect("commits");
    let removal: i64 = sqlx::query_scalar(
        "INSERT INTO queue.actions (kind, handler, observable_type, observable_value, action, status, result)
         VALUES ('remediation', 'test', 'email_delivery', '<m@x>|alias@example.com', 'remove', 'COMPLETED', 'SUCCESS')
         RETURNING id",
    )
    .fetch_one(db.pool())
    .await
    .expect("a removal");
    sqlx::query(
        "INSERT INTO queue.action_attempts (action_id, status, result, message, resolved_target)
         VALUES ($1, 'COMPLETED', 'SUCCESS', 'alias@example.com is an alias of owner@example.com: removed',
                 'owner@example.com')",
    )
    .bind(removal)
    .execute(db.pool())
    .await
    .expect("a try");

    let reader = user(&stack, "reader").await;
    grant_to(&stack, &reader, "alert", "read").await;
    grant_to(&stack, &reader, "remediation", "read").await;
    let viewer = user(&stack, "viewer").await;
    grant_to(&stack, &viewer, "alert", "read").await;
    let (rd, vw) = (
        session_of(&stack, "reader").await,
        session_of(&stack, "viewer").await,
    );
    let get =
        |session: &str, path: String| stack.get(&path).header("cookie", cookie(session)).send();
    let shown = get(&rd, format!("/alerts/{alert}"))
        .await
        .expect("answered");
    assert_eq!(shown.status(), StatusCode::OK);
    let shown: String = shown
        .text()
        .await
        .expect("a page")
        .lines()
        .map(str::trim)
        .collect();
    contains_all(
        &shown,
        &[
            r#"<details class="section remediation" id="remediation" data-section-id="remediation" open>"#,
            r#"<span class="hint">(1 event)</span>"#,
            "<td>alias@example.com → owner@example.com</td><td>ACE</td><td title=\"alias@example.com is an alias of owner@example.com: removed\">Remove (Success) via owner@example.com</td>",
            &format!(r#"<a href="/remediations/{removal}">history</a>"#),
        ],
    );
    // without remediation:read the page has no panel
    let hidden = get(&vw, format!("/alerts/{alert}"))
        .await
        .expect("answered");
    assert_eq!(hidden.status(), StatusCode::OK);
    let hidden = hidden.text().await.expect("a page");
    assert!(!hidden.contains(r#"id="remediation""#), "{hidden}");
    assert!(!hidden.contains("Remove (Success)"), "{hidden}");
    // nothing remediated: no panel
    let none = get(&rd, format!("/alerts/{quiet}"))
        .await
        .expect("answered");
    assert_eq!(none.status(), StatusCode::OK);
    let none = none.text().await.expect("a page");
    assert!(!none.contains(r#"id="remediation""#), "{none}");
}

// PLAN.md 7.14: an alert's detection verdicts on its page.

use ace_gui::verdicts::VerdictsView;
use ace_service::{DetectionPoint, Verdict, VerdictSource};

fn verdict_fixture(
    id: i64,
    description: &str,
    verdict: Option<(Verdict, VerdictSource)>,
    stored: Option<Verdict>,
) -> DetectionPoint {
    DetectionPoint {
        id,
        alert: uuid::Uuid::from_u128(0x5800),
        observable: (id % 2 == 1).then(|| (id, "fqdn".to_owned(), format!("{HOSTILE}.example"))),
        module: None,
        description: description.to_owned(),
        details: None,
        queue: None,
        signature_uuid: None,
        signature_version: None,
        signature_family: None,
        created_at: chrono::DateTime::from_timestamp(1_790_000_000, 0).expect("a time"),
        verdict: verdict.map(|(v, _)| v),
        verdict_source: verdict.map(|(_, s)| s),
        override_verdict: stored,
        override_by: stored.map(|_| RecordedActor {
            kind: "user".to_owned(),
            id: "u".to_owned(),
            name: Some(HOSTILE.to_owned()),
        }),
        override_set_at: stored
            .map(|_| chrono::DateTime::from_timestamp(1_790_000_100, 0).expect("a time")),
    }
}

/// The list drawn directly: ace3's badges, its menu only where it applies, hostile text escaped, and on an
/// alert that doesn't take verdicts, why instead of the forms.
#[test]
fn the_verdicts_view_draws_ace3_s_badges_and_menu() {
    let alert = uuid::Uuid::from_u128(0x5800);
    let detections = [
        verdict_fixture(
            1,
            HOSTILE,
            Some((Verdict::Fp, VerdictSource::Explicit)),
            Some(Verdict::Fp),
        ),
        verdict_fixture(
            2,
            "kit",
            Some((Verdict::Tp, VerdictSource::InheritedMulti)),
            None,
        ),
        verdict_fixture(
            3,
            "confirmed",
            Some((Verdict::Tp, VerdictSource::Explicit)),
            Some(Verdict::Tp),
        ),
    ];
    let (tree, comments) = fixture_tree();
    let layout = Layout::signed_out("nonce");
    let view = VerdictsView::new(alert, &detections, None, true, false);
    assert_eq!(view.unconfirmed, 1);
    let page = AlertPage::new(
        layout.clone(),
        &tree,
        &comments,
        &ObservableActions::empty(),
        &std::collections::BTreeMap::new(),
    )
    .expect("a page")
    .with_verdicts(view);
    let html = drawn_safely(&page);
    assert!(!html.contains(HOSTILE), "{html}");
    contains_all(
        &html,
        &[
            r#"<details class="section verdicts" id="detections" data-section-id="detections">"#,
            r#"<summary>Detection Verdicts (3) <span class="hint">3 detections · 2 TP · 1 FP · 1 unconfirmed</span></summary>"#,
            &format!("<td>{HOSTILE_ESCAPED}</td>"),
            &format!(r#"<td class="muted">fqdn: {HOSTILE_ESCAPED}.example</td>"#),
            r#"<span class="badge verdict-fp" title="set by an analyst">FP · explicit</span>"#,
            &format!(
                r#"<span class="muted">FP stored by {HOSTILE_ESCAPED} at 2026-09-21 14:15:00 UTC</span>"#
            ),
            r#"<span class="badge verdict-tp" title="inherited from the alert&#39;s disposition, on an alert where several signatures fired; nobody has confirmed it">TP · unconfirmed</span>"#,
            r#"<td class="muted">the alert</td>"#,
            &format!(
                r#"<form method="post" action="/alerts/{alert}/detections/2/verdict" class="inline">"#
            ),
            &format!(
                r#"<form method="post" action="/alerts/{alert}/detections/confirm" class="inline">"#
            ),
            "Confirm the others as TP (1)",
        ],
    );
    let forms = |id: i64| {
        let start = html.find(&format!(r#"<tr id="d{id}">"#)).expect("its row");
        let row = &html[start..start + html[start..].find("</tr>").expect("its end")];
        ["fp", "tp", "inherit"]
            .into_iter()
            .filter(|value| row.contains(&format!(r#"name="verdict" value="{value}""#)))
            .collect::<Vec<_>>()
    };
    // ace3's menu: no "noise" on an explicit FP, no "confirm" on an explicit TP, "inherit" only when stored
    assert_eq!(forms(1), ["tp", "inherit"]);
    assert_eq!(forms(2), ["fp", "tp"]);
    assert_eq!(forms(3), ["fp", "inherit"]);

    // an FP alert, or a viewer without alert:write: the badges and no forms
    let why = "every detection on a false positive alert is FP; if the alert was wrong, correct its disposition";
    for (refusal, can_write) in [(Some(why.to_owned()), true), (None, false)] {
        let view = VerdictsView::new(alert, &detections, refusal.clone(), can_write, true);
        let page = AlertPage::new(
            layout.clone(),
            &tree,
            &comments,
            &ObservableActions::empty(),
            &std::collections::BTreeMap::new(),
        )
        .expect("a page")
        .with_verdicts(view);
        let html = page.render().expect("renders");
        assert!(!html.contains(r#"name="verdict""#), "{html}");
        assert!(!html.contains("/detections/confirm"), "{html}");
        assert!(
            html.contains(
                r#"<summary>Detection Verdicts (3+) <span class="hint">3+ detections · "#
            ),
            "{html}"
        );
        assert!(html.contains("more detections than this list shows"));
        assert_eq!(
            html.contains("correct its disposition"),
            refusal.is_some(),
            "{html}"
        );
    }
}

/// A detection of `root`, of `signature`, on its first observable, or on the alert itself.
async fn gui_detection(stack: &Stack, root: uuid::Uuid, on_root: bool, signature: &str) -> i64 {
    let db = stack.test_db.db().pool();
    sqlx::query_scalar(
        "INSERT INTO analysis.detections (root_id, observable_id, description, signature_uuid)
         SELECT $1, CASE WHEN $2 THEN NULL ELSE (SELECT min(id) FROM analysis.observables WHERE root_id = $1) END,
                'a <b>generic</b> rule', $3
         RETURNING id",
    )
    .bind(root)
    .bind(on_root)
    .bind(signature)
    .fetch_one(db)
    .await
    .expect("a detection")
}

async fn gui_disposition(stack: &Stack, root: uuid::Uuid, disposition: &str) {
    sqlx::query(
        "UPDATE analysis.roots SET disposition = $2,
             dispositioned_by = '{\"kind\": \"internal\", \"id\": \"test\"}' WHERE id = $1",
    )
    .bind(root)
    .bind(disposition)
    .execute(stack.test_db.db().pool())
    .await
    .expect("dispositions");
}

async fn gui_verdicts(stack: &Stack, root: uuid::Uuid) -> Vec<(i64, String)> {
    sqlx::query_as(
        "SELECT detection_id, verdict FROM analysis.detection_verdicts WHERE root_id = $1 ORDER BY 1",
    )
    .bind(root)
    .fetch_all(stack.test_db.db().pool())
    .await
    .expect("reads")
}

/// Through the server: the page lists the verdicts under `alert:read`, offers the forms to a holder of
/// `alert:write`, and each form is one audited write from this site only; a refusal changes nothing.
#[tokio::test]
async fn detection_verdicts_are_set_through_the_alert_page() {
    let stack = stack().await;
    let alice = user(&stack, "alice").await;
    grant_alert_read(&stack, &alice).await;
    let carol = user(&stack, "carol").await;
    grant_alert_read(&stack, &carol).await;
    grant_to(&stack, &carol, "alert", "write").await;
    let _bob = user(&stack, "bob").await;
    let (root, _) = splunk_alert(&stack).await;
    let first = gui_detection(&stack, root, false, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").await;
    let second = gui_detection(&stack, root, true, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").await;
    gui_disposition(&stack, root, "DELIVERY").await;
    let (alice_session, carol_session, bob_session) = (
        session_of(&stack, "alice").await,
        session_of(&stack, "carol").await,
        session_of(&stack, "bob").await,
    );
    let page_for = |session: &str| {
        let request = stack
            .get(&format!("/alerts/{root}"))
            .header("cookie", cookie(session));
        async move {
            let response = request.send().await.expect("answered");
            (response.status(), response.text().await.expect("a page"))
        }
    };
    let (status, page) = page_for(&alice_session).await;
    assert_eq!(status, StatusCode::OK);
    assert!(inline_free(&page));
    assert!(page.contains("TP · unconfirmed"), "{page}");
    assert!(
        page.contains("a &#60;b&#62;generic&#60;/b&#62; rule"),
        "{page}"
    );
    assert!(!page.contains(r#"name="verdict""#), "a reader has no forms");
    let (_, page) = page_for(&carol_session).await;
    let path = format!("/alerts/{root}/detections/{first}/verdict");
    assert!(
        page.contains(&format!(
            r#"<form method="post" action="{path}" class="inline">"#
        )),
        "{page}"
    );

    // alice can read but not grade
    let audits = stack.audit_count().await;
    let refused = stack
        .post(&path, &[("verdict", "fp")])
        .header("cookie", cookie(&alice_session))
        .send()
        .await
        .expect("answered");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(stack.audit_count().await, audits);

    let marked = stack
        .post(&path, &[("verdict", "fp")])
        .header("cookie", cookie(&carol_session))
        .send()
        .await
        .expect("answered");
    assert_eq!(marked.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&marked), format!("/alerts/{root}#detections"));
    assert_eq!(stack.audit_count().await, audits + 1);
    assert_eq!(gui_verdicts(&stack, root).await, [(first, "fp".to_owned())]);
    let (_, page) = page_for(&carol_session).await;
    assert!(page.contains("FP · explicit"), "{page}");
    assert!(page.contains("FP stored by carol at "), "{page}");
    let confirmed = stack
        .post(&format!("/alerts/{root}/detections/confirm"), &[])
        .header("cookie", cookie(&carol_session))
        .send()
        .await
        .expect("answered");
    assert_eq!(confirmed.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        gui_verdicts(&stack, root).await,
        [(first, "fp".to_owned()), (second, "tp".to_owned())]
    );
    let inherited = stack
        .post(&path, &[("verdict", "inherit")])
        .header("cookie", cookie(&carol_session))
        .send()
        .await
        .expect("answered");
    assert_eq!(inherited.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        gui_verdicts(&stack, root).await,
        [(second, "tp".to_owned())]
    );
    assert_eq!(stack.audit_count().await, audits + 3);

    // a verdict that isn't one, a form that isn't one, no such detection, another site, no session
    let audits = stack.audit_count().await;
    for (form, status) in [
        (vec![("verdict", "maybe")], StatusCode::BAD_REQUEST),
        (vec![("other", "x")], StatusCode::BAD_REQUEST),
    ] {
        let response = stack
            .post(&path, &form)
            .header("cookie", cookie(&carol_session))
            .send()
            .await
            .expect("answered");
        assert_eq!(response.status(), status, "{form:?}");
    }
    for missing in [
        format!("/alerts/{root}/detections/999999999/verdict"),
        format!("/alerts/{root}/detections/x/verdict"),
        format!("/alerts/x/detections/{first}/verdict"),
        format!("/alerts/{}/detections/{first}/verdict", uuid::Uuid::nil()),
    ] {
        let response = stack
            .post(&missing, &[("verdict", "fp")])
            .header("cookie", cookie(&carol_session))
            .send()
            .await
            .expect("answered");
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{missing}");
    }
    let cross_site = stack
        .post(&path, &[("verdict", "fp")])
        .header("cookie", cookie(&carol_session))
        .header("sec-fetch-site", "cross-site")
        .send()
        .await
        .expect("answered");
    assert_eq!(cross_site.status(), StatusCode::FORBIDDEN);
    let anonymous = stack
        .post(&path, &[("verdict", "fp")])
        .send()
        .await
        .expect("answered");
    assert_eq!(anonymous.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&anonymous), "/login");
    let (status, _) = page_for(&bob_session).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "bob can't read the alert");

    // an FP alert: the page says why, and a form posted anyway is refused
    gui_disposition(&stack, root, "FALSE_POSITIVE").await;
    let (_, page) = page_for(&carol_session).await;
    assert!(page.contains("correct its disposition"), "{page}");
    assert!(!page.contains(r#"name="verdict""#));
    let refused = stack
        .post(&path, &[("verdict", "fp")])
        .header("cookie", cookie(&carol_session))
        .send()
        .await
        .expect("answered");
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    let refused = stack
        .post(&format!("/alerts/{root}/detections/confirm"), &[])
        .header("cookie", cookie(&carol_session))
        .send()
        .await
        .expect("answered");
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    assert_eq!(stack.audit_count().await, audits);
}

// ---- the signatures area's samples (PLAN.md 7.10 batch 2) ----

use ace_gui::svs_samples::{
    ConfirmDeletePage, DeleteView, DeletedPage, SamplePage, SamplesPage, sample_href, sample_row,
    sample_view, samples_view,
};
use ace_service::{
    CaptureState, MissingCount, MissingReason, Sample, SampleCapture, SampleDetail,
    SampleDetection, SampleLabel, SampleQuery, SampleVotes, VoteStrength,
};

const SVS_SHA: &str = "abababababababababababababababababababababababababababababababab";
const SVS_RULE: &str = "7d1c2a4e-5b6f-4c3d-9e8f-0a1b2c3d4e5f";

fn fixture_sample(label: Option<SampleLabel>) -> Sample {
    let at = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("a time");
    Sample {
        sha256: SVS_SHA.to_owned(),
        rule_uuid: SVS_RULE.to_owned(),
        rule_name: HOSTILE.to_owned(),
        namespace: Some(HOSTILE.to_owned()),
        file_path: HOSTILE.to_owned(),
        file_size: Some(2048),
        capture_count: 2,
        stored: 1,
        missing: 1,
        missing_data: 1,
        unknown_version: 1,
        first_captured: at,
        last_captured: at,
        updated_at: at,
        latest_capture_id: 2,
        label,
        label_source: label.map(|_| VoteStrength::InheritedMulti),
        votes: SampleVotes {
            tp_inherited_multi: 1,
            ..SampleVotes::default()
        },
        retired: true,
        retired_by: Some(RecordedActor {
            kind: "user".to_owned(),
            id: "x".to_owned(),
            name: Some(HOSTILE.to_owned()),
        }),
        retired_at: Some(at),
        retired_reason: Some(HOSTILE.to_owned()),
    }
}

fn fixture_detail(refusal: Option<&str>) -> SampleDetail {
    let at = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("a time");
    let alert = uuid::Uuid::from_u128(7);
    SampleDetail {
        sample: fixture_sample(Some(SampleLabel::Tp)),
        captures: vec![SampleCapture {
            id: 2,
            alert,
            observable: Some(3),
            rule_name: HOSTILE.to_owned(),
            namespace: None,
            signature_version: HOSTILE.to_owned(),
            rule_content_hash: None,
            file_path: HOSTILE.to_owned(),
            file_size: Some(10),
            yara_meta_tags: vec![HOSTILE.to_owned()],
            state: CaptureState::Stored,
            missing_reason: Some(MissingReason::MatchRecord),
            has_record: true,
            match_summary: Some(serde_json::json!({"string_match_count": 3})),
            yara_version: Some("1".to_owned()),
            created_at: at,
            stored_at: Some(at),
            updated_at: at,
            detections: vec![SampleDetection {
                detection: 9,
                verdict: Some(Verdict::Tp),
                verdict_source: Some(VerdictSource::InheritedMulti),
                override_verdict: None,
                override_by: None,
                override_set_at: None,
            }],
        }],
        relabel_refusal: refusal.map(str::to_owned),
    }
}

/// The samples views, called directly: the list with its filters, sorts, pages, exports and missing
/// counts, a sample with its captures and the forms its viewer may use, the deletion's confirm and its
/// answer, each with hostile text escaped and nothing inline.
#[test]
fn the_samples_views_draw_samples_captures_and_deletions() {
    let layout = || {
        Layout::new(
            "n",
            Theme::default(),
            Some("analyst".to_owned()),
            "/signatures",
        )
    };
    assert_eq!(
        sample_href(SVS_SHA, "a b/c"),
        format!("/signatures/samples/{SVS_SHA}/a%20b%2Fc")
    );
    let query = SampleQuery {
        filters: vec![FilterEntry::text("Label", false, &["tp"])],
        ..SampleQuery::default()
    };
    let missing = [MissingCount {
        rule_uuid: SVS_RULE.to_owned(),
        rule_name: HOSTILE.to_owned(),
        reason: MissingReason::File,
        count: 4,
    }];
    let samples = [
        fixture_sample(Some(SampleLabel::Conflicted)),
        fixture_sample(None),
    ];
    let view = samples_view(
        &query,
        vec!["label:tp".to_owned()],
        &samples,
        Some("c1"),
        Some("c2"),
        true,
        &missing,
    );
    let page = drawn_safely(&SamplesPage {
        quick: Default::default(),
        layout: layout(),
        view,
    });
    assert!(
        page.contains(r#"value="tp" placeholder="tp, fp, conflicted, none""#),
        "{page}"
    );
    assert!(
        page.contains(r#"<span class="badge disposition-warning""#),
        "{page}"
    );
    assert!(
        page.contains(r#"<span class="muted">none</span>"#),
        "{page}"
    );
    assert!(page.contains(r#"<span class="badge disposition-secondary">retired</span>"#));
    assert!(page.contains(r#"<a href="/signatures/samples?f=label%3Atp&#38;sort=last_captured&#38;desc=true">First</a>"#), "{page}");
    assert!(page.contains(r#"cursor=c2" rel="next">Next</a>"#), "{page}");
    assert!(
        page.contains(r#"href="/api/svs/v1/samples/export/csv?f=label%3Atp"#),
        "{page}"
    );
    assert!(page.contains(r#"<a href="/api/svs/v1/samples/download?f=label%3Atp" title="password: infected">Download files</a>"#), "{page}");
    assert!(page.contains("<h2>Captures missing something</h2>"));
    let plain = samples_view(&query, Vec::new(), &[], None, None, false, &[]);
    let page = drawn_safely(&SamplesPage {
        quick: Default::default(),
        layout: layout(),
        view: plain,
    });
    assert!(page.contains("No samples."));
    assert!(
        !page.contains("Download files") && !page.contains("Next"),
        "{page}"
    );

    // a sample: a reader sees no forms
    let detail = fixture_detail(None);
    let page = drawn_safely(&SamplePage {
        layout: layout(),
        view: sample_view(&detail, false, false, false, None),
    });
    for absent in [
        r#"<form method="post" action="/signatures/samples"#,
        "Download the file",
        "Delete this file",
    ] {
        assert!(!page.contains(absent), "{absent}: {page}");
    }
    assert!(page.contains(r#"<a href="/api/svs/v1/samples/captures/2/record">Match record</a>"#));
    assert!(page.contains(r#"<a href="/alerts/00000000-0000-0000-0000-000000000007">"#));
    assert!(
        page.contains(r#"<span class="badge verdict-tp">tp</span> inherited_multi"#),
        "{page}"
    );
    // alert:write: the label forms, Confirm with an unconfirmed detection; svs:admin and download too
    let page = drawn_safely(&SamplePage {
        layout: layout(),
        view: sample_view(&detail, true, true, true, Some("relabeled")),
    });
    let href = sample_href(SVS_SHA, SVS_RULE);
    for form in [
        format!(
            r#"<form method="post" action="{href}/label" class="inline"><input type="hidden" name="verdict" value="fp">"#
        ),
        format!(r#"<form method="post" action="{href}/confirm" class="inline">"#),
        format!(r#"<form method="post" action="{href}/unretire" class="inline">"#),
        format!(r#"<a href="/signatures/samples/{SVS_SHA}/delete">"#),
        format!(r#"<a href="/api/svs/v1/samples/{SVS_SHA}/{SVS_RULE}/download""#),
    ] {
        assert!(page.contains(&form), "{form}: {page}");
    }
    assert!(page.contains("have the verdict"), "{page}");
    // a relabel that would be refused shows why in place of its forms
    let refused = drawn_safely(&SamplePage {
        layout: layout(),
        view: sample_view(
            &fixture_detail(Some("every detection is <b>FP</b>")),
            true,
            false,
            false,
            None,
        ),
    });
    assert!(
        refused.contains("every detection is &#60;b&#62;FP&#60;/b&#62;"),
        "{refused}"
    );
    assert!(!refused.contains("/label\""), "{refused}");

    let confirm = drawn_safely(&ConfirmDeletePage {
        layout: layout(),
        view: DeleteView {
            sha256: SVS_SHA.to_owned(),
            action: format!("/signatures/samples/{SVS_SHA}/delete"),
            rows: vec![sample_row(&fixture_sample(None))],
            reason: HOSTILE.to_owned(),
            max_reason: 4000,
            problem: Some(HOSTILE.to_owned()),
        },
    });
    assert!(confirm.contains(&format!(
        r#"<form method="post" action="/signatures/samples/{SVS_SHA}/delete" class="fields">"#
    )));
    assert!(confirm.contains(r#"<p class="error" role="alert">Nothing was deleted: "#));
    let deleted = drawn_safely(&DeletedPage {
        layout: layout(),
        sha256: SVS_SHA.to_owned(),
        capture_count: 1,
        rules: HOSTILE.to_owned(),
        purged: false,
    });
    assert!(deleted.contains("couldn't be purged yet"), "{deleted}");
}

/// A sample in the GUI's database, as the core's capture leaves one: a DELIVERY alert's file with two
/// rules' detections, a stored capture of each, and the bytes in the samples' pool.
async fn gui_sample(stack: &Stack) -> uuid::Uuid {
    let db = stack.test_db.db();
    let root = ace_core::tree::NewRoot::new("correlation");
    let mut tx = db.begin().await.expect("begins");
    ace_core::tree::create_root(&mut tx, &root)
        .await
        .expect("creates");
    tx.commit().await.expect("commits");
    let observable: i64 = sqlx::query_scalar(
        "INSERT INTO analysis.observables (root_id, type, value) VALUES ($1, 'file', $2) RETURNING id",
    )
    .bind(root.id)
    .bind(SVS_SHA)
    .fetch_one(db.pool())
    .await
    .expect("a file");
    for rule in [SVS_RULE, "1e2d3c4b-5a69-4788-9a0b-1c2d3e4f5a6b"] {
        sqlx::query(
            "INSERT INTO analysis.detections (root_id, observable_id, description, signature_uuid)
             VALUES ($1, $2, 'matched', $3)",
        )
        .bind(root.id)
        .bind(observable)
        .bind(rule)
        .execute(db.pool())
        .await
        .expect("a detection");
        sqlx::query(
            "INSERT INTO svs.yara_captures (root_id, observable_id, sha256, rule_uuid, rule_name,
                                            signature_version, file_path, state, record, stored_at)
             VALUES ($1, $2, $3, $4, $5, 'c', $5, 'stored', '{}', now())",
        )
        .bind(root.id)
        .bind(observable)
        .bind(SVS_SHA)
        .bind(rule)
        .bind(HOSTILE)
        .execute(db.pool())
        .await
        .expect("a capture");
    }
    // the samples pool's index row, which a deletion purges; the bucket goes by the index
    sqlx::query("INSERT INTO store.objects (pool, sha256, size) VALUES ('svs_samples', $1, 1)")
        .bind(SVS_SHA)
        .execute(db.pool())
        .await
        .expect("an object");
    sqlx::query(
        "UPDATE analysis.roots SET alerted_at = now(), disposition = 'DELIVERY',
             dispositioned_by = '{\"kind\": \"internal\", \"id\": \"test\"}' WHERE id = $1",
    )
    .bind(root.id)
    .execute(db.pool())
    .await
    .expect("dispositions it");
    root.id
}

/// The samples pages through the server: signed out goes to the login; without `signature:read` each
/// page and post is 403; with it the list and the sample with no forms, and the errors; `alert:write` adds
/// the label forms, whose posts relabel and reset; `svs:admin` retires, unretires and deletes behind a
/// confirm; a post from another site is refused; and each write has its audit row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_samples_pages_need_signature_read_then_alert_write_and_svs_admin() {
    let cache = std::env::temp_dir().join(format!("ace-rs-gui-cache-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&cache).expect("a cache directory");
    let store = ace_store::Store::new(
        &ace_store::BucketConfig::from_env().expect("the ACE_RS_BUCKET_* variables"),
        ace_store::NodeCache::new(&cache, 1 << 30).expect("a cache"),
    )
    .await;
    let stack = stack_of_db(Catalog::new(vec![]), move |service, db| {
        let bucket = ace_core::bucket::Bucket::new(
            db.clone(),
            store,
            ace_core::bucket::BucketSettings::default(),
        );
        Gui::new(service.with_bucket(bucket), Transport::Plain)
    })
    .await;
    let alice = user(&stack, "alice").await;
    gui_sample(&stack).await;
    let sample = sample_href(SVS_SHA, SVS_RULE);

    for path in ["/signatures/samples".to_owned(), sample.clone()] {
        let page = stack.get(&path).send().await.expect("answered");
        assert_eq!(page.status(), StatusCode::SEE_OTHER, "{path}");
        assert!(location(&page).starts_with("/login?next="), "{path}");
    }
    let session = session_of(&stack, "alice").await;
    let get = |path: String| stack.get(&path).header("cookie", cookie(&session)).send();
    let post = |path: String, form: Vec<(&'static str, &'static str)>| {
        stack
            .post(&path, &form)
            .header("cookie", cookie(&session))
            .send()
    };
    for path in [
        "/signatures/samples".to_owned(),
        sample.clone(),
        format!("/signatures/samples/{SVS_SHA}/delete"),
    ] {
        let page = get(path.clone()).await.expect("answered");
        assert_eq!(page.status(), StatusCode::FORBIDDEN, "{path}");
    }
    let refused = post(format!("{sample}/label"), vec![("verdict", "fp")])
        .await
        .expect("answered");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);

    // signature:read: the pages, with no forms
    grant_to(&stack, &alice, "signature", "read").await;
    let audit = stack.audit_count().await;
    let hub = get("/signatures".to_owned())
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(
        hub.contains(r#"<a href="/signatures/samples"><b>Samples</b>"#),
        "{hub}"
    );
    let list = get("/signatures/samples".to_owned())
        .await
        .expect("answered");
    assert_eq!(list.status(), StatusCode::OK);
    let list = list.text().await.expect("a page");
    assert!(list.contains(&format!(r#"<a href="{sample}">"#)), "{list}");
    assert!(!list.contains("<script>alert"), "{list}");
    assert!(!list.contains("Download files"), "{list}");
    let page = get(sample.clone()).await.expect("answered");
    assert_eq!(page.status(), StatusCode::OK);
    let page = page.text().await.expect("a page");
    assert!(
        !page.contains(r#"<form method="post" action="/signatures/samples"#)
            && !page.contains("<script>alert"),
        "{page}"
    );
    // the filter form folds into a share link
    let folded = get("/signatures/samples?label=tp&sort=rule&desc=false".to_owned())
        .await
        .expect("answered");
    assert_eq!(folded.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&folded),
        "/signatures/samples?f=label%3Atp&sort=rule&desc=false"
    );
    for (path, status) in [
        (
            "/signatures/samples?sort=size".to_owned(),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/signatures/samples?f=label%3Amaybe".to_owned(),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/signatures/samples?cursor=nope".to_owned(),
            StatusCode::BAD_REQUEST,
        ),
        (
            format!("/signatures/samples/zz/{SVS_RULE}"),
            StatusCode::BAD_REQUEST,
        ),
        (sample_href(SVS_SHA, "no-such-rule"), StatusCode::NOT_FOUND),
        // the confirm needs svs:admin before anything else
        (
            format!("/signatures/samples/{SVS_SHA}/delete"),
            StatusCode::FORBIDDEN,
        ),
    ] {
        assert_eq!(
            get(path.clone()).await.expect("answered").status(),
            status,
            "{path}"
        );
    }
    for (path, form) in [
        (format!("{sample}/label"), vec![("verdict", "fp")]),
        (format!("{sample}/retire"), vec![("reason", "stale")]),
        (format!("{sample}/unretire"), vec![]),
        (
            format!("/signatures/samples/{SVS_SHA}/delete"),
            vec![("reason", "x")],
        ),
    ] {
        let refused = post(path.clone(), form).await.expect("answered");
        assert_eq!(refused.status(), StatusCode::FORBIDDEN, "{path}");
    }
    // the samples page seeded alice's quick filters when it was first drawn, which is the one row
    assert_eq!(last_action(&stack).await, "seed_saved_filters");
    assert_eq!(stack.audit_count().await, audit + 1, "no refusal has a row");

    // alert:write: the label forms and their posts
    grant_to(&stack, &alice, "alert", "write").await;
    let audit = stack.audit_count().await;
    let page = get(sample.clone())
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(
        page.contains(&format!(r#"action="{sample}/label""#)),
        "{page}"
    );
    assert!(
        page.contains(&format!(r#"action="{sample}/confirm""#)),
        "{page}"
    );
    assert!(
        !page.contains("/retire") && !page.contains("/delete"),
        "{page}"
    );
    let relabeled = post(format!("{sample}/label"), vec![("verdict", "fp")])
        .await
        .expect("answered");
    assert_eq!(relabeled.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&relabeled), format!("{sample}?done=relabeled"));
    let reset = post(format!("{sample}/label"), vec![("verdict", "reset")])
        .await
        .expect("answered");
    assert_eq!(location(&reset), format!("{sample}?done=reset"));
    let confirmed = post(format!("{sample}/confirm"), vec![])
        .await
        .expect("answered");
    assert_eq!(location(&confirmed), format!("{sample}?done=confirmed"));
    assert_eq!(stack.audit_count().await, audit + 3);
    let bad = post(format!("{sample}/label"), vec![("verdict", "maybe")])
        .await
        .expect("answered");
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
    // a post from another site is refused, and writes nothing
    let crossed = stack
        .http
        .post(format!("{}{sample}/label", stack.url))
        .header("cookie", cookie(&session))
        .header("origin", "https://evil.example")
        .form(&[("verdict", "tp")])
        .send()
        .await
        .expect("answered");
    assert_eq!(crossed.status(), StatusCode::FORBIDDEN);
    assert_eq!(stack.audit_count().await, audit + 3);

    // svs:admin: retire, unretire, and a deletion behind its confirm
    grant_to(&stack, &alice, "svs", "admin").await;
    let audit = stack.audit_count().await;
    let retired = post(format!("{sample}/retire"), vec![("reason", "stale")])
        .await
        .expect("answered");
    assert_eq!(location(&retired), format!("{sample}?done=retired"));
    let empty = post(format!("{sample}/retire"), vec![("reason", " ")])
        .await
        .expect("answered");
    assert_eq!(empty.status(), StatusCode::BAD_REQUEST);
    let unretired = post(format!("{sample}/unretire"), vec![])
        .await
        .expect("answered");
    assert_eq!(location(&unretired), format!("{sample}?done=unretired"));
    let confirm = get(format!("/signatures/samples/{SVS_SHA}/delete"))
        .await
        .expect("answered");
    assert_eq!(confirm.status(), StatusCode::OK);
    let confirm = confirm.text().await.expect("a page");
    assert!(
        confirm.contains(&format!("<h1>Delete <code>{SVS_SHA}</code> from SVS?</h1>")),
        "{confirm}"
    );
    let again = post(
        format!("/signatures/samples/{SVS_SHA}/delete"),
        vec![("reason", "")],
    )
    .await
    .expect("answered");
    assert_eq!(again.status(), StatusCode::BAD_REQUEST);
    assert!(
        again
            .text()
            .await
            .expect("a page")
            .contains("Nothing was deleted")
    );
    let deleted = post(
        format!("/signatures/samples/{SVS_SHA}/delete"),
        vec![("reason", "legal request")],
    )
    .await
    .expect("answered");
    assert_eq!(deleted.status(), StatusCode::OK);
    let deleted = deleted.text().await.expect("a page");
    assert!(deleted.contains("2 captures removed"), "{deleted}");
    assert_eq!(stack.audit_count().await, audit + 3);
    assert_eq!(
        get(sample.clone()).await.expect("answered").status(),
        StatusCode::NOT_FOUND
    );
    std::fs::remove_dir_all(&cache).expect("removes the cache");
}

// ---- the signatures area's validations (PLAN.md 7.10 batch 3) ----

use ace_gui::svs_validations::{
    ValidationPage, ValidationsPage, validation_href, validation_view, validations_view,
};
use ace_service::{
    Validation, ValidationDetail, ValidationQuery, ValidationResult, ValidationState,
};

fn fixture_validation(state: ValidationState) -> Validation {
    let at = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("a time");
    Validation {
        uuid: uuid::Uuid::from_u128(0x5a),
        repository: HOSTILE.to_owned(),
        base_sha: "a".repeat(40),
        head_sha: "b".repeat(40),
        branch: HOSTILE.to_owned(),
        pr_url: Some(format!("https://git.example/pr/{HOSTILE}")),
        state,
        requested_by: RecordedActor {
            kind: "api_key".to_owned(),
            id: "k".to_owned(),
            name: Some(HOSTILE.to_owned()),
        },
        created_at: at,
        started_at: Some(at),
        finished_at: Some(at),
        error: Some(HOSTILE.to_owned()),
        diffed: Some(true),
        regressions: Some(1),
        new_fps: Some(0),
        compile_errors: Some(1),
        counts: Some(
            [
                ("regression".to_owned(), 1),
                ("unchanged".to_owned(), 4),
                ("known_fp".to_owned(), 0),
            ]
            .into(),
        ),
        updated_at: at,
    }
}

fn fixture_result() -> ValidationResult {
    ValidationResult {
        id: 1,
        sha256: SVS_SHA.to_owned(),
        rule_uuid: SVS_RULE.to_owned(),
        rule_name: HOSTILE.to_owned(),
        namespace: Some(HOSTILE.to_owned()),
        label: Some("tp".to_owned()),
        label_source: Some("inherited_single".to_owned()),
        base: "match".to_owned(),
        head: "miss".to_owned(),
        raw_base: true,
        raw_head: true,
        category: "regression".to_owned(),
        note: Some(HOSTILE.to_owned()),
    }
}

/// A report as a worker stores one, with text from a rule repository in every field that can hold it.
fn fixture_report() -> serde_json::Value {
    serde_json::json!({
        "base": {"sha": "a".repeat(40), "namespaces": ["acme"], "rule_count": 2, "file_errors": [],
                 "not_loaded": [], "skipped_members": [], "warnings": [], "ruleset_error": null},
        "head": {"sha": "b".repeat(40), "namespaces": [HOSTILE], "rule_count": 1,
                 "file_errors": [{"file": HOSTILE, "namespace": "acme", "error": HOSTILE, "dropped": []}],
                 "not_loaded": [{"path": HOSTILE, "reason": HOSTILE}],
                 "skipped_members": [[HOSTILE, HOSTILE]], "warnings": [HOSTILE], "ruleset_error": HOSTILE},
        "added_rules": [{"uuid": "u", "name": HOSTILE, "file": HOSTILE}],
        "removed_rules": [], "changed_rules": [],
        "not_testable": [{"uuid": null, "name": HOSTILE, "file": HOSTILE, "reason": "no uuid"}],
        "full_path_rules": [],
        "skipped": [{"sha256": SVS_SHA, "file_path": HOSTILE, "reason": "unsafe_path", "detail": ""}],
        "files": 1, "units": 1, "samples": 1, "bytes": 10, "duration_seconds": 1.25,
    })
}

/// The validations views, called directly: the list with its filters, pages and exports, and a report with
/// its counts, both commits, the rules, what wasn't replayed and its rows, each with hostile text escaped
/// and nothing inline.
#[test]
fn the_validations_views_draw_validations_and_a_report() {
    let layout = || {
        Layout::new(
            "n",
            Theme::default(),
            Some("analyst".to_owned()),
            "/signatures",
        )
    };
    let validation = fixture_validation(ValidationState::Completed);
    let list = drawn_safely(&ValidationsPage {
        quick: Default::default(),
        layout: layout(),
        view: validations_view(
            &ValidationQuery::default(),
            vec!["state:completed".to_owned()],
            std::slice::from_ref(&validation),
            Some("c1"),
            Some("c2"),
        ),
    });
    let href = validation_href(validation.uuid);
    assert!(list.contains(&format!(r#"<a href="{href}">"#)), "{list}");
    assert!(
        list.contains(r#"<a href="/signatures/validations?f=state%3Acompleted">First</a>"#),
        "{list}"
    );
    assert!(list.contains(r#"<a href="/signatures/validations?f=state%3Acompleted&#38;cursor=c2" rel="next">Next</a>"#), "{list}");
    assert!(
        list.contains(r#"href="/api/svs/v1/yara/validations/export/csv?f=state%3Acompleted""#),
        "{list}"
    );
    assert!(
        list.contains(r#"<input type="text" id="filter-has_regressions""#),
        "{list}"
    );
    // a pull request that isn't http is no link
    let mut script = fixture_validation(ValidationState::Failed);
    script.pr_url = Some("javascript:alert(1)".to_owned());
    let refused = drawn_safely(&ValidationsPage {
        quick: Default::default(),
        layout: layout(),
        view: validations_view(&ValidationQuery::default(), vec![], &[script], None, None),
    });
    assert!(!refused.contains("javascript:"), "{refused}");
    assert!(refused.contains("disposition-danger"), "{refused}");

    let detail = ValidationDetail {
        validation,
        attempts: 1,
        claimed_by: Some(HOSTILE.to_owned()),
        corpus_version: Some("v".to_owned()),
        engine_fingerprint: Some("f".to_owned()),
        report: Some(fixture_report()),
    };
    let chosen = vec!["regression".to_owned()];
    let page = drawn_safely(&ValidationPage {
        layout: layout(),
        view: validation_view(
            &detail,
            &chosen,
            &[fixture_result()],
            None,
            Some("n1"),
            true,
        ),
    });
    assert!(page.contains(r#"<a href="/signatures/validations/00000000-0000-0000-0000-00000000005a?category=regression">regression</a>"#), "{page}");
    // a counted-only category has no rows to show, and a zero isn't listed
    assert!(
        page.contains("<td>unchanged</td>") && !page.contains("known_fp</td><td>0"),
        "{page}"
    );
    assert!(
        page.contains(&format!(
            r#"<a href="/signatures/samples/{SVS_SHA}/{SVS_RULE}">"#
        )),
        "{page}"
    );
    assert!(
        page.contains(r#"<option value="regression" selected>regression</option>"#),
        "{page}"
    );
    assert!(page.contains(r#"href="/api/svs/v1/yara/validations/00000000-0000-0000-0000-00000000005a/download?category=regression""#), "{page}");
    // ace3's Export links: the chosen categories' rows, every one of them, from the API
    assert!(
        page.contains(r#"Export the chosen categories' rows as <a href="/api/svs/v1/yara/validations/00000000-0000-0000-0000-00000000005a/results/export/csv?category=regression">CSV</a> or <a href="/api/svs/v1/yara/validations/00000000-0000-0000-0000-00000000005a/results/export/ndjson?category=regression">NDJSON</a>"#),
        "{page}"
    );
    assert!(page.contains("The ruleset would not load"), "{page}");
    assert!(page.contains("miss (matches, no detection)"), "{page}");
    assert!(
        page.contains("1 files, 1 scans, 1 samples, 10 bytes, in 1.2s"),
        "{page}"
    );
    assert!(page.contains(r#"rel="next">Next</a>"#), "{page}");
    // without signature:download, no download
    let plain = drawn_safely(&ValidationPage {
        layout: layout(),
        view: validation_view(&detail, &[], &[fixture_result()], None, None, false),
    });
    assert!(!plain.contains("/download"), "{plain}");
    // a queued validation has no report yet
    let queued = ValidationDetail {
        validation: fixture_validation(ValidationState::Queued),
        attempts: 0,
        claimed_by: None,
        corpus_version: None,
        engine_fingerprint: None,
        report: None,
    };
    let waiting = drawn_safely(&ValidationPage {
        layout: layout(),
        view: validation_view(&queued, &[], &[], None, None, true),
    });
    assert!(
        waiting.contains("No rows.") && !waiting.contains("/download"),
        "{waiting}"
    );
    assert!(
        waiting.contains(r#"Export every row as <a href="/api/svs/v1/yara/validations/"#)
            && waiting.contains(r#"/results/export/ndjson">NDJSON</a>"#),
        "{waiting}"
    );
}

/// A completed validation in the GUI's database with a hostile report and one row.
async fn gui_validation(stack: &Stack) -> uuid::Uuid {
    let db = stack.test_db.db();
    let uuid = uuid::Uuid::new_v4();
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO svs.validations
             (uuid, repository, base_sha, head_sha, branch, requested_by, state, claimed_by, attempts,
              started_at, finished_at, counts, report, regressions, new_fps, compile_errors, diffed)
         VALUES ($1, 'rules', repeat('a', 40), repeat('b', 40), $2,
                 '{\"kind\": \"internal\", \"id\": \"test\"}', 'completed', 'node1', 1, now(), now(),
                 '{\"regression\": 1}', $3, 1, 0, 1, true)
         RETURNING id",
    )
    .bind(uuid)
    .bind(HOSTILE)
    .bind(fixture_report())
    .fetch_one(db.pool())
    .await
    .expect("a validation");
    sqlx::query(
        "INSERT INTO svs.validation_results
             (validation_id, sha256, rule_uuid, rule_name, base, head, raw_base, raw_head, category, note)
         VALUES ($1, $2, $3, $4, 'match', 'miss', true, false, 'regression', $4)",
    )
    .bind(id)
    .bind(SVS_SHA)
    .bind(SVS_RULE)
    .bind(HOSTILE)
    .execute(db.pool())
    .await
    .expect("a row");
    uuid
}

/// The validations pages through the server: signed out goes to the login; without `signature:read` each
/// is 403; with it the hub's tile, the list and a report, its rows and their errors; the filter form folds
/// into a share link; and `signature:download` adds the download of the rows' files.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_validations_pages_need_signature_read() {
    let stack = stack_of_db(Catalog::new(vec![]), |service, _| {
        Gui::new(service, Transport::Plain)
    })
    .await;
    let alice = user(&stack, "alice").await;
    let uuid = gui_validation(&stack).await;
    let report = validation_href(uuid);

    for path in ["/signatures/validations".to_owned(), report.clone()] {
        let page = stack.get(&path).send().await.expect("answered");
        assert_eq!(page.status(), StatusCode::SEE_OTHER, "{path}");
        assert!(location(&page).starts_with("/login?next="), "{path}");
    }
    let session = session_of(&stack, "alice").await;
    let get = |path: String| stack.get(&path).header("cookie", cookie(&session)).send();
    for path in ["/signatures/validations".to_owned(), report.clone()] {
        assert_eq!(
            get(path.clone()).await.expect("answered").status(),
            StatusCode::FORBIDDEN,
            "{path}"
        );
    }

    grant_to(&stack, &alice, "signature", "read").await;
    let hub = get("/signatures".to_owned())
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(
        hub.contains(r#"<a href="/signatures/validations"><b>Validations</b>"#),
        "{hub}"
    );
    let list = get("/signatures/validations".to_owned())
        .await
        .expect("answered");
    assert_eq!(list.status(), StatusCode::OK);
    let list = list.text().await.expect("a page");
    assert!(list.contains(&format!(r#"<a href="{report}">"#)), "{list}");
    assert!(!list.contains("<script>alert"), "{list}");
    let page = get(report.clone()).await.expect("answered");
    assert_eq!(page.status(), StatusCode::OK);
    let page = page.text().await.expect("a page");
    assert!(
        page.contains(&format!(
            r#"<a href="/signatures/samples/{SVS_SHA}/{SVS_RULE}">"#
        )),
        "{page}"
    );
    assert!(
        !page.contains("<script>alert") && !page.contains("/download"),
        "{page}"
    );
    let folded = get("/signatures/validations?state=completed".to_owned())
        .await
        .expect("answered");
    assert_eq!(folded.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&folded),
        "/signatures/validations?f=state%3Acompleted"
    );
    let filtered = get("/signatures/validations?f=state%3Afailed".to_owned())
        .await
        .expect("answered");
    assert!(
        filtered
            .text()
            .await
            .expect("a page")
            .contains("No validations.")
    );
    for (path, status) in [
        (
            "/signatures/validations?f=state%3Adone".to_owned(),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/signatures/validations?cursor=nope".to_owned(),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/signatures/validations/nope".to_owned(),
            StatusCode::BAD_REQUEST,
        ),
        (
            format!("{report}?category=known_fp"),
            StatusCode::BAD_REQUEST,
        ),
        (validation_href(uuid::Uuid::new_v4()), StatusCode::NOT_FOUND),
    ] {
        assert_eq!(
            get(path.clone()).await.expect("answered").status(),
            status,
            "{path}"
        );
    }

    grant_to(&stack, &alice, "signature", "download").await;
    let page = get(format!("{report}?category=regression"))
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(
        page.contains(&format!(
            r#"href="/api/svs/v1/yara/validations/{uuid}/download?category=regression""#
        )),
        "{page}"
    );
}

// ---- the SVS area: runs, the run page and the test hosts (PLAN.md 7.10 batch 5) ----

use ace_gui::svs::{
    BatchesPage, HostPage, HostsPage, RunPage, RunPageData, RunsPage, Tabs, batches_view,
    host_view, hosts_view, run_href, run_view, runs_view,
};
use ace_service::{
    HistoryRun, Ignore, Run, RunBatch, RunComment, RunEvent, RunHistory, RunQuery, RunResult,
    RunRow, RunSummary, RunTarget, SignatureHistory, SuppressionShare, TestHost,
};

fn svs_at() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("a time")
}

fn svs_actor() -> RecordedActor {
    RecordedActor {
        kind: "api_key".to_owned(),
        id: "k".to_owned(),
        name: Some(HOSTILE.to_owned()),
    }
}

/// A run with text from its launcher in every field that can hold it.
fn fixture_run_row() -> RunRow {
    let at = svs_at();
    RunRow {
        run: Run {
            uuid: uuid::Uuid::from_u128(0x5b),
            test_guid: uuid::Uuid::from_u128(0x7e57),
            platform: "windows".to_owned(),
            test_content_hash: "0".repeat(64),
            catalog_commit: "a".repeat(40),
            state: ace_core::svs::RunState::Ended,
            marker: "svs-aaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            launcher: HOSTILE.to_owned(),
            batch_id: Some(HOSTILE.to_owned()),
            extra: serde_json::json!({"ticket": "<b>42</b>"}),
            registered_by: Some(svs_actor()),
            created_at: at,
            started_at: Some(at),
            executed_at: Some(at),
            cleanup_at: None,
            exit_code: Some(1),
            launcher_error: Some(HOSTILE.to_owned()),
            ended_at: Some(at),
            end_reason: Some(HOSTILE.to_owned()),
            canceled_at: None,
            closed_at: None,
            close_reason: Some(HOSTILE.to_owned()),
            error_reason: Some(HOSTILE.to_owned()),
            observation_seconds: 5400,
            attribution_seconds: 90000,
            observation_ends_at: Some(at),
            attribution_ends_at: Some(at),
            holds_host: true,
            warnings: vec!["no <b>hunts</b> recorded".to_owned()],
            updated_at: at,
            targets: vec![RunTarget {
                hostname: HOSTILE.to_owned(),
                username: Some(HOSTILE.to_owned()),
                host: "win10-01".to_owned(),
                fqdn: None,
                user: None,
            }],
        },
        test_name: Some(HOSTILE.to_owned()),
        technique: Some("T1059.001".to_owned()),
        technique_name: Some(HOSTILE.to_owned()),
        owner: Some(HOSTILE.to_owned()),
        reviewer: None,
        reviewed_at: None,
        changed_since_review: false,
        needs_attention: true,
        summary: RunSummary {
            hit: 1,
            missing: 1,
            possibly_suppressed: 1,
            candidate: 2,
            alerts: 3,
            marker_alerts: 2,
            context_alerts: 1,
            late_alerts: 1,
            result_stale: true,
            ..RunSummary::default()
        },
    }
}

fn fixture_run_result(id: i64, signature: &str, status: Option<&str>) -> RunResult {
    RunResult {
        id,
        run: uuid::Uuid::from_u128(0x5b),
        signature_uuid: signature.to_owned(),
        signature_family: Some(HOSTILE.to_owned()),
        signature_name: Some(HOSTILE.to_owned()),
        status: status.map(str::to_owned),
        alert_count: 2,
        late_only: true,
        context_only: true,
        fallback_time: true,
        content_hash: None,
        suppressing_alert: (status == Some("possibly_suppressed"))
            .then(|| uuid::Uuid::from_u128(0xa1e7)),
        reviewed_status: status.is_none().then(|| "hit".to_owned()),
        reviewed_alert_count: None,
        reviewed_late_only: None,
        reviewed_content_hash: None,
        updated_at: svs_at(),
    }
}

fn fixture_host() -> TestHost {
    TestHost {
        id: 7,
        hostname: "win10-01".to_owned(),
        fqdn: Some("win10-01.lab.example".to_owned()),
        usernames: vec!["svc_art".to_owned(), "other".to_owned()],
        ips: vec!["10.0.0.5".to_owned()],
        platform: Some("linux".to_owned()),
        notes: Some(HOSTILE.to_owned()),
        created_by: Some(svs_actor()),
        created_at: svs_at(),
        updated_at: svs_at(),
    }
}

/// The SVS area's views, called directly: the runs with their filters, pages and exports, the batches, a
/// run's page with its result's decisions by what its viewer holds, its history, comments and event log,
/// and the test hosts with their forms, each with hostile text escaped and nothing inline.
#[test]
fn the_svs_views_draw_runs_a_run_and_test_hosts() {
    let layout = || Layout::new("n", Theme::default(), Some("analyst".to_owned()), "/svs");
    let tabs = |admin| Tabs {
        open: "runs",
        admin,
    };
    let share = SuppressionShare {
        missing: 4,
        possibly_suppressed: 1,
        reviewed_runs: 60,
        first_reviewed_at: Some(svs_at()),
        trigger_reached: true,
    };
    let row = fixture_run_row();
    let filters = vec!["state:ended".to_owned()];
    let query = RunQuery {
        filters: vec![FilterEntry::text("State", false, &["ended"])],
        ..RunQuery::default()
    };
    let list = drawn_safely(&RunsPage {
        quick: Default::default(),
        layout: layout(),
        view: runs_view(
            tabs(false),
            &query,
            &filters,
            1,
            &share,
            std::slice::from_ref(&row),
            Some("c1"),
            Some("c2"),
            false,
            None,
        ),
    });
    assert!(
        list.contains(&format!(
            r#"<a href="{}">2023-11-14 22:13:20 UTC</a>"#,
            run_href(row.run.uuid)
        )),
        "{list}"
    );
    assert!(list.contains(HOSTILE_ESCAPED), "{list}");
    assert!(
        list.contains(r#"<span class="badge disposition-warning">ended</span> <span class="muted">needs attention</span>"#),
        "{list}"
    );
    assert!(list.contains(r#"<td class="num">1/3 <span"#), "{list}");
    assert!(
        list.contains(r#"<a href="/svs/runs?f=state%3Aended">First</a>"#)
            && list.contains(
                r#"<a href="/svs/runs?f=state%3Aended&#38;cursor=c2" rel="next">Next</a>"#
            ),
        "{list}"
    );
    assert!(
        list.contains(r#"href="/api/svs/v1/runs/export/csv?f=state%3Aended""#)
            && list.contains(r#"href="/svs/runs/batches?f=state%3Aended""#),
        "{list}"
    );
    assert!(
        list.contains(r#"id="filter-state" name="state" value="ended""#),
        "{list}"
    );
    // the batch is a link to its runs, its id percent-encoded in the filter
    assert!(list.contains(r#"<a href="/svs/runs?f=batch%3A"#), "{list}");
    assert!(
        list.contains("1 of 4 expected signatures missing from 60 reviewed runs were possibly suppressed (25%). Keeping the hunter from suppressing test targets is worth reconsidering."),
        "{list}"
    );
    // only an admin gets the Test hosts tab
    assert!(!list.contains(r#"href="/svs/test-hosts""#), "{list}");
    let empty = drawn_safely(&RunsPage {
        quick: Default::default(),
        layout: layout(),
        view: runs_view(
            tabs(true),
            &RunQuery::default(),
            &[],
            0,
            &SuppressionShare {
                missing: 0,
                possibly_suppressed: 0,
                reviewed_runs: 0,
                first_reviewed_at: None,
                trigger_reached: false,
            },
            &[],
            None,
            None,
            false,
            None,
        ),
    });
    assert!(
        empty.contains("No runs.")
            && empty.contains(r#"href="/svs/test-hosts""#)
            && !empty.contains("possibly suppressed"),
        "{empty}"
    );

    let batch = RunBatch {
        batch_id: HOSTILE.to_owned(),
        runs: 3,
        states: vec![
            (ace_core::svs::RunState::Created, 0),
            (ace_core::svs::RunState::Ended, 2),
            (ace_core::svs::RunState::Started, 1),
        ],
        needs_attention: 2,
        first_created_at: svs_at(),
        last_created_at: svs_at(),
        result_hit: 1,
        result_expected: 4,
        result_missing: 3,
        result_candidate: 0,
    };
    let batches = drawn_safely(&BatchesPage {
        layout: layout(),
        view: batches_view(tabs(false), &query, &filters, &[batch], None, Some("b2")),
    });
    assert!(
        batches.contains("<td>2 ended, 1 started</td>")
            && batches.contains(r#"<td class="num">1/4</td>"#),
        "{batches}"
    );
    assert!(
        batches.contains(
            r#"<a href="/svs/runs/batches?f=state%3Aended&#38;cursor=b2" rel="next">Next</a>"#
        ) && batches.contains(r#"href="/api/svs/v1/runs/batches/export/ndjson?f=state%3Aended""#),
        "{batches}"
    );

    // the run page
    let results = [
        fixture_run_result(1, "sig-candidate", Some("candidate")),
        fixture_run_result(2, "sig-hit", Some("hit")),
        fixture_run_result(3, "sig-ignored", Some("ignored")),
        fixture_run_result(4, "sig-suppressed", Some("possibly_suppressed")),
        fixture_run_result(5, "sig-left", None),
    ];
    let history = RunHistory {
        runs: vec![HistoryRun {
            run: uuid::Uuid::from_u128(0x01d),
            state: ace_core::svs::RunState::Reviewed,
            created_at: svs_at(),
            reviewed_at: Some(svs_at()),
        }],
        signatures: results
            .iter()
            .map(|result| SignatureHistory {
                signature_uuid: result.signature_uuid.clone(),
                statuses: vec![(result.id == 2).then(|| "missing".to_owned())],
            })
            .collect(),
    };
    let ignore = |test: Option<u128>| Ignore {
        test_guid: test.map(uuid::Uuid::from_u128),
        signature_uuid: "sig-ignored".to_owned(),
        signature_family: None,
        signature_name: None,
        reason: None,
        created_by: Some(svs_actor()),
        created_at: svs_at(),
        updated_at: svs_at(),
    };
    let ignores = [ignore(Some(0x7e57)), ignore(None)];
    let comment = |id: i64, user: &str| RunComment {
        id,
        run: row.run.uuid,
        user: Some(user.to_owned()),
        comment: HOSTILE.to_owned(),
        created_at: svs_at(),
        updated_at: svs_at() + chrono::TimeDelta::minutes(5),
    };
    let comments = [comment(1, "analyst"), comment(2, "someone-else")];
    let events = [RunEvent {
        id: 1,
        kind: "transition".to_owned(),
        from_state: Some(ace_core::svs::RunState::Started),
        to_state: Some(ace_core::svs::RunState::Ended),
        actor: Some(svs_actor()),
        details: Some(serde_json::json!({"reason": "<b>nothing fired</b>"})),
        created_at: svs_at(),
    }];
    let data = |manage: bool, admin: bool, log_search: Option<&str>| RunPageData {
        row: &row,
        launcher_output: Some(HOSTILE),
        log_search: log_search.map(str::to_owned),
        results: &results,
        result_stale: true,
        computed_at: Some(svs_at()),
        history: &history,
        ignores: &ignores,
        comments: &comments,
        events: &events,
        alerts: &[],
        more_alerts: false,
        blockers: None,
        viewer: Some("analyst"),
        manage,
        admin,
        samples: false,
        notice: Some("The comment is added.".to_owned()),
    };
    let page = drawn_safely(&RunPage {
        layout: layout(),
        view: run_view(
            tabs(false),
            &data(false, false, Some("https://logs.example/search?q=svs-aaa")),
        ),
    });
    assert!(
        page.contains(r#"<a href="https://logs.example/search?q=svs-aaa" rel="noopener noreferrer">Search the logs for this run</a>"#),
        "{page}"
    );
    assert!(
        page.contains("<tr><th>Observation window</th><td class=\"qa-text\">1 h 30 min, until 2023-11-14 22:13:20 UTC</td></tr>")
            && page.contains("25 h, until 2023-11-14 22:13:20 UTC, holding its hosts")
            // what its registration warned of, escaped
            && page.contains("<tr><th>Warnings</th><td class=\"qa-text\">no &#60;b&#62;hunts&#60;/b&#62; recorded</td></tr>")
            && !page.contains("no <b>hunts</b>"),
        "{page}"
    );
    assert!(
        page.contains("3 (2 by a marker, 1 by context alone, 1 late)")
            && page.contains("Something changed since this result was computed."),
        "{page}"
    );
    assert!(
        page.contains(r#"<span class="badge disposition-warning">candidate</span> <span class="muted">late, context only, fallback time</span>"#)
            && page.contains(r#"<span class="badge disposition-secondary">left the result</span>"#)
            && page.contains(r#"<a href="/alerts/00000000-0000-0000-0000-00000000a1e7">the alert that may have suppressed it</a>"#),
        "{page}"
    );
    // the earlier run is a column, and the hit was missing there
    assert!(
        page.contains(r#"<a href="/svs/runs/00000000-0000-0000-0000-00000000001d""#)
            && page.contains("<td>missing</td>"),
        "{page}"
    );
    assert!(
        page.contains("&#60;b&#62;nothing fired&#60;/b&#62;")
            && page.contains("&#60;b&#62;42&#60;/b&#62;")
            && page.contains("started → ended"),
        "{page}"
    );
    assert!(
        page.contains(r#"<p class="notice" role="status">The comment is added.</p>"#),
        "{page}"
    );
    // without svs:run_manage there are no forms
    assert!(
        !page.contains("<form method=\"post\" action=\"/svs"),
        "{page}"
    );
    // a link that isn't http or https isn't one
    let unsafe_link = drawn_safely(&RunPage {
        layout: layout(),
        view: run_view(
            tabs(false),
            &data(false, false, Some("javascript:alert(1)")),
        ),
    });
    assert!(!unsafe_link.contains("Search the logs"), "{unsafe_link}");

    // a manager decides, and changes only their own comment
    let managed = drawn_safely(&RunPage {
        layout: layout(),
        view: run_view(tabs(false), &data(true, false, None)),
    });
    // one form a row: a decision that keeps its reason has the Why field beside its buttons, and
    // undoing one has none
    const WHY: &str =
        r#"<input type="text" name="reason" maxlength="4096" placeholder="why" aria-label="Why">"#;
    let row_form = |signature: &str, why: bool, decisions: &[(&str, &str)]| {
        let buttons: String = decisions
            .iter()
            .map(|(decision, text)| {
                format!(
                    r#"<button type="submit" name="decision" value="{decision}">{text}</button>"#
                )
            })
            .collect();
        format!(
            r#"<form method="post" action="/svs/runs/00000000-0000-0000-0000-00000000005b/decide" class="inline"><input type="hidden" name="signature" value="{signature}">{}{buttons}</form>"#,
            if why { WHY } else { "" }
        )
    };
    for (signature, why, decisions) in [
        (
            "sig-candidate",
            true,
            vec![
                ("expected", "Expect"),
                ("rejected", "Reject"),
                ("ignore", "Ignore for this test"),
            ],
        ),
        ("sig-hit", false, vec![("undecide", "Undecide")]),
        ("sig-suppressed", false, vec![("undecide", "Undecide")]),
        (
            "sig-ignored",
            false,
            vec![("unignore", "Stop ignoring for this test")],
        ),
    ] {
        assert!(
            managed.contains(&row_form(signature, why, &decisions)),
            "{signature}: {managed}"
        );
    }
    assert_eq!(
        managed.matches(WHY).count(),
        1,
        "only the candidate's decisions keep a reason: {managed}"
    );
    assert!(
        !managed.contains("ignore_globally") && !managed.contains(r#"value="sig-left""#),
        "{managed}"
    );
    assert!(
        managed.contains(r#"<form method="post" action="/svs/runs/00000000-0000-0000-0000-00000000005b/comments/1">"#)
            && !managed.contains("/comments/2\""),
        "{managed}"
    );
    assert!(
        managed.contains(r#"<form method="post" action="/svs/runs/00000000-0000-0000-0000-00000000005b/comments">"#)
            && managed.contains(", changed 2023-11-14 22:18:20 UTC"),
        "{managed}"
    );
    // an admin ignores, and stops ignoring, for every test
    let admin = drawn_safely(&RunPage {
        layout: layout(),
        view: run_view(tabs(true), &data(true, true, None)),
    });
    assert!(
        admin.contains(&row_form(
            "sig-candidate",
            true,
            &[
                ("expected", "Expect"),
                ("rejected", "Reject"),
                ("ignore", "Ignore for this test"),
                ("ignore_globally", "Ignore for every test"),
            ],
        )) && admin.contains(&row_form(
            "sig-ignored",
            false,
            &[
                ("unignore", "Stop ignoring for this test"),
                ("unignore_globally", "Stop ignoring for every test"),
            ],
        )),
        "{admin}"
    );
    // nobody's alerts were captured from: a run with no alerts has no link to the samples
    assert!(!admin.contains("files captured from"), "{admin}");

    // the test hosts, and a host's form
    let hosts_tab = || Tabs {
        open: "test_hosts",
        admin: true,
    };
    let host = fixture_host();
    let hosts = drawn_safely(&HostsPage {
        layout: layout(),
        view: hosts_view(
            hosts_tab(),
            std::slice::from_ref(&host),
            Some("c1"),
            Some("c2"),
            Some("The test host is added.".to_owned()),
        ),
    });
    assert!(
        hosts.contains(r#"<a href="/svs/test-hosts/7">win10-01</a>"#)
            && hosts.contains("<td class=\"qa-text\">svc_art, other</td>")
            && hosts.contains(r#"<a href="/svs/test-hosts?cursor=c2" rel="next">Next</a>"#)
            && hosts
                .contains(r#"<form method="post" action="/svs/test-hosts" class="detection-add">"#)
            && hosts.contains(r#"<a href="/svs/test-hosts" aria-current="page">Test hosts</a>"#),
        "{hosts}"
    );
    assert!(!hosts.contains(r#"name="seen""#), "{hosts}");
    let edit = drawn_safely(&HostPage {
        layout: layout(),
        view: host_view(hosts_tab(), &host),
    });
    assert!(
        edit.contains(r#"<form method="post" action="/svs/test-hosts/7" class="detection-add">"#)
            && edit.contains(
                r#"<input type="hidden" name="seen" value="2023-11-14T22:13:20.000000Z">"#
            )
            && edit.contains(r#"<option value="linux" selected>linux</option>"#)
            && edit.contains(r#"<option value="windows">windows</option>"#)
            && edit.contains(r#"name="usernames" value="svc_art, other""#)
            && edit.contains(r#"<form method="post" action="/svs/test-hosts/7/delete">"#),
        "{edit}"
    );
}

// ---- PLAN.md 7.10 batch 7b: a run's alerts and review, the alert's SVS banner and the list's status ----

fn fixture_run_alert(n: u128, title: &str, confidence: Option<&str>) -> ace_service::RunAlert {
    let id = uuid::Uuid::from_u128(n);
    let run = uuid::Uuid::from_u128(0x5b);
    let attribution = |removed: bool| ace_service::RunAttribution {
        id: 1,
        run,
        alert: id,
        detection: 7,
        signature_uuid: Some("sig".to_owned()),
        signature_family: Some("hunt".to_owned()),
        confidence: match confidence {
            Some("context") => ace_service::AttributionConfidence::Context,
            _ => ace_service::AttributionConfidence::Marker,
        },
        late: true,
        event_time: Some(svs_at()),
        cleanup: false,
        event_time_source: Some("event".to_owned()),
        fallback_time: false,
        source: "router".to_owned(),
        scan_point: None,
        actor: Some(svs_actor()),
        created_at: svs_at(),
        removed_at: removed.then(svs_at),
        removed_by: removed.then(svs_actor),
        removal_reason: removed.then(|| HOSTILE.to_owned()),
        kept_at: None,
        kept_by: None,
        updated_at: svs_at(),
    };
    let held = confidence.is_some();
    ace_service::RunAlert {
        alert: AlertSummary {
            tags: vec!["svs_test".to_owned()],
            svs: held.then(|| ace_service::AlertSvsStatus {
                status: if confidence == Some("context") {
                    ace_service::SvsStatus::TestContext
                } else {
                    ace_service::SvsStatus::Test
                },
                runs: vec![run],
            }),
            ..summary(id, title)
        },
        first_attribution: 1,
        holds: held,
        confidence: held.then_some(match confidence {
            Some("context") => ace_service::AttributionConfidence::Context,
            _ => ace_service::AttributionConfidence::Marker,
        }),
        late: held,
        cleanup: false,
        fallback_time: false,
        manual: false,
        kept: false,
        undecided_context: confidence == Some("context"),
        detections: vec![ace_service::RunAlertDetection {
            detection: 7,
            description: HOSTILE.to_owned(),
            signature_uuid: Some("sig".to_owned()),
            signature_family: Some("hunt".to_owned()),
            attribution: Some(attribution(!held)),
        }],
    }
}

/// Batch 7b's views, called directly: a run's alerts with how the run holds each and the association
/// forms, its review with what stands in the way, what a person may do to it, the page a bulk action
/// answers with, the alert page's SVS banner and the alert list's marks, each with hostile text escaped
/// and nothing inline, and no form for a viewer who may not use it.
#[test]
fn the_svs_review_views_draw_alerts_a_review_and_the_banner() {
    use ace_gui::svs::{ActedPage, acted_view};
    use ace_gui::svs_alert::SvsBanner;
    let layout = || Layout::new("n", Theme::default(), Some("analyst".to_owned()), "/svs");
    let tabs = || Tabs {
        open: "runs",
        admin: false,
    };
    let row = fixture_run_row();
    let alerts = [
        fixture_run_alert(0xa1, HOSTILE, Some("marker")),
        fixture_run_alert(0xa2, "by context", Some("context")),
        fixture_run_alert(0xa3, "let go", None),
    ];
    let blockers = ace_service::ReviewBlockers {
        stale: true,
        candidates: vec!["sig-a".to_owned(), "sig-b".to_owned()],
        context_alerts: vec![uuid::Uuid::from_u128(0xa2)],
    };
    let history = RunHistory {
        runs: Vec::new(),
        signatures: Vec::new(),
    };
    let data = |manage: bool, blockers: Option<&'static ace_service::ReviewBlockers>| RunPageData {
        row: &row,
        launcher_output: None,
        log_search: None,
        results: &[],
        result_stale: false,
        computed_at: None,
        history: &history,
        ignores: &[],
        comments: &[],
        events: &[],
        alerts: &alerts,
        more_alerts: true,
        blockers,
        viewer: Some("analyst"),
        manage,
        admin: false,
        samples: true,
        notice: None,
    };
    let blockers: &'static ace_service::ReviewBlockers = Box::leak(Box::new(blockers));
    let href = "/svs/runs/00000000-0000-0000-0000-00000000005b";

    // a reader: the alerts and what a review waits for, with no forms
    let read = drawn_safely(&RunPage {
        layout: layout(),
        view: run_view(tabs(), &data(false, Some(blockers))),
    });
    assert!(
        read.contains(&format!(
            r#"<a href="/alerts/00000000-0000-0000-0000-0000000000a1">{HOSTILE_ESCAPED}</a>"#
        )),
        "{read}"
    );
    assert!(
        read.contains(r#"<span class="badge svs-status">test</span>"#)
            && read.contains(r#"<span class="badge svs-status">test?</span>"#)
            && read.contains(r#"<td>marker <span class="muted">late</span></td>"#)
            && read.contains(r#"<td>context <span class="muted">late, undecided</span></td>"#)
            && read.contains("<td>1 of 1</td>")
            && read.contains("<td>0 of 1</td>"),
        "{read}"
    );
    // why it was let go, as text
    assert!(
        read.contains(&format!(
            r#"<td>no longer held <span class="muted qa-text">{HOSTILE_ESCAPED}</span></td>"#
        )),
        "{read}"
    );
    assert!(
        read.contains(&format!(
            r#"<a href="/api/svs/v1/runs/{}/alerts/export/ndjson">NDJSON</a> · the page shows the first of them"#,
            row.run.uuid
        )),
        "{read}"
    );
    // ace3's link to the files captured from the run's alerts: the samples page, narrowed to them
    let captured = ace_gui::svs::captured_files_href(
        &alerts
            .iter()
            .map(|alert| alert.alert.id)
            .collect::<Vec<_>>(),
    )
    .expect("a link");
    assert!(
        captured.starts_with("/signatures/samples?f=alert%3A00000000-0000-0000-0000-0000000000a1"),
        "{captured}"
    );
    assert!(
        read.contains(&format!(
            r#" · <a href="{captured}" title="What the run's alerts captured for other rules: did this rule's target reach ACE?">files captured from this run's alerts</a></p>"#
        )),
        "{read}"
    );
    let (decoded, _) = ace_service::filters::decode(
        FilterScreen::SvsSamples,
        &serde_urlencoded::from_str::<Vec<(String, String)>>(
            captured.trim_start_matches("/signatures/samples?"),
        )
        .expect("pairs")
        .into_iter()
        .map(|(_, f)| f)
        .collect::<Vec<_>>(),
        true,
    )
    .expect("the samples screen reads it");
    assert_eq!(decoded.len(), 1);
    assert_eq!(
        (decoded[0].name.as_str(), decoded[0].values.len()),
        ("Alert", alerts.len())
    );
    // a run with more alerts than a filter holds links the first of them, and one with none has no link
    let many: Vec<uuid::Uuid> = (0..100).map(uuid::Uuid::from_u128).collect();
    let capped = ace_gui::svs::captured_files_href(&many).expect("a link");
    assert_eq!(
        capped.matches("00000000-0000-0000-0000-").count(),
        ace_gui::svs::MAX_CAPTURE_LINK_ALERTS
    );
    assert_eq!(ace_gui::svs::captured_files_href(&[]), None);
    // without signature:read the samples page isn't theirs to open
    let no_samples = drawn_safely(&RunPage {
        layout: layout(),
        view: run_view(
            tabs(),
            &RunPageData {
                samples: false,
                ..data(false, None)
            },
        ),
    });
    assert!(!no_samples.contains("files captured from"), "{no_samples}");
    assert!(
        read.contains("<li>Its result is being recomputed, which takes at most a minute.</li>")
            && read.contains("<li>2 candidate signature(s) are undecided: expect, reject or ignore each in the result.</li>")
            && read.contains("<li>1 context-only alert(s) are neither kept nor marked not a test.</li>"),
        "{read}"
    );
    assert!(
        !read.contains("<form method=\"post\" action=\"/svs"),
        "{read}"
    );

    // a manager: the review, the alerts' forms, the association form, and what they may do to the run
    let managed = drawn_safely(&RunPage {
        layout: layout(),
        view: run_view(tabs(), &data(true, Some(blockers))),
    });
    // someone else owns it (the fixture's owner is hostile text): the review takes it only when told to
    assert!(
        managed.contains(&format!(
            r#"<form method="post" action="{href}/review" class="review">"#
        )) && managed.contains(&format!(
            r#"<label><input type="checkbox" name="take_from" value="{HOSTILE_ESCAPED}"> Take the run from <b>{HOSTILE_ESCAPED}</b>, who owns it</label>"#
        )) && managed.contains(">Review</button>"),
        "{managed}"
    );
    let buttons = |alert: &str, actions: &[(&str, &str)]| {
        let buttons: String = actions
            .iter()
            .map(|(value, label)| {
                format!(r#"<button type="submit" name="action" value="{value}">{label}</button>"#)
            })
            .collect();
        format!(
            r#"<form method="post" action="{href}/alerts" class="inline"><input type="hidden" name="alert" value="{alert}"><input type="text" name="reason" maxlength="512" placeholder="why" aria-label="Why">{buttons}</form>"#
        )
    };
    let compact: String = managed.lines().map(str::trim).collect::<Vec<_>>().join("");
    for (alert, actions) in [
        (
            "00000000-0000-0000-0000-0000000000a1",
            &[("disassociate", "Disassociate")][..],
        ),
        (
            "00000000-0000-0000-0000-0000000000a2",
            &[
                ("keep", "Keep"),
                ("not_a_test", "Not a test"),
                ("disassociate", "Disassociate"),
            ][..],
        ),
        (
            "00000000-0000-0000-0000-0000000000a3",
            &[("associate", "Associate again")][..],
        ),
    ] {
        assert!(
            compact.contains(&buttons(alert, actions)),
            "{alert}: {compact}"
        );
    }
    assert!(
        compact.contains(&format!(
            r#"<form method="post" action="{href}/alerts" class="associate"><input type="hidden" name="action" value="associate">"#
        )),
        "{compact}"
    );
    // an ended run someone else owns: take it, or close it, with why
    assert!(
        compact.contains(&format!(
            r#"<form method="post" action="/svs/runs/bulk" class="run-actions"><input type="hidden" name="run" value="{}"><input type="hidden" name="back" value="{href}"><label for="act-reason">Why</label><input type="text" id="act-reason" name="reason" maxlength="4096"><button type="submit" name="action" value="take">Take</button><button type="submit" name="action" value="close">Close</button></form>"#,
            row.run.uuid
        )),
        "{compact}"
    );
    // a run that can't be reviewed has no review at all
    let started = drawn_safely(&RunPage {
        layout: layout(),
        view: run_view(tabs(), &data(true, None)),
    });
    assert!(!started.contains(r#"id="review""#), "{started}");
    // nothing in the way
    let clear: &'static ace_service::ReviewBlockers =
        Box::leak(Box::new(ace_service::ReviewBlockers::default()));
    let ready = drawn_safely(&RunPage {
        layout: layout(),
        view: run_view(tabs(), &data(true, Some(clear))),
    });
    assert!(
        ready.contains("Nothing stands in the way of a review."),
        "{ready}"
    );

    // the runs list's bulk form, for a manager only
    let share = SuppressionShare {
        missing: 0,
        possibly_suppressed: 0,
        reviewed_runs: 0,
        first_reviewed_at: None,
        trigger_reached: false,
    };
    let filters = vec!["state:ended".to_owned()];
    let list = |manage: bool| {
        drawn_safely(&RunsPage {
            quick: Default::default(),
            layout: layout(),
            view: runs_view(
                tabs(),
                &RunQuery::default(),
                &filters,
                1,
                &share,
                std::slice::from_ref(&row),
                Some("c1"),
                None,
                manage,
                Some("Done.".to_owned()),
            ),
        })
    };
    let bulk = list(true);
    assert!(
        bulk.contains(&format!(
            r#"<input type="checkbox" form="bulk" name="run" value="{}" aria-label="Tick this run">"#,
            row.run.uuid
        )) && bulk.contains(r#"<form method="post" action="/svs/runs/bulk" id="bulk" class="bulk">"#)
            && bulk.contains(
                r#"<input type="hidden" name="back" value="/svs/runs?f=state%3Aended&#38;cursor=c1">"#
            )
            && bulk.contains(r#"<button type="submit" name="action" value="end">End now</button>"#)
            && bulk.contains(r#"<p class="notice" role="status">Done.</p>"#),
        "{bulk}"
    );
    let plain = list(false);
    assert!(
        !plain.contains("action=\"/svs/runs/bulk\"") && !plain.contains("type=\"checkbox\""),
        "{plain}"
    );

    // what a bulk action answers with when not every run was done
    let (done, owned, wrong, gone) = (
        uuid::Uuid::from_u128(1),
        uuid::Uuid::from_u128(2),
        uuid::Uuid::from_u128(3),
        uuid::Uuid::from_u128(4),
    );
    let result = ace_service::BulkResult {
        done: vec![done],
        left_alone: [(owned, "bob".to_owned())].into_iter().collect(),
        conflicts: [(wrong, HOSTILE.to_owned())].into_iter().collect(),
        unknown: vec![gone],
    };
    let acted = drawn_safely(&ActedPage {
        layout: layout(),
        view: acted_view(
            tabs(),
            "close",
            Some(HOSTILE),
            "/svs/runs?f=state%3Aended",
            &result,
        ),
    });
    let acted: String = acted.lines().map(str::trim).collect::<Vec<_>>().join("");
    assert!(
        acted.contains("<h3>Done (1)</h3>")
            && acted.contains(&format!(r#"<a href="{}"><code>{done}</code></a>"#, run_href(done)))
            && acted.contains("<h3>Left alone: someone else owns them (1)</h3>")
            && acted.contains(&format!(
                r#"<input type="hidden" name="run" value="{owned}"><input type="hidden" name="take" value="{owned}=bob">"#
            ))
            && acted.contains(r#"<input type="hidden" name="action" value="close">"#)
            && acted.contains(&format!(
                r#"<input type="hidden" name="reason" value="{HOSTILE_ESCAPED}">"#
            ))
            && acted.contains("<button type=\"submit\">Take them from their owners: Close</button>")
            && acted.contains(&format!(
                r#"<code>{wrong}</code></a>: <span class="qa-text">{HOSTILE_ESCAPED}</span>"#
            ))
            && acted.contains(&format!("<li><code>{gone}</code></li>")),
        "{acted}"
    );

    // the alert page's banner
    let (tree, comments) = fixture_tree();
    let run_ref = |state| ace_service::RunRef {
        uuid: uuid::Uuid::from_u128(0x5b),
        state,
        test_guid: uuid::Uuid::from_u128(0x7e57),
        test_name: Some(HOSTILE.to_owned()),
    };
    let view = ace_service::AlertSvsView {
        status: ace_service::SvsStatus::TestContext,
        runs: vec![run_ref(ace_service::RunState::Started)],
        detections: std::collections::BTreeMap::new(),
        mismatches: vec![
            ace_service::MarkerMismatch {
                marker: HOSTILE.to_owned(),
                result: HOSTILE.to_owned(),
                run: Some(run_ref(ace_service::RunState::Closed)),
            },
            ace_service::MarkerMismatch {
                marker: "svs-bbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
                result: "unknown".to_owned(),
                run: None,
            },
        ],
    };
    let tags = vec!["svs_test".to_owned(), HOSTILE.to_owned()];
    let alert = tree.alert.summary.id;
    let page_with = |banner: Option<SvsBanner>| {
        let page = AlertPage::new(
            Layout::new("n0nce", Theme::Light, Some("alice".to_owned()), "/alerts/x"),
            &tree,
            &comments,
            &ObservableActions::empty(),
            &std::collections::BTreeMap::new(),
        )
        .expect("a page")
        .with_svs(banner)
        .render()
        .expect("renders");
        assert!(
            !page.contains("<script>alert") && !page.contains("<img"),
            "{page}"
        );
        page.lines().map(str::trim).collect::<Vec<_>>().join("")
    };
    // an analyst who may open runs and change alerts
    let full = page_with(SvsBanner::new(alert, Some(&view), &tags, true, true));
    assert!(
        full.contains(&format!(
            r#"<details class="section svs-banner" id="svs" data-section-id="svs"><summary>SVS <span class="badge svs-status">test?</span> <span class="badge tag">svs_test</span> <span class="badge tag">{HOSTILE_ESCAPED}</span> <span class="hint">"#
        )),
        "{full}"
    );
    assert!(
        full.contains("<p>Probably a test alert: every detection is attributed to an SVS test run by its host and time alone. Keep it or mark it not a test.</p>")
            && full.contains(&format!(
                r#"<li>Test run <a href="{href}"><code>00000000-0000-0000-0000-00000000005b</code></a> of <span class="qa-text">{HOSTILE_ESCAPED}</span>, started</li>"#
            ))
            && full.contains(&format!(
                r#"<li>Marker <code>{HOSTILE_ESCAPED}</code>: <span class="qa-text">{HOSTILE_ESCAPED}</span>; it belongs to test run <a href="{href}">"#
            ))
            && full.contains("<span class=\"qa-text\">unknown</span>; no run has it</li>"),
        "{full}"
    );
    assert!(
        full.contains(&format!(
            r#"<form method="post" action="/alerts/{alert}/svs" class="inline">"#
        )) && full.contains(r#"<button type="submit" name="action" value="disassociate""#)
            && full.contains(r#"<button type="submit" name="action" value="not_a_test""#),
        "{full}"
    );
    // a viewer who may do neither: no links to runs, and no form
    let bare = page_with(SvsBanner::new(alert, Some(&view), &tags, false, false));
    assert!(
        bare.contains("<li>Test run <code>00000000-0000-0000-0000-00000000005b</code> of")
            && !bare.contains("/svs/runs/")
            && !bare.contains("/svs\" class=\"inline\""),
        "{bare}"
    );
    // a marker's alert isn't offered not a test, and a mismatch has no runs to let go of
    let marked = AlertSvsViewOf(ace_service::SvsStatus::Test, view.runs.clone());
    let marked = page_with(SvsBanner::new(alert, Some(&marked.view()), &[], true, true));
    assert!(
        marked.contains(r#"value="disassociate""#) && !marked.contains(r#"value="not_a_test""#),
        "{marked}"
    );
    let mismatch = AlertSvsViewOf(ace_service::SvsStatus::Mismatch, Vec::new());
    let mismatch = page_with(SvsBanner::new(
        alert,
        Some(&mismatch.view()),
        &[],
        true,
        true,
    ));
    assert!(
        mismatch.contains(r#"<span class="badge svs-status">mismatch</span>"#)
            && !mismatch.contains("/svs\" class=\"inline\""),
        "{mismatch}"
    );
    // only a tag: the banner says so; nothing at all: no banner
    let tagged = page_with(SvsBanner::new(
        alert,
        None,
        &["svs:maintenance".to_owned()],
        true,
        true,
    ));
    assert!(
        tagged.contains(r#"<summary>SVS <span class="badge tag">svs:maintenance</span> <span class="hint">tagged by the core</span></summary>"#)
            && !tagged.contains("svs-status"),
        "{tagged}"
    );
    assert_eq!(SvsBanner::new(alert, None, &[], true, true), None);
    assert!(!page_with(None).contains("svs-banner"));

    // the alert list: the status beside the description, leading to the run, and the root's tags
    let (one, two) = (uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2));
    let page = ListedPage {
        alerts: vec![
            AlertSummary {
                tags: vec![HOSTILE.to_owned()],
                svs: Some(ace_service::AlertSvsStatus {
                    status: ace_service::SvsStatus::Test,
                    runs: vec![uuid::Uuid::from_u128(0x5b), uuid::Uuid::from_u128(0x5c)],
                }),
                ..fixture_summary(one, "a test alert", None)
            },
            AlertSummary {
                svs: Some(ace_service::AlertSvsStatus {
                    status: ace_service::SvsStatus::Mismatch,
                    runs: Vec::new(),
                }),
                ..fixture_summary(two, "a mismatch", None)
            },
        ],
        next: None,
        total: 2,
    };
    let columns = ace_service::PreferenceKey::ManageColumns
        .parse(serde_json::json!({"order": ["description"], "hidden": []}))
        .expect("a value");
    let ace_service::PreferenceValue::ManageColumns(columns) = columns else {
        panic!("manage_columns");
    };
    let view = list_view(
        &page,
        &ListQuery::default(),
        &columns,
        &[],
        &std::collections::HashMap::new(),
        chrono_tz::Tz::UTC,
        Vec::new(),
        None,
        &ace_service::Dispositions::ace3(),
        None,
    );
    let html = AlertListFragment {
        list: view.list.clone(),
    }
    .render()
    .expect("renders");
    assert!(
        html.contains(&format!(
            r#"<a href="/alerts/{one}">a test alert</a> <a href="{href}" class="badge svs-status" title="A test alert: every detection is attributed to an SVS test run, at least one by its marker.">test</a> <span class="badge tag">{HOSTILE_ESCAPED}</span></td>"#
        )),
        "{html}"
    );
    assert!(
        html.contains(&format!(
            r#"<a href="/alerts/{two}">a mismatch</a> <span class="badge svs-status" title="It holds an SVS test marker that doesn&#39;t agree with its run: it stays with analysts.">mismatch</span></td>"#
        )),
        "{html}"
    );
    assert!(
        !html.contains("<script>alert") && !html.contains("<img"),
        "{html}"
    );
}

/// An `AlertSvsView` of a status and its runs, with nothing else.
struct AlertSvsViewOf(ace_service::SvsStatus, Vec<ace_service::RunRef>);

impl AlertSvsViewOf {
    fn view(&self) -> ace_service::AlertSvsView {
        ace_service::AlertSvsView {
            status: self.0,
            runs: self.1.clone(),
            detections: std::collections::BTreeMap::new(),
            mismatches: Vec::new(),
        }
    }
}

/// An alert in the GUI's database with one detection, attributed to the run by `confidence` when given.
async fn gui_run_alert(
    stack: &Stack,
    run: uuid::Uuid,
    title: &str,
    signature: Option<&str>,
    confidence: Option<&str>,
) -> uuid::Uuid {
    let db = stack.test_db.db();
    let alert = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO analysis.roots (id, analysis_mode, description, event_time_source, alerted_at, tags)
         VALUES ($1, 'correlation', $2, 'unset', now(),
                 CASE WHEN $3 THEN '{svs_test}'::text[] ELSE '{}' END)",
    )
    .bind(alert)
    .bind(title)
    .bind(confidence.is_some())
    .execute(db.pool())
    .await
    .expect("an alert");
    sqlx::query(
        "INSERT INTO analysis.detections (root_id, description, signature_uuid, signature_family)
         VALUES ($1, 'a detection', $2, 'hunt')",
    )
    .bind(alert)
    .bind(signature)
    .execute(db.pool())
    .await
    .expect("a detection");
    if let Some(confidence) = confidence {
        sqlx::query(
            "INSERT INTO svs.attributions
                 (run_id, root_id, detection_id, confidence, source, actor, event_time,
                  event_time_source)
             SELECT (SELECT id FROM svs.runs WHERE uuid = $1), d.root_id, d.id,
                    $3::svs.attribution_confidence, 'router',
                    '{\"kind\": \"internal\", \"id\": \"svs\"}', now(), 'insert_time'
             FROM analysis.detections d WHERE d.root_id = $2",
        )
        .bind(run)
        .bind(alert)
        .bind(confidence)
        .execute(db.pool())
        .await
        .expect("an attribution");
    }
    alert
}

/// Batch 7b's pages through the server: a reader sees a run's alerts and what its review waits for, with
/// no forms, and the alert page's banner and the list's status; `svs:run_manage` adds the association
/// forms, the review and a person's actions, whose posts keep, associate, review and take a run from its
/// owner only when told to; `alert:write` adds the banner's form, which gives the alert back; each post
/// is refused without its permission and from another site, and each write has its audit row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_svs_review_pages_need_run_manage_and_the_banner_alert_write() {
    let stack = stack_of_db(Catalog::new(vec![]), |service, _| {
        Gui::new(service, Transport::Plain)
    })
    .await;
    let db = stack.test_db.db();
    let alice = user(&stack, "alice").await;
    let bob = user(&stack, "bob").await;
    let boss = user(&stack, "boss").await;
    for minor in ["admin", "run_register"] {
        grant_to(&stack, &boss, "svs", minor).await;
    }
    // an ended run: its test's name and its launcher are hostile text
    let run = gui_run(&stack, &boss).await;
    let page_of = run_href(run);
    let rule = "33333333-cccc-4ccc-8ccc-333333333333";
    let marked = gui_run_alert(&stack, run, HOSTILE, Some(rule), Some("marker")).await;
    let context = gui_run_alert(&stack, run, "by context", None, Some("context")).await;
    let free = gui_run_alert(&stack, run, "nobody's", None, None).await;
    // a started run that bob owns
    stack
        .service
        .create_test_host(&boss, &ace_service::HostFields::new("gui-host-02"))
        .await
        .expect("a test host");
    let bobs = stack
        .service
        .register_svs_run(
            &boss,
            &ace_service::Registration {
                test_guid: uuid::Uuid::from_u128(0x7e57).to_string(),
                targets: vec![ace_service::TargetSpec::new("gui-host-02", None)],
                launcher: "art".to_owned(),
                batch_id: None,
                extra: serde_json::json!({}),
            },
            chrono::Utc::now(),
        )
        .await
        .expect("registers")
        .uuid;
    stack
        .service
        .start_svs_run(&boss, bobs, chrono::Utc::now())
        .await
        .expect("starts");
    sqlx::query(
        "UPDATE svs.runs SET owner_id = (SELECT id FROM service.users WHERE username = 'bob')
         WHERE uuid = $1",
    )
    .bind(bobs)
    .execute(db.pool())
    .await
    .expect("gives it to bob");
    let state_of = async |run: uuid::Uuid| -> (String, Option<String>) {
        sqlx::query_as(
            "SELECT r.state::text, u.username::text FROM svs.runs r
             LEFT JOIN service.users u ON u.id = r.owner_id WHERE r.uuid = $1",
        )
        .bind(run)
        .fetch_one(db.pool())
        .await
        .expect("the run")
    };
    let disposition_of = async |alert: uuid::Uuid| -> Option<String> {
        sqlx::query_scalar("SELECT disposition FROM analysis.roots WHERE id = $1")
            .bind(alert)
            .fetch_one(db.pool())
            .await
            .expect("the alert")
    };

    let session = session_of(&stack, "alice").await;
    let get = |path: String| stack.get(&path).header("cookie", cookie(&session)).send();
    let post = |path: String, form: Vec<(&'static str, String)>| {
        let form: Vec<(&str, &str)> = form.iter().map(|(k, v)| (*k, v.as_str())).collect();
        stack
            .post(&path, &form)
            .header("cookie", cookie(&session))
            .send()
    };
    let text = async |path: String| -> String {
        let page = get(path.clone()).await.expect("answered");
        assert_eq!(page.status(), StatusCode::OK, "{path}");
        page.text().await.expect("a page")
    };
    let bulk = |action: &'static str, run: uuid::Uuid, more: Vec<(&'static str, String)>| {
        let mut form = vec![("action", action.to_owned()), ("run", run.to_string())];
        form.extend(more);
        post("/svs/runs/bulk".to_owned(), form)
    };
    let associate = |action: &'static str, alert: String| {
        post(
            format!("{page_of}/alerts"),
            vec![("action", action.to_owned()), ("alert", alert)],
        )
    };
    let release = |alert: uuid::Uuid, action: &'static str| {
        post(
            format!("/alerts/{alert}/svs"),
            vec![("action", action.to_owned()), ("reason", "mine".to_owned())],
        )
    };
    let writes = || {
        sqlx_count(
            &stack.test_db,
            "SELECT count(*) FROM service.audit
             WHERE action LIKE '%svs%' OR action IN ('change_svs_association', 'release_alert_from_svs')",
        )
    };

    // signed out: the posts go to the login
    for path in [
        "/svs/runs/bulk".to_owned(),
        format!("{page_of}/review"),
        format!("{page_of}/alerts"),
        format!("/alerts/{marked}/svs"),
    ] {
        let refused = stack.post(&path, &[]).send().await.expect("answered");
        assert_eq!(refused.status(), StatusCode::SEE_OTHER, "{path}");
        assert!(location(&refused).starts_with("/login"), "{path}");
    }
    // signed in, holding nothing: each post is refused
    for refused in [
        bulk("take", run, vec![]).await,
        post(format!("{page_of}/review"), vec![]).await,
        associate("keep", context.to_string()).await,
        release(marked, "disassociate").await,
    ] {
        assert_eq!(refused.expect("answered").status(), StatusCode::FORBIDDEN);
    }

    // svs:run_read and alert:read: the run's alerts and its review's blockers, with no forms
    grant_to(&stack, &alice, "svs", "run_read").await;
    grant_to(&stack, &alice, "alert", "read").await;
    let before = writes().await;
    let page = text(page_of.clone()).await;
    assert!(
        page.contains(&format!(
            r#"<a href="/alerts/{marked}">{HOSTILE_ESCAPED}</a>"#
        )) && page.contains(r#"<span class="badge svs-status">test</span>"#)
            && page.contains(r#"<span class="badge svs-status">test?</span>"#)
            && page.contains(r#"<h3 id="review">Review</h3>"#)
            && page.contains("1 context-only alert(s) are neither kept nor marked not a test.")
            && !page.contains("<script>alert")
            && !page.contains("<form method=\"post\" action=\"/svs"),
        "{page}"
    );
    // the alert's banner, with its run a link and its tag, and no form without alert:write
    let banner = text(format!("/alerts/{marked}")).await;
    assert!(
        banner.contains(r#"<details class="section svs-banner" id="svs" data-section-id="svs">"#)
            && banner.contains(r#"<span class="badge svs-status">test</span>"#)
            && banner.contains(r#"<span class="badge tag">svs_test</span>"#)
            && banner.contains(&format!(r#"<a href="{page_of}"><code>{run}</code></a>"#))
            && banner.contains(HOSTILE_ESCAPED)
            && !banner.contains("<script>alert")
            && !banner.contains(&format!("/alerts/{marked}/svs")),
        "{banner}"
    );
    assert!(
        !text(format!("/alerts/{free}")).await.contains("svs-banner"),
        "an alert SVS never touched has no banner"
    );
    // the alert list: the status, leading to the run, and the tag
    let list = text("/".to_owned()).await;
    assert!(
        list.contains(&format!(
            r#"<a href="{page_of}" class="badge svs-status" title="A test alert: every detection is attributed to an SVS test run, at least one by its marker.">test</a> <span class="badge tag">svs_test</span>"#
        )) && list.contains(r#"class="badge svs-status" title="Probably a test alert"#),
        "{list}"
    );
    // a reader's posts are the service's refusals, and write nothing
    for refused in [
        bulk("take", run, vec![]).await,
        post(format!("{page_of}/review"), vec![]).await,
        associate("keep", context.to_string()).await,
        release(marked, "disassociate").await,
    ] {
        assert_eq!(refused.expect("answered").status(), StatusCode::FORBIDDEN);
    }
    assert_eq!(writes().await, before);

    // svs:run_manage: the forms
    grant_to(&stack, &alice, "svs", "run_manage").await;
    let page = text(page_of.clone()).await;
    assert!(
        page.contains(&format!(
            r#"<form method="post" action="{page_of}/review" class="review">"#
        )) && page.contains(&format!(
            r#"<form method="post" action="{page_of}/alerts" class="associate">"#
        )) && page.contains(r#"<button type="submit" name="action" value="keep">Keep</button>"#)
            && page.contains(r#"<button type="submit" name="action" value="close">Close</button>"#)
            && !page.contains("<script>alert"),
        "{page}"
    );
    // a review that something blocks is refused, and says what
    let blocked = post(format!("{page_of}/review"), vec![])
        .await
        .expect("answered");
    assert_eq!(blocked.status(), StatusCode::CONFLICT);
    assert!(
        blocked
            .text()
            .await
            .expect("a page")
            .contains("can&#39;t be reviewed"),
    );
    assert_eq!(state_of(run).await.0, "ended");

    // the associations: keep the context alert, associate one by its id, and let it go again
    let kept = associate("keep", context.to_string())
        .await
        .expect("answered");
    assert_eq!(kept.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&kept), format!("{page_of}?done=keep"));
    assert!(
        text(location(&kept).to_owned())
            .await
            .contains("The alert is kept: it is the run&#39;s."),
    );
    let associated = associate("associate", format!(" {free} "))
        .await
        .expect("answered");
    assert_eq!(location(&associated), format!("{page_of}?done=associate"));
    let let_go = associate("disassociate", free.to_string())
        .await
        .expect("answered");
    assert_eq!(location(&let_go), format!("{page_of}?done=disassociate"));
    assert!(text(page_of.clone()).await.contains(
        r#"<button type="submit" name="action" value="associate">Associate again</button>"#
    ),);
    for (action, alert, status) in [
        ("promote", free.to_string(), StatusCode::BAD_REQUEST),
        ("associate", "nope".to_owned(), StatusCode::BAD_REQUEST),
        (
            "associate",
            uuid::Uuid::new_v4().to_string(),
            StatusCode::NOT_FOUND,
        ),
        // nothing to keep
        ("keep", free.to_string(), StatusCode::CONFLICT),
    ] {
        assert_eq!(
            associate(action, alert.clone())
                .await
                .expect("answered")
                .status(),
            status,
            "{action} {alert}"
        );
    }
    for (path, status) in [
        ("/svs/runs/nope/alerts".to_owned(), StatusCode::BAD_REQUEST),
        (
            format!("{}/alerts", run_href(uuid::Uuid::new_v4())),
            StatusCode::NOT_FOUND,
        ),
        ("/svs/runs/nope/review".to_owned(), StatusCode::BAD_REQUEST),
        (
            format!("{}/review", run_href(uuid::Uuid::new_v4())),
            StatusCode::NOT_FOUND,
        ),
    ] {
        assert_eq!(
            post(
                path.clone(),
                vec![("action", "keep".to_owned()), ("alert", free.to_string())]
            )
            .await
            .expect("answered")
            .status(),
            status,
            "{path}"
        );
    }

    // the review, once its result is computed and its candidate decided
    let timers = Actor::Internal {
        id: ace_service::Component::new("scheduler:svs_run_timers").expect("a name"),
    };
    let recompute = async || {
        stack
            .service
            .recompute_stale_svs_results(&timers, chrono::Utc::now(), None)
            .await
            .expect("recomputes");
    };
    recompute().await;
    let decided = post(
        format!("{page_of}/decide"),
        vec![
            ("signature", rule.to_owned()),
            ("decision", "expected".to_owned()),
        ],
    )
    .await
    .expect("answered");
    assert_eq!(decided.status(), StatusCode::SEE_OTHER);
    recompute().await;
    assert!(
        text(page_of.clone())
            .await
            .contains("Nothing stands in the way of a review."),
    );
    let reviewed = post(format!("{page_of}/review"), vec![])
        .await
        .expect("answered");
    assert_eq!(reviewed.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&reviewed), format!("{page_of}?done=reviewed"));
    let after = text(location(&reviewed).to_owned()).await;
    assert!(
        after.contains("The run is reviewed: its result is signed off")
            && after.contains(r#"<span class="badge disposition-success">reviewed</span>"#)
            && after.contains(">Review again</button>")
            && after.contains("<tr><th>Reviewed by</th><td class=\"qa-text\">alice</td></tr>"),
        "{after}"
    );
    assert_eq!(
        state_of(run).await,
        ("reviewed".to_owned(), Some("alice".to_owned()))
    );
    for alert in [marked, context] {
        assert_eq!(disposition_of(alert).await.as_deref(), Some("SIMULATED"));
    }

    // a run someone else owns: left alone, on a page that says so and offers to take it
    let left = bulk("cancel", bobs, vec![("back", page_of.clone())])
        .await
        .expect("answered");
    assert_eq!(left.status(), StatusCode::OK);
    let left = left.text().await.expect("a page");
    assert!(
        left.contains("<h3>Left alone: someone else owns them (1)</h3>")
            && left.contains(&format!(
                r#"<input type="hidden" name="take" value="{bobs}=bob">"#
            ))
            && left.contains(&format!(
                r#"<input type="hidden" name="back" value="{page_of}">"#
            )),
        "{left}"
    );
    assert_eq!(
        state_of(bobs).await,
        ("started".to_owned(), Some("bob".to_owned()))
    );
    // a review of it is refused the same way, until the box is ticked
    let owned = post(format!("{}/review", run_href(bobs)), vec![])
        .await
        .expect("answered");
    assert_eq!(owned.status(), StatusCode::CONFLICT);
    // an end with no reason isn't done, and the page says why
    let refused = bulk(
        "end",
        bobs,
        vec![("take", format!("{bobs}=bob")), ("back", page_of.clone())],
    )
    .await
    .expect("answered");
    assert_eq!(refused.status(), StatusCode::OK);
    assert!(
        refused
            .text()
            .await
            .expect("a page")
            .contains("ending it early needs a reason"),
    );
    // the take was confirmed, and stands
    assert_eq!(
        state_of(bobs).await,
        ("started".to_owned(), Some("alice".to_owned()))
    );
    let ended = bulk(
        "end",
        bobs,
        vec![
            ("reason", "nothing fired".to_owned()),
            ("back", format!("{}?f=state%3Astarted", "/svs/runs")),
        ],
    )
    .await
    .expect("answered");
    assert_eq!(ended.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&ended), "/svs/runs?f=state%3Astarted&done=acted");
    assert!(
        text(location(&ended).to_owned())
            .await
            .contains(r#"<p class="notice" role="status">Done.</p>"#),
    );
    assert_eq!(state_of(bobs).await.0, "ended");
    // the runs list has the bulk form and each run's box
    let list = text("/svs/runs".to_owned()).await;
    assert!(
        list.contains(r#"<form method="post" action="/svs/runs/bulk" id="bulk" class="bulk">"#)
            && list.contains(&format!(
                r#"<input type="checkbox" form="bulk" name="run" value="{bobs}" aria-label="Tick this run">"#
            )),
        "{list}"
    );
    // a back that isn't one of the runs' pages is the runs list
    let elsewhere = bulk(
        "take",
        bobs,
        vec![("back", "//evil.example/svs/runs".to_owned())],
    )
    .await
    .expect("answered");
    assert_eq!(location(&elsewhere), "/svs/runs?done=acted");
    // a run that isn't there, and requests that aren't ones
    let gone = bulk("take", uuid::Uuid::new_v4(), vec![])
        .await
        .expect("answered");
    assert_eq!(gone.status(), StatusCode::OK);
    assert!(
        gone.text()
            .await
            .expect("a page")
            .contains("<h3>No such run (1)</h3>"),
    );
    for form in [
        vec![("action", "promote".to_owned()), ("run", bobs.to_string())],
        vec![("action", "take".to_owned())],
        vec![("action", "take".to_owned()), ("run", "nope".to_owned())],
        vec![
            ("action", "take".to_owned()),
            ("run", bobs.to_string()),
            ("take", "nope".to_owned()),
        ],
    ] {
        assert_eq!(
            post("/svs/runs/bulk".to_owned(), form.clone())
                .await
                .expect("answered")
                .status(),
            StatusCode::BAD_REQUEST,
            "{form:?}"
        );
    }

    // the banner's form needs alert:write
    let held = gui_run_alert(&stack, bobs, "held by context", None, Some("context")).await;
    assert_eq!(
        release(held, "not_a_test")
            .await
            .expect("answered")
            .status(),
        StatusCode::FORBIDDEN
    );
    grant_to(&stack, &alice, "alert", "write").await;
    let banner = text(format!("/alerts/{held}")).await;
    assert!(
        banner.contains(&format!(
            r#"<form method="post" action="/alerts/{held}/svs" class="inline">"#
        )) && banner.contains(r#"<button type="submit" name="action" value="not_a_test""#),
        "{banner}"
    );
    let released = release(held, "not_a_test").await.expect("answered");
    assert_eq!(released.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&released), format!("/alerts/{held}#svs"));
    // the reason typed with Not a test is kept, in the run's event and the audit row; the attribution's
    // own removal reason stays ace3's fixed text
    let event: serde_json::Value = sqlx::query_scalar(
        "SELECT details FROM svs.run_events
         WHERE kind = 'disassociated' AND details ->> 'alert_uuid' = $1 ORDER BY id DESC LIMIT 1",
    )
    .bind(held.to_string())
    .fetch_one(db.pool())
    .await
    .expect("the event");
    assert_eq!(
        (&event["reason"], &event["not_a_test"]),
        (&serde_json::json!("mine"), &serde_json::json!(true))
    );
    let audited: serde_json::Value = sqlx::query_scalar(
        "SELECT details FROM service.audit
         WHERE action = 'release_alert_from_svs' AND target_id = $1 ORDER BY id DESC LIMIT 1",
    )
    .bind(held.to_string())
    .fetch_one(db.pool())
    .await
    .expect("the audit row");
    assert_eq!(
        (&audited["action"], &audited["reason"]),
        (&serde_json::json!("not_a_test"), &serde_json::json!("mine"))
    );
    let removal: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT DISTINCT removal_reason FROM svs.attributions WHERE root_id = $1",
    )
    .bind(held)
    .fetch_all(db.pool())
    .await
    .expect("reads");
    assert_eq!(removal, [Some("not a test".to_owned())]);
    let attributed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM svs.attributions WHERE root_id = $1 AND removed_at IS NULL",
    )
    .bind(held)
    .fetch_one(db.pool())
    .await
    .expect("counts");
    assert_eq!(attributed, 0);
    // a SIMULATED alert given back is open again
    let reopened = release(marked, "disassociate").await.expect("answered");
    assert_eq!(reopened.status(), StatusCode::SEE_OTHER);
    assert_eq!(disposition_of(marked).await.as_deref(), Some("OPEN"));
    for (path, action, status) in [
        (
            format!("/alerts/{held}/svs"),
            "promote",
            StatusCode::BAD_REQUEST,
        ),
        // nothing holds it any more
        (
            format!("/alerts/{held}/svs"),
            "disassociate",
            StatusCode::CONFLICT,
        ),
        (
            "/alerts/nope/svs".to_owned(),
            "disassociate",
            StatusCode::NOT_FOUND,
        ),
        (
            format!("/alerts/{}/svs", uuid::Uuid::new_v4()),
            "disassociate",
            StatusCode::NOT_FOUND,
        ),
    ] {
        assert_eq!(
            post(path.clone(), vec![("action", action.to_owned())])
                .await
                .expect("answered")
                .status(),
            status,
            "{path} {action}"
        );
    }

    // a post from another site's page is refused, and changes nothing
    let before = writes().await;
    for path in [
        "/svs/runs/bulk".to_owned(),
        format!("{}/review", run_href(bobs)),
        format!("{page_of}/alerts"),
        format!("/alerts/{context}/svs"),
    ] {
        let cross = stack
            .http
            .post(format!("{}{path}", stack.url))
            .header("origin", "https://evil.example")
            .header("cookie", cookie(&session))
            .form(&[
                ("action", "disassociate"),
                ("run", &bobs.to_string()),
                ("alert", &context.to_string()),
            ])
            .send()
            .await
            .expect("answered");
        assert_eq!(cross.status(), StatusCode::FORBIDDEN, "{path}");
    }
    assert_eq!(writes().await, before);
    assert_eq!(state_of(bobs).await.0, "ended");

    // each write left its audit row, by alice
    let audited: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT action FROM service.audit
         WHERE actor ->> 'name' = 'alice' AND action <> 'login' ORDER BY 1",
    )
    .fetch_all(db.pool())
    .await
    .expect("reads");
    for action in [
        "change_svs_association",
        "end_svs_runs",
        "release_alert_from_svs",
        "review_svs_run",
        "set_svs_expectation",
    ] {
        assert!(audited.iter().any(|a| a == action), "{action}: {audited:?}");
    }
    let _ = bob;

    // Not a test from a run's page keeps the reason typed with it, as the alert's page does
    let another = gui_run_alert(&stack, run, "another by context", None, Some("context")).await;
    let marked_not = post(
        format!("{page_of}/alerts"),
        vec![
            ("action", "not_a_test".to_owned()),
            ("alert", another.to_string()),
            ("reason", " a lab rebuild ".to_owned()),
        ],
    )
    .await
    .expect("answered");
    assert_eq!(marked_not.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&marked_not), format!("{page_of}?done=not_a_test"));
    let event: serde_json::Value = sqlx::query_scalar(
        "SELECT details FROM svs.run_events
         WHERE kind = 'disassociated' AND details ->> 'alert_uuid' = $1 ORDER BY id DESC LIMIT 1",
    )
    .bind(another.to_string())
    .fetch_one(db.pool())
    .await
    .expect("the event");
    assert_eq!(
        (&event["reason"], &event["not_a_test"]),
        (
            &serde_json::json!("a lab rebuild"),
            &serde_json::json!(true)
        )
    );
}

/// A catalog test and a run of it in the GUI's database, with hostile text where a launcher and a
/// repository put theirs, ended, with a result of one candidate and one hit.
async fn gui_run(stack: &Stack, registrar: &Actor) -> uuid::Uuid {
    let db = stack.test_db.db();
    let guid = uuid::Uuid::from_u128(0x7e57);
    sqlx::query(
        "INSERT INTO svs.catalog_tests
             (guid, repository, technique, name, platforms, test, content_hash, commit, path)
         VALUES ($1, 'atomic-red-team', 'T1059.001', $2, '{windows}', '{}', repeat('0', 64),
                 repeat('a', 40), 'atomics/T1059.001/T1059.001.yaml')",
    )
    .bind(guid)
    .bind(HOSTILE)
    .execute(db.pool())
    .await
    .expect("a catalog test");
    stack
        .service
        .create_test_host(registrar, &ace_service::HostFields::new("gui-host-01"))
        .await
        .expect("a test host");
    let run = stack
        .service
        .register_svs_run(
            registrar,
            &ace_service::Registration {
                test_guid: guid.to_string(),
                targets: vec![ace_service::TargetSpec::new("gui-host-01", None)],
                launcher: HOSTILE.to_owned(),
                batch_id: Some("nightly".to_owned()),
                extra: serde_json::json!({}),
            },
            chrono::Utc::now(),
        )
        .await
        .expect("registers");
    stack
        .service
        .start_svs_run(registrar, run.uuid, chrono::Utc::now())
        .await
        .expect("starts");
    sqlx::query("UPDATE svs.runs SET state = 'ended', ended_at = now() WHERE uuid = $1")
        .bind(run.uuid)
        .execute(db.pool())
        .await
        .expect("ends");
    for (signature, status) in [
        ("11111111-aaaa-4aaa-8aaa-111111111111", "candidate"),
        ("22222222-bbbb-4bbb-8bbb-222222222222", "hit"),
    ] {
        sqlx::query(
            "INSERT INTO svs.run_results
                 (run_id, signature_uuid, signature_family, signature_name, status, alert_count)
             VALUES ((SELECT id FROM svs.runs WHERE uuid = $1), $2, 'yara', $3, $4, 1)",
        )
        .bind(run.uuid)
        .bind(signature)
        .bind(HOSTILE)
        .bind(status)
        .execute(db.pool())
        .await
        .expect("a result row");
    }
    run.uuid
}

/// The SVS pages through the server: signed out goes to the login; without `svs:run_read` each page and
/// post is 403; with it the layout's link, the runs, the batches and a run with no forms, and the errors;
/// `svs:run_manage` adds the decisions and the comments, whose posts decide once, comment, and change
/// only one's own; `svs:admin` opens the test hosts, whose form adds, changes from a fresh form only, and
/// removes; a post from another site is refused; and each write has its audit row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_svs_pages_need_run_read_then_run_manage_and_svs_admin() {
    let stack = stack_of_db(Catalog::new(vec![]), |service, _| {
        Gui::new(service, Transport::Plain)
    })
    .await;
    let alice = user(&stack, "alice").await;
    let bob = user(&stack, "bob").await;
    // whoever set the lab up: its test host and the launcher's run
    let boss = user(&stack, "boss").await;
    for minor in ["admin", "run_register"] {
        grant_to(&stack, &boss, "svs", minor).await;
    }
    let run = gui_run(&stack, &boss).await;
    let page_of = run_href(run);
    let candidate = "11111111-aaaa-4aaa-8aaa-111111111111";

    let pages = [
        "/svs".to_owned(),
        "/svs/runs".to_owned(),
        "/svs/runs/batches".to_owned(),
        page_of.clone(),
        "/svs/test-hosts".to_owned(),
    ];
    for path in &pages {
        let page = stack.get(path).send().await.expect("answered");
        assert_eq!(page.status(), StatusCode::SEE_OTHER, "{path}");
        assert!(location(&page).starts_with("/login?next="), "{path}");
    }
    let session = session_of(&stack, "alice").await;
    let get = |path: String| stack.get(&path).header("cookie", cookie(&session)).send();
    let post = |path: String, form: Vec<(&'static str, String)>| {
        let form: Vec<(&str, &str)> = form.iter().map(|(k, v)| (*k, v.as_str())).collect();
        stack
            .post(&path, &form)
            .header("cookie", cookie(&session))
            .send()
    };
    for path in &pages {
        assert_eq!(
            get(path.clone()).await.expect("answered").status(),
            StatusCode::FORBIDDEN,
            "{path}"
        );
    }
    let decide = |decision: &'static str| {
        post(
            format!("{page_of}/decide"),
            vec![
                ("signature", candidate.to_owned()),
                ("decision", decision.to_owned()),
            ],
        )
    };
    for refused in [
        decide("expected").await,
        post(
            format!("{page_of}/comments"),
            vec![("comment", "x".to_owned())],
        )
        .await,
        post(
            "/svs/test-hosts".to_owned(),
            vec![("hostname", "nope".to_owned())],
        )
        .await,
    ] {
        assert_eq!(refused.expect("answered").status(), StatusCode::FORBIDDEN);
    }

    // svs:run_read: the pages, with no forms
    grant_to(&stack, &alice, "svs", "run_read").await;
    // the audit rows of SVS's own writes: grants and logins have theirs too
    let svs_writes = || {
        sqlx_count(
            &stack.test_db,
            "SELECT count(*) FROM service.audit
             WHERE action LIKE '%svs%' OR action LIKE '%test_host%'",
        )
    };
    let audit = svs_writes().await;
    let home = get("/svs".to_owned()).await.expect("answered");
    assert_eq!(home.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&home), "/svs/runs?f=needs_attention%3Atrue");
    let list = get(location(&home).to_owned()).await.expect("answered");
    assert_eq!(list.status(), StatusCode::OK);
    let list = list.text().await.expect("a page");
    assert!(list.contains(&format!(r#"<a href="{page_of}">"#)), "{list}");
    // the layout's link, marked as the section the page is in, with the one run that needs attention
    // (batch 9)
    assert!(
        list.contains(
            r#"<a href="/svs" aria-current="page">SVS<span class="count" id="svs-nav-count" title="runs that need attention">(1)</span></a>"#
        ),
        "{list}"
    );
    assert!(
        !list.contains("<script>alert") && !list.contains(r#"href="/svs/test-hosts""#),
        "{list}"
    );
    assert!(list.contains("1 matching"), "{list}");
    let folded = get("/svs/runs?state=ended&batch=nightly".to_owned())
        .await
        .expect("answered");
    assert_eq!(folded.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&folded),
        "/svs/runs?f=state%3Aended&f=batch%3Anightly"
    );
    let none = get("/svs/runs?f=state%3Astarted".to_owned())
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(none.contains("No runs."), "{none}");
    let batches = get("/svs/runs/batches".to_owned()).await.expect("answered");
    assert_eq!(batches.status(), StatusCode::OK);
    let batches = batches.text().await.expect("a page");
    assert!(
        batches.contains(r#"<a href="/svs/runs?f=batch%3Anightly">nightly</a>"#)
            && batches.contains("<td>1 ended</td>"),
        "{batches}"
    );
    let page = get(page_of.clone()).await.expect("answered");
    assert_eq!(page.status(), StatusCode::OK);
    let page = page.text().await.expect("a page");
    assert!(
        page.contains(candidate)
            && page.contains(r#"<span class="badge disposition-warning">candidate</span>"#)
            && !page.contains("<script>alert")
            && !page.contains("<form method=\"post\" action=\"/svs"),
        "{page}"
    );
    for (path, status) in [
        (
            "/svs/runs?f=state%3Afinished".to_owned(),
            StatusCode::BAD_REQUEST,
        ),
        ("/svs/runs?cursor=nope".to_owned(), StatusCode::BAD_REQUEST),
        (
            "/svs/runs/batches?cursor=nope".to_owned(),
            StatusCode::BAD_REQUEST,
        ),
        ("/svs/runs/nope".to_owned(), StatusCode::BAD_REQUEST),
        (run_href(uuid::Uuid::new_v4()), StatusCode::NOT_FOUND),
        ("/svs/test-hosts".to_owned(), StatusCode::FORBIDDEN),
        ("/svs/test-hosts/1".to_owned(), StatusCode::FORBIDDEN),
    ] {
        assert_eq!(
            get(path.clone()).await.expect("answered").status(),
            status,
            "{path}"
        );
    }
    // reading writes nothing, and a reader's post is the service's refusal
    assert_eq!(
        decide("expected").await.expect("answered").status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(svs_writes().await, audit);

    // svs:run_manage: the decisions and the comments
    grant_to(&stack, &alice, "svs", "run_manage").await;
    let page = get(page_of.clone())
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(
        page.contains(&format!(
            r#"<form method="post" action="{page_of}/decide" class="inline"><input type="hidden" name="signature" value="{candidate}"><input type="text" name="reason" maxlength="4096" placeholder="why" aria-label="Why"><button type="submit" name="decision" value="expected">Expect</button>"#
        )) && !page.contains("ignore_globally"),
        "{page}"
    );
    // the form's Why reaches the decision: ace3's page asks for it, and the handler always read it
    let reasoned = post(
        format!("{page_of}/decide"),
        vec![
            ("signature", candidate.to_owned()),
            ("reason", format!("  {HOSTILE}  ")),
            ("decision", "rejected".to_owned()),
        ],
    )
    .await
    .expect("answered");
    assert_eq!(reasoned.status(), StatusCode::SEE_OTHER);
    let kept: Option<String> =
        sqlx::query_scalar("SELECT reason FROM svs.expectations WHERE signature_uuid = $1")
            .bind(candidate)
            .fetch_one(stack.test_db.db().pool())
            .await
            .expect("the decision");
    assert_eq!(kept.as_deref(), Some(HOSTILE), "trimmed, and kept as typed");
    assert_eq!(
        decide("undecide").await.expect("answered").status(),
        StatusCode::SEE_OTHER
    );
    let decided = decide("expected").await.expect("answered");
    assert_eq!(decided.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&decided), format!("{page_of}?done=expected"));
    let after = get(location(&decided).to_owned())
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(
        after.contains("The signature is expected of this test on this platform.")
            && after.contains("candidate_decision"),
        "{after}"
    );
    // the same decision from a page loaded before it: refused, not made twice
    assert_eq!(
        decide("rejected").await.expect("answered").status(),
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(
        decide("undecide").await.expect("answered").status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        decide("ignore").await.expect("answered").status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        decide("unignore").await.expect("answered").status(),
        StatusCode::SEE_OTHER
    );
    for (decision, status) in [
        // a global ignore is svs:admin's
        ("ignore_globally", StatusCode::FORBIDDEN),
        ("promote", StatusCode::BAD_REQUEST),
        // nothing to remove
        ("undecide", StatusCode::NOT_FOUND),
    ] {
        assert_eq!(
            decide(decision).await.expect("answered").status(),
            status,
            "{decision}"
        );
    }
    assert_eq!(
        post(format!("{page_of}/decide"), vec![])
            .await
            .expect("answered")
            .status(),
        StatusCode::BAD_REQUEST
    );

    let commented = post(
        format!("{page_of}/comments"),
        vec![("comment", HOSTILE.to_owned())],
    )
    .await
    .expect("answered");
    assert_eq!(location(&commented), format!("{page_of}?done=commented"));
    let comment: i64 =
        sqlx::query_scalar("SELECT id FROM svs.run_comments ORDER BY id DESC LIMIT 1")
            .fetch_one(stack.test_db.db().pool())
            .await
            .expect("the comment");
    let with_comment = get(page_of.clone())
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(
        with_comment.contains(&format!(
            r#"<form method="post" action="{page_of}/comments/{comment}">"#
        )) && !with_comment.contains("<script>alert"),
        "{with_comment}"
    );
    assert_eq!(
        post(
            format!("{page_of}/comments"),
            vec![("comment", "  ".to_owned())]
        )
        .await
        .expect("answered")
        .status(),
        StatusCode::BAD_REQUEST
    );
    // another manager sees it with no form, and can't change it
    grant_to(&stack, &bob, "svs", "run_read").await;
    grant_to(&stack, &bob, "svs", "run_manage").await;
    let bobs = session_of(&stack, "bob").await;
    let bobs_page = stack
        .get(&page_of)
        .header("cookie", cookie(&bobs))
        .send()
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(
        !bobs_page.contains(&format!("{page_of}/comments/{comment}\"")),
        "{bobs_page}"
    );
    let theirs = stack
        .post(
            &format!("{page_of}/comments/{comment}"),
            &[("comment", "theirs")],
        )
        .header("cookie", cookie(&bobs))
        .send()
        .await
        .expect("answered");
    assert_eq!(theirs.status(), StatusCode::FORBIDDEN);
    let edited = post(
        format!("{page_of}/comments/{comment}"),
        vec![("comment", "edited".to_owned())],
    )
    .await
    .expect("answered");
    assert_eq!(location(&edited), format!("{page_of}?done=edited"));
    for (path, status) in [
        (format!("{page_of}/comments/999999"), StatusCode::NOT_FOUND),
        (format!("{page_of}/comments/first"), StatusCode::BAD_REQUEST),
        (
            format!("{}/comments/{comment}", run_href(uuid::Uuid::new_v4())),
            StatusCode::NOT_FOUND,
        ),
    ] {
        assert_eq!(
            post(path.clone(), vec![("comment", "x".to_owned())])
                .await
                .expect("answered")
                .status(),
            status,
            "{path}"
        );
    }
    // a post from another site's page is refused, and changes nothing
    let cross = stack
        .http
        .post(format!("{}{page_of}/comments/{comment}", stack.url))
        .header("origin", "https://evil.example")
        .header("cookie", cookie(&session))
        .form(&[("delete", "1")])
        .send()
        .await
        .expect("answered");
    assert_eq!(cross.status(), StatusCode::FORBIDDEN);
    let deleted = post(
        format!("{page_of}/comments/{comment}"),
        vec![("delete", "1".to_owned())],
    )
    .await
    .expect("answered");
    assert_eq!(location(&deleted), format!("{page_of}?done=deleted"));
    // rejected with its reason, undecided, expected, undecided, ignored, unignored, commented, edited,
    // deleted
    assert_eq!(svs_writes().await, audit + 9);

    // svs:admin: the test hosts
    grant_to(&stack, &alice, "svs", "admin").await;
    let hosts = get("/svs/test-hosts".to_owned()).await.expect("answered");
    assert_eq!(hosts.status(), StatusCode::OK);
    let hosts = hosts.text().await.expect("a page");
    assert!(
        hosts.contains("gui-host-01")
            && hosts.contains(r#"<a href="/svs/test-hosts" aria-current="page">Test hosts</a>"#),
        "{hosts}"
    );
    let added = post(
        "/svs/test-hosts".to_owned(),
        vec![
            ("hostname", "WIN10-02.lab.example".to_owned()),
            ("platform", "windows".to_owned()),
            ("usernames", "LAB\\svc_art, other".to_owned()),
            ("ips", "10.0.0.6".to_owned()),
            ("notes", HOSTILE.to_owned()),
        ],
    )
    .await
    .expect("answered");
    assert_eq!(location(&added), "/svs/test-hosts?done=added");
    let host: i64 = sqlx::query_scalar("SELECT id FROM svs.test_hosts WHERE hostname = 'win10-02'")
        .fetch_one(stack.test_db.db().pool())
        .await
        .expect("the host");
    let listed = get("/svs/test-hosts?done=added".to_owned())
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(
        listed.contains("The test host is added.")
            && listed.contains("<td class=\"qa-text\">other, svc_art</td>")
            && !listed.contains("<script>alert"),
        "{listed}"
    );
    for (form, status) in [
        (
            vec![("hostname", "not a host".to_owned())],
            StatusCode::BAD_REQUEST,
        ),
        (
            vec![("hostname", "win10-02".to_owned())],
            StatusCode::CONFLICT,
        ),
    ] {
        assert_eq!(
            post("/svs/test-hosts".to_owned(), form)
                .await
                .expect("answered")
                .status(),
            status
        );
    }
    let edit = get(format!("/svs/test-hosts/{host}"))
        .await
        .expect("answered");
    assert_eq!(edit.status(), StatusCode::OK);
    let edit = edit.text().await.expect("a page");
    let seen = edit
        .split(r#"name="seen" value=""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("the form's seen")
        .to_owned();
    let change = |notes: &'static str, seen: String| {
        post(
            format!("/svs/test-hosts/{host}"),
            vec![
                ("hostname", "win10-02".to_owned()),
                ("notes", notes.to_owned()),
                ("seen", seen),
            ],
        )
    };
    let changed = change("lab 4", seen.clone()).await.expect("answered");
    assert_eq!(location(&changed), "/svs/test-hosts?done=changed");
    // the same form again: someone changed the host since it was loaded
    let stale = change("lab 5", seen).await.expect("answered");
    assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);
    assert!(
        stale
            .text()
            .await
            .expect("a page")
            .contains("was changed by someone else since you loaded it")
    );
    assert_eq!(
        change("x", "yesterday".to_owned())
            .await
            .expect("answered")
            .status(),
        StatusCode::BAD_REQUEST
    );
    for (path, status) in [
        ("/svs/test-hosts/nope".to_owned(), StatusCode::BAD_REQUEST),
        ("/svs/test-hosts/999999".to_owned(), StatusCode::NOT_FOUND),
        (
            "/svs/test-hosts?cursor=nope".to_owned(),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        assert_eq!(
            get(path.clone()).await.expect("answered").status(),
            status,
            "{path}"
        );
    }
    let removed = post(format!("/svs/test-hosts/{host}/delete"), vec![])
        .await
        .expect("answered");
    assert_eq!(location(&removed), "/svs/test-hosts?done=removed");
    assert_eq!(
        post(format!("/svs/test-hosts/{host}/delete"), vec![])
            .await
            .expect("answered")
            .status(),
        StatusCode::NOT_FOUND
    );
    // added, changed, removed
    assert_eq!(svs_writes().await, audit + 12);
    // and an admin ignores for every test from the run page
    let page = get(page_of.clone())
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    assert!(page.contains("ignore_globally"), "{page}");
    assert_eq!(
        decide("ignore_globally").await.expect("answered").status(),
        StatusCode::SEE_OTHER
    );
}

use ace_gui::svs_coverage::{
    CoveragePage, SignaturePage, TechniquePage, TestPage, TestsPage, WorklistPage, bulk_notice,
    coverage_view, signature_href, signature_view, technique_href, technique_view, test_href,
    test_view, tests_view, worklist_view,
};

const COVERAGE_SIGNATURE: &str = "c0c0c0c0-2222-4222-8222-222222222222";

fn fixture_catalog_test() -> ace_service::CatalogTest {
    use ace_service::{PlatformHistory, TestHistory, TestState};
    let run = uuid::Uuid::from_u128(0x5b);
    ace_service::CatalogTest {
        guid: uuid::Uuid::from_u128(0x7e57),
        repository: HOSTILE.to_owned(),
        technique: "T1059.001".to_owned(),
        technique_name: Some(HOSTILE.to_owned()),
        name: HOSTILE.to_owned(),
        platforms: vec!["windows".to_owned(), HOSTILE.to_owned()],
        executor: Some(HOSTILE.to_owned()),
        path: HOSTILE.to_owned(),
        commit: "a".repeat(40),
        content_hash: "0".repeat(64),
        first_seen_at: svs_at(),
        removed_at: Some(svs_at()),
        updated_at: svs_at(),
        history: TestHistory {
            state: TestState::Failing,
            run_count: 7,
            last_run: Some(run),
            last_run_at: Some(svs_at()),
            last_reviewed_run: Some(run),
            last_reviewed_at: Some(svs_at()),
            expected: 2,
            recent_runs: 5,
            recent_runs_missing: 2,
            platform_states: [
                (
                    "linux".to_owned(),
                    PlatformHistory {
                        state: TestState::NeverRun,
                        last_reviewed_run: None,
                        last_reviewed_at: None,
                        expected: 0,
                    },
                ),
                (
                    "windows".to_owned(),
                    PlatformHistory {
                        state: TestState::Failing,
                        last_reviewed_run: Some(run),
                        last_reviewed_at: Some(svs_at()),
                        expected: 2,
                    },
                ),
            ]
            .into(),
        },
    }
}

fn fixture_coverage_row(technique: &str, platform: &str) -> ace_service::CoverageRow {
    ace_service::CoverageRow {
        technique: technique.to_owned(),
        platform: platform.to_owned(),
        parent: None,
        is_subtechnique: false,
        technique_name: Some(HOSTILE.to_owned()),
        tactics: vec!["TA0002".to_owned()],
        catalog_status: "unknown".to_owned(),
        attack_platform: false,
        state: ace_service::SvsCoverageState::Failing,
        own_state: ace_service::SvsCoverageState::Manual,
        tests_total: 4,
        tests_validated: 1,
        tests_failing: 2,
        tests_stale: 0,
        manual_signatures: 3,
        measured_signatures: 5,
        last_reviewed_at: Some(svs_at()),
        state_changed_at: svs_at(),
        first_seen_at: svs_at(),
        retired_at: Some(svs_at()),
        updated_at: svs_at(),
    }
}

fn fixture_worklist_row(
    technique: &str,
    status: ace_service::WorklistStatus,
    resolved: bool,
) -> ace_service::WorklistRow {
    ace_service::WorklistRow {
        signature_uuid: COVERAGE_SIGNATURE.to_owned(),
        technique: technique.to_owned(),
        technique_name: Some(HOSTILE.to_owned()),
        kind: ace_service::WorklistKind::Declared,
        status,
        declared_as: vec![technique.to_owned(), "T1086".to_owned()],
        tag_present: true,
        signature_counts: true,
        counts: !resolved,
        measured: true,
        measured_techniques: vec!["T1059.001".to_owned()],
        signature_family: Some("hunt".to_owned()),
        signature_name: Some(HOSTILE.to_owned()),
        resolution: resolved.then_some(ace_service::WorklistResolution::Remove),
        reason: resolved.then(|| HOSTILE.to_owned()),
        reference: resolved.then(|| "https://git.example/pull/7?a=1&b=2".to_owned()),
        resolved_by: resolved.then(svs_actor),
        resolved_at: resolved.then(svs_at),
        first_seen_at: svs_at(),
        status_changed_at: svs_at(),
        updated_at: svs_at(),
    }
}

/// The Tests, Coverage and Worklist views, called directly: the tests with their state and run history, a
/// test's page with its settings and decisions by what its viewer holds, coverage with its counts and a
/// failed refresh, a technique's drill-down, and the worklist with its resolution forms, each with hostile
/// text escaped and nothing inline.
#[test]
fn the_svs_coverage_views_draw_tests_coverage_and_the_worklist() {
    use ace_service::{
        CatalogTestDetail, CatalogTestQuery, CoverageQuery, CoverageSnapshotRow, CoverageSummary,
        Expectation, ExpectationState, ManualSignature, MeasuredSignature, MeasuredTechnique,
        MeasuredTest, PlatformCounts, RemovedTest, SignatureWorklist, SvsCoverageRefreshState,
        SvsCoverageState, TechniqueCoverage, TestSettings, TestState, WorklistQuery,
        WorklistStatus,
    };
    let layout = || Layout::new("n", Theme::default(), Some("analyst".to_owned()), "/svs");
    let tabs = |open| Tabs { open, admin: false };
    let test = fixture_catalog_test();
    let run = run_href(uuid::Uuid::from_u128(0x5b));

    // the Tests tab
    let filters = vec!["removed:false".to_owned()];
    let query = CatalogTestQuery {
        filters: vec![FilterEntry::text("Removed", false, &["false"])],
        ..CatalogTestQuery::default()
    };
    let list = drawn_safely(&TestsPage {
        quick: Default::default(),
        layout: layout(),
        view: tests_view(
            tabs("tests"),
            &query,
            &filters,
            std::slice::from_ref(&test),
            Some("c1"),
            Some("c2"),
        ),
    });
    assert!(
        list.contains(&format!(
            r#"<a href="{}">{HOSTILE_ESCAPED}</a> <span class="muted">removed</span>"#,
            test_href(test.guid)
        )),
        "{list}"
    );
    assert!(
        list.contains(r#"<a href="/svs/coverage/T1059.001">T1059.001</a>"#)
            && list.contains(r#"<span class="badge disposition-danger">failing</span>"#)
            && list.contains(&format!(r#"<a href="{run}">2023-11-14 22:13:20 UTC</a>"#))
            && list.contains("<td>2 of 5 missed</td>")
            && list.contains(r#"<td class="num">7</td>"#),
        "{list}"
    );
    assert!(
        list.contains(r#"<a href="/svs/tests?f=removed%3Afalse">First</a>"#)
            && list.contains(
                r#"<a href="/svs/tests?f=removed%3Afalse&#38;cursor=c2" rel="next">Next</a>"#
            )
            && list.contains(r#"href="/api/svs/v1/tests/export/csv?f=removed%3Afalse""#)
            && list.contains(r#"id="filter-removed" name="removed" value="false""#),
        "{list}"
    );
    // each tab opens on its default view, and the open one says so
    assert!(
        list.contains(r#"<a href="/svs/tests?f=removed%3Afalse" aria-current="page">Tests</a>"#)
            && list.contains(
                r#"<a href="/svs/coverage?f=platform%3Awindows%2Clinux%2Cmacos&amp;f=retired%3Afalse">Coverage</a>"#
            )
            && list.contains(r#"<a href="/svs/worklist?f=status%3Aopen">Worklist</a>"#)
            && !list.contains(r#"href="/svs/test-hosts""#),
        "{list}"
    );
    let none = drawn_safely(&TestsPage {
        quick: Default::default(),
        layout: layout(),
        view: tests_view(
            tabs("tests"),
            &CatalogTestQuery::default(),
            &[],
            &[],
            None,
            None,
        ),
    });
    assert!(
        none.contains("No tests.") && !none.contains(">First<"),
        "{none}"
    );

    // a test's page
    let detail = CatalogTestDetail {
        test: test.clone(),
        description: Some(HOSTILE.to_owned()),
        platform_slugs: vec!["windows".to_owned()],
        entry: serde_json::json!({"executor": {"command": HOSTILE}}),
    };
    let settings = TestSettings {
        test_guid: test.guid,
        observation_minutes: Some(45),
        holds_host: true,
        set_by: Some(svs_actor()),
        updated_at: svs_at(),
    };
    let expectation = Expectation {
        test_guid: test.guid,
        platform: "windows".to_owned(),
        signature_uuid: HOSTILE.to_owned(),
        state: ExpectationState::Expected,
        signature_family: Some("yara".to_owned()),
        signature_name: Some(HOSTILE.to_owned()),
        reason: Some(HOSTILE.to_owned()),
        decided_from_run: None,
        decided_by: Some(svs_actor()),
        decided_at: svs_at(),
        updated_at: svs_at(),
    };
    let ignore = |global: bool| Ignore {
        test_guid: (!global).then_some(test.guid),
        signature_uuid: COVERAGE_SIGNATURE.to_owned(),
        signature_family: None,
        signature_name: Some(HOSTILE.to_owned()),
        reason: Some(HOSTILE.to_owned()),
        created_by: Some(svs_actor()),
        created_at: svs_at(),
        updated_at: svs_at(),
    };
    let ignores = [ignore(false), ignore(true)];
    let page_of = test_href(test.guid);
    let draw = |manage: bool, admin: bool, settings: Option<&TestSettings>| {
        drawn_safely(&TestPage {
            layout: layout(),
            view: test_view(
                tabs("tests"),
                &detail,
                settings,
                std::slice::from_ref(&expectation),
                &ignores,
                manage,
                admin,
                Some("Done.".to_owned()),
            ),
        })
    };
    let reader = draw(false, false, Some(&settings));
    assert!(
        reader.contains(HOSTILE_ESCAPED) && !reader.contains("<form method=\"post\" action=\"/svs"),
        "{reader}"
    );
    assert!(
        reader.contains("Runs registered from now on are observed for 45 minutes.")
            && reader.contains("its runs hold their hosts until their attribution window ends")
            && reader.contains(r#"<p class="notice" role="status">Done.</p>"#)
            && reader.contains(
                r#"<a href="/svs/runs?f=test%3A00000000-0000-0000-0000-000000007e57">Its runs</a>"#
            )
            && reader.contains("<td>linux</td>")
            && reader.contains(r#"<span class="badge disposition-secondary">never_run</span>"#)
            && reader.contains("<td>every test</td>")
            && reader.contains("<td>this test</td>"),
        "{reader}"
    );
    // the entry is shown as text
    assert!(reader.contains("&#34;command&#34;"), "{reader}");
    let manager = draw(true, false, Some(&settings));
    assert!(
        manager.contains(&format!(
            r#"<form method="post" action="{page_of}/settings" class="detection-add">"#
        )) && manager.contains(r#"name="observation_minutes" min="1" step="1" value="45""#)
            && manager.contains(r#"name="holds_host" value="1" checked"#)
            && manager.contains(r#"<input type="hidden" name="action" value="clear">"#)
            && manager.contains(&format!(
                r#"<form method="post" action="{page_of}/decide" class="inline"><input type="hidden" name="decision" value="undecide"><input type="hidden" name="platform" value="windows"><input type="hidden" name="signature" value="{HOSTILE_ESCAPED}">"#
            ))
            && manager.contains(r#"name="decision" value="unignore">"#)
            // a global ignore's removal is svs:admin's
            && !manager.contains("unignore_globally"),
        "{manager}"
    );
    let admin = draw(false, true, None);
    assert!(
        admin.contains(r#"name="decision" value="unignore_globally">"#)
            && !admin.contains(r#"value="undecide""#)
            && !admin.contains("/settings")
            && admin.contains("Its runs get the computed window"),
        "{admin}"
    );
    let unset = draw(true, false, None);
    assert!(
        !unset.contains(r#"value="clear""#) && !unset.contains(" checked"),
        "{unset}"
    );

    // the Coverage tab
    let rows = [
        fixture_coverage_row("T1234", "windows"),
        ace_service::CoverageRow {
            technique: "T1059.001".to_owned(),
            parent: Some("T1059".to_owned()),
            is_subtechnique: true,
            catalog_status: "active".to_owned(),
            attack_platform: true,
            state: SvsCoverageState::None,
            own_state: SvsCoverageState::None,
            tests_total: 0,
            tests_validated: 0,
            tests_failing: 0,
            manual_signatures: 0,
            measured_signatures: 0,
            last_reviewed_at: None,
            retired_at: None,
            ..fixture_coverage_row("T1059.001", "windows")
        },
    ];
    let counts = |pairs: &[(&str, i64)]| {
        pairs
            .iter()
            .map(|(state, count)| ((*state).to_owned(), *count))
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let summary = |refreshed: bool, error: Option<&str>| CoverageSummary {
        rows: 12,
        states: counts(&[("failing", 2), ("none", 9), ("validated", 1), ("stale", 0)]),
        own_states: counts(&[("none", 12)]),
        platforms: vec![PlatformCounts {
            platform: "windows".to_owned(),
            rows: 12,
            states: counts(&[("failing", 2)]),
            own_states: counts(&[]),
        }],
        refresh: Some(SvsCoverageRefreshState {
            attack_release: Some("v99.0".to_owned()),
            refreshed_at: refreshed.then(svs_at),
            duration_ms: Some(12),
            rows: 12,
            changed: 3,
            retired: 1,
            unknown_tags: 4,
            ignored_tags: 5,
            error: error.map(str::to_owned),
        }),
    };
    let coverage_filters = vec!["state:failing".to_owned()];
    let coverage_query = CoverageQuery {
        filters: vec![FilterEntry::text("State", false, &["failing"])],
        ..CoverageQuery::default()
    };
    let coverage = drawn_safely(&CoveragePage {
        quick: Default::default(),
        layout: layout(),
        view: coverage_view(
            tabs("coverage"),
            &coverage_query,
            &coverage_filters,
            &summary(true, Some(HOSTILE)),
            &rows,
            None,
            Some("c2"),
        ),
    });
    assert!(
        coverage.contains(
            r#"<a href="/svs/coverage/T1234">T1234</a> <span class="muted">unknown, a test&#39;s platform, retired</span>"#
        ) && coverage.contains(r#"<span class="badge disposition-danger">failing</span>"#)
            && coverage.contains("<td>manual</td>")
            && coverage.contains("<td>1 validated, 2 failing of 4</td>")
            && coverage.contains(r#"<td class="nowrap"><a href="/svs/coverage/T1059.001">T1059.001</a></td>"#)
            && coverage.contains(r#"<span class="badge disposition-secondary">none</span>"#),
        "{coverage}"
    );
    assert!(
        coverage.contains("12 rows: 2 failing, 1 validated, 9 none")
            && coverage.contains(
                "Refreshed 2023-11-14 22:13:20 UTC against ATT&#38;CK v99.0: 12 rows, 3 changed, 4 tags \
                 naming an unknown technique, 5 tags that aren&#39;t technique ids."
            )
            && coverage.contains(&format!(
                r#"<p class="error" role="alert">The latest refresh failed: {HOSTILE_ESCAPED}</p>"#
            ))
            && coverage.contains(r#"href="/api/svs/v1/coverage/export/ndjson?f=state%3Afailing""#)
            && coverage.contains(
                r#"<a href="/svs/coverage?f=state%3Afailing&#38;cursor=c2" rel="next">Next</a>"#
            )
            && coverage.contains(r#"aria-current="page">Coverage</a>"#),
        "{coverage}"
    );
    let never = drawn_safely(&CoveragePage {
        quick: Default::default(),
        layout: layout(),
        view: coverage_view(
            tabs("coverage"),
            &CoverageQuery::default(),
            &[],
            &CoverageSummary {
                rows: 0,
                states: counts(&[]),
                own_states: counts(&[]),
                platforms: vec![],
                refresh: None,
            },
            &[],
            None,
            None,
        ),
    });
    assert!(
        never.contains("Coverage has never been refreshed.")
            && never.contains("No coverage rows.")
            && never.contains("0 rows ·")
            && !never.contains(r#"role="alert""#),
        "{never}"
    );

    // a technique's page
    let technique = TechniqueCoverage {
        requested: " t1086 ".to_owned(),
        technique: "T1059.001".to_owned(),
        name: Some(HOSTILE.to_owned()),
        parent: Some("T1059".to_owned()),
        is_subtechnique: true,
        catalog_status: "active".to_owned(),
        tactics: vec!["TA0002".to_owned()],
        attack_release: "v99.0".to_owned(),
        refreshed_at: Some(svs_at()),
        rows: vec![rows[1].clone()],
        sub_technique_rows: vec![rows[0].clone()],
        tests: vec![ace_service::CoverageTestRow {
            guid: test.guid,
            name: HOSTILE.to_owned(),
            test_technique: "T1086".to_owned(),
            technique: "T1059.001".to_owned(),
            platform: "windows".to_owned(),
            test_state: TestState::AwaitingReview,
            contribution: SvsCoverageState::Stale,
            last_reviewed_run: Some(uuid::Uuid::from_u128(0x5b)),
            last_reviewed_at: Some(svs_at()),
            expected_signatures: vec![COVERAGE_SIGNATURE.to_owned()],
        }],
        measured_signatures: vec![MeasuredSignature {
            signature_uuid: HOSTILE.to_owned(),
            name: None,
            family: Some("yara".to_owned()),
            tests: vec![(test.guid, "windows".to_owned())],
        }],
        manual_signatures: vec![
            ManualSignature {
                signature_uuid: COVERAGE_SIGNATURE.to_owned(),
                name: Some(HOSTILE.to_owned()),
                family: "hunt".to_owned(),
                declared: "T1086".to_owned(),
                technique: "T1059.001".to_owned(),
                counts: false,
                reason: Some("removed".to_owned()),
            },
            ManualSignature {
                signature_uuid: "another".to_owned(),
                name: None,
                family: "yara".to_owned(),
                declared: "T1059.001".to_owned(),
                technique: "T1059.001".to_owned(),
                counts: true,
                reason: None,
            },
        ],
        removed_tests: vec![RemovedTest {
            guid: test.guid,
            name: HOSTILE.to_owned(),
            technique: "T1086".to_owned(),
            removed_at: Some(svs_at()),
        }],
    };
    let snapshot = CoverageSnapshotRow {
        snapshot_date: "2026-10-16".parse().expect("a day"),
        technique: "T1059.001".to_owned(),
        platform: "windows".to_owned(),
        attack_release: "v99.0".to_owned(),
        parent: Some("T1059".to_owned()),
        is_subtechnique: true,
        state: SvsCoverageState::Validated,
        own_state: SvsCoverageState::Validated,
        tests_total: 1,
        tests_validated: 1,
        tests_failing: 0,
        tests_stale: 0,
        manual_signatures: 0,
        measured_signatures: 1,
        updated_at: svs_at(),
    };
    let drill = drawn_safely(&TechniquePage {
        layout: layout(),
        view: technique_view(tabs("coverage"), &technique, &[snapshot]),
    });
    assert!(
        drill.contains(r#"<a href="/svs/coverage/T1059">T1059</a> / <code>T1059.001</code>"#)
            && drill.contains("<th>Asked for</th><td class=\"qa-text\">t1086 (revoked, now this technique)</td>")
            && drill.contains(r#"<a href="/svs/tests?f=technique%3AT1059.001">Its tests</a>"#)
            && drill.contains(r#"<a href="/svs/runs?f=technique%3AT1059.001">Its runs</a>"#)
            && drill.contains(&format!(
                r#"<a href="{page_of}">{HOSTILE_ESCAPED}</a>"#
            ))
            && drill.contains(r#"<span class="badge disposition-warning">awaiting_review</span>"#)
            && drill.contains("<td>stale</td>")
            && drill.contains("tagged T1086, which counts as T1059.001")
            && drill.contains("doesn&#39;t count: resolved remove on the worklist")
            && drill.contains("<td>tagged T1059.001</td>")
            && drill.contains("<td>counts</td>")
            && drill.contains("<td>1 test on a platform</td>")
            && drill.contains(r#"<td class="nowrap">2026-10-16</td>"#)
            && drill.contains(
                r#"href="/api/svs/v1/coverage/history/export/csv?f=technique%3AT1059.001&#38;f=level%3Asub-technique&#38;f=date%3A-365d""#
            ),
        "{drill}"
    );
    // a signature's uuid in a link is percent-encoded, and hostile text never opens a tag
    assert!(
        drill.contains(&format!(r#"<a href="{}">"#, signature_href(HOSTILE)))
            && signature_href(HOSTILE).starts_with("/svs/worklist/%22%3E%3Cscript%3E"),
        "{drill}"
    );
    assert_eq!(technique_href("T1059.001"), "/svs/coverage/T1059.001");

    // the Worklist tab
    let open = fixture_worklist_row("T1547", WorklistStatus::Open, false);
    let pending = fixture_worklist_row("T1059", WorklistStatus::RemovePending, true);
    let confirmed = ace_service::WorklistRow {
        kind: ace_service::WorklistKind::Undeclared,
        ..fixture_worklist_row("T1059.001", WorklistStatus::Undeclared, false)
    };
    let worklist_rows = [open.clone(), pending.clone(), confirmed.clone()];
    let worklist_filters = vec!["status:open".to_owned()];
    let worklist_query = WorklistQuery {
        filters: vec![FilterEntry::text("Status", false, &["open"])],
        ..WorklistQuery::default()
    };
    let draw_worklist = |manage: bool, notice: Option<String>| {
        drawn_safely(&WorklistPage {
            quick: Default::default(),
            layout: layout(),
            view: worklist_view(
                tabs("worklist"),
                &worklist_query,
                &worklist_filters,
                &worklist_rows,
                Some("c1"),
                None,
                manage,
                notice,
            ),
        })
    };
    let read_only = draw_worklist(false, None);
    assert!(
        read_only.contains(&format!(
            r#"<a href="{}">{HOSTILE_ESCAPED}</a> <code class="muted">{COVERAGE_SIGNATURE}</code>"#,
            signature_href(COVERAGE_SIGNATURE)
        )) && read_only.contains(r#"<a href="/svs/coverage/T1547">T1547</a>"#)
            && read_only.contains(
                r#"<span class="badge disposition-warning">open</span> <span class="muted">counts</span>"#
            )
            && read_only.contains(
                r#"<span class="badge disposition-warning">remove_pending</span> <span class="muted">doesn&#39;t count</span>"#
            )
            && read_only.contains("<td>T1547, T1086</td>")
            && read_only.contains(&format!("remove: {HOSTILE_ESCAPED}"))
            && read_only.contains(
                r#"<a href="https://git.example/pull/7?a=1&#38;b=2" rel="noopener noreferrer">reference</a>"#
            )
            && !read_only.contains("<form method=\"post\" action=\"/svs")
            && !read_only.contains("type=\"checkbox\""),
        "{read_only}"
    );
    let managed = draw_worklist(true, Some(bulk_notice(2, 1, 0)));
    assert!(
        managed.contains(r#"<form method="post" action="/svs/worklist/resolve" id="worklist-resolve" class="run-actions">"#)
            && managed.contains(r#"<input type="hidden" name="back" value="/svs/worklist?f=status%3Aopen&#38;cursor=c1">"#)
            && managed.contains(&format!(
                r#"<input type="checkbox" name="row" value="{COVERAGE_SIGNATURE}|T1547" form="worklist-resolve""#
            ))
            && managed.contains(&format!(r#"value="{COVERAGE_SIGNATURE}|T1059""#))
            // an informational row can't be resolved, so it has no box
            && !managed.contains(&format!(r#"value="{COVERAGE_SIGNATURE}|T1059.001""#))
            && managed.contains(
                "2 rows resolved. 1 row left alone: only open, kept and remove_pending rows can be resolved."
            ),
        "{managed}"
    );
    assert_eq!(bulk_notice(1, 0, 3), "1 row resolved. 3 rows not found.");

    // a signature's page
    let signature = SignatureWorklist {
        signature_uuid: COVERAGE_SIGNATURE.to_owned(),
        signature_family: Some("hunt".to_owned()),
        signature_name: Some(HOSTILE.to_owned()),
        rows: worklist_rows.to_vec(),
        measured: vec![MeasuredTechnique {
            technique: "T1059.001".to_owned(),
            technique_name: Some(HOSTILE.to_owned()),
            tests: vec![MeasuredTest {
                guid: test.guid,
                name: Some(HOSTILE.to_owned()),
                platform: "windows".to_owned(),
            }],
        }],
    };
    let of_signature = signature_href(COVERAGE_SIGNATURE);
    let draw_signature = |manage: bool| {
        drawn_safely(&SignaturePage {
            layout: layout(),
            view: signature_view(tabs("worklist"), &signature, manage, None),
        })
    };
    let plain = draw_signature(false);
    assert!(
        plain.contains(&format!(
            r#"<a href="{page_of}">{HOSTILE_ESCAPED} on windows</a>"#
        )) && plain.contains(r#"<a href="/svs/worklist?f=status%3Aopen">Worklist</a>"#)
            && !plain.contains("<form method=\"post\" action=\"/svs"),
        "{plain}"
    );
    let forms = draw_signature(true);
    let seen = "2023-11-14T22:13:20.000000Z";
    assert!(
        forms.contains(&format!(
            r#"<form method="post" action="{of_signature}/resolve" class="inline">
            <input type="hidden" name="technique" value="T1547">
            <input type="hidden" name="seen" value="{seen}">"#
        )) && forms.contains(r#"<button type="submit" name="resolution" value="keep">Keep</button>"#)
            && forms.contains(r#"<button type="submit" name="resolution" value="remove">Remove</button>"#)
            // only a resolved row has a resolution to clear
            && forms.matches(r#"name="resolution" value="reopen""#).count() == 1
            && forms.contains(&format!(
                r#"<input type="hidden" name="technique" value="T1059"><input type="hidden" name="seen" value="{seen}"><input type="hidden" name="resolution" value="reopen">"#
            ))
            // the informational row has no form
            && forms.matches(r#"name="resolution" value="keep""#).count() == 2,
        "{forms}"
    );
}

/// The Tests, Coverage and Worklist pages through the server: signed out goes to the login; without
/// `svs:run_read` each page and post is 403; with it the pages draw, with no forms, and their errors;
/// `svs:run_manage` adds a test's settings and decisions and the worklist's resolutions, which a stale
/// page can't make; a post from another site is refused; and each write has its audit row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_svs_coverage_pages_need_run_read_then_run_manage() {
    let pinned = |service: Service| {
        service.with_attack_catalog(Arc::new(ace_core::testing::attack_catalog()))
    };
    let stack = stack_of_db(Catalog::new(vec![]), |service, _| {
        Gui::new(pinned(service), Transport::Plain)
    })
    .await;
    let db = stack.test_db.db();
    let service = pinned(stack.service.clone());
    let alice = user(&stack, "alice").await;
    let boss = user(&stack, "boss").await;
    for minor in ["admin", "run_manage", "run_read"] {
        grant_to(&stack, &boss, "svs", minor).await;
    }
    let component = |name: &str| Actor::Internal {
        id: Component::new(name).expect("a valid name"),
    };

    // a test of T1059.001 that expects a hunt tagged T1547, both named by hostile text
    let guid = uuid::Uuid::from_u128(0x7e58);
    sqlx::query(
        "INSERT INTO svs.catalog_tests
             (guid, repository, technique, technique_name, name, description, platforms, test,
              content_hash, commit, path)
         VALUES ($1, 'atomic-red-team', 'T1059.001', 'PowerShell', $2, $2, '{windows}',
                 jsonb_build_object('name', $2), repeat('0', 64), repeat('a', 40),
                 'atomics/T1059.001/T1059.001.yaml')",
    )
    .bind(guid)
    .bind(HOSTILE)
    .execute(db.pool())
    .await
    .expect("a catalog test");
    service
        .set_svs_expectation(
            &boss,
            &guid.to_string(),
            Some("windows"),
            COVERAGE_SIGNATURE,
            "expected",
            None,
            None,
            ace_service::Precondition::None,
            chrono::Utc::now(),
        )
        .await
        .expect("expects the hunt");
    let recorded: ace_core::svs::windows::RecordedHunt =
        serde_json::from_value(serde_json::json!({
            "uuid": COVERAGE_SIGNATURE, "name": HOSTILE, "enabled": true, "latency_seconds": 3600,
            "suppression_seconds": null, "per_group": false, "content_hash": "c".repeat(64),
            "tags": ["mitre:T1547"],
        }))
        .expect("a recorded hunt");
    service
        .sync_hunts(
            &component("hunter"),
            "coverage",
            &[ace_service::LoadedHuntRow {
                kind: "coverage".to_owned(),
                path: "coverage.yaml".to_owned(),
                name: Some(HOSTILE.to_owned()),
                uuid: Some(COVERAGE_SIGNATURE.to_owned()),
                enabled: Some(true),
                frequency: Some("00:10:00".to_owned()),
                error: None,
                svs: Some(recorded),
            }],
        )
        .await
        .expect("records the hunt");
    service
        .write_svs_coverage_snapshot(
            &component("scheduler:svs_coverage_snapshot"),
            None,
            chrono::Utc::now(),
        )
        .await
        .expect("refreshes and files a snapshot");

    let test_page = test_href(guid);
    let signature_page = signature_href(COVERAGE_SIGNATURE);
    let pages = [
        "/svs/tests".to_owned(),
        test_page.clone(),
        "/svs/coverage".to_owned(),
        "/svs/coverage/T1547".to_owned(),
        "/svs/worklist".to_owned(),
        signature_page.clone(),
    ];
    for path in &pages {
        let page = stack.get(path).send().await.expect("answered");
        assert_eq!(page.status(), StatusCode::SEE_OTHER, "{path}");
        assert!(location(&page).starts_with("/login?next="), "{path}");
    }
    let session = session_of(&stack, "alice").await;
    let get = |path: String| stack.get(&path).header("cookie", cookie(&session)).send();
    let post = |path: String, form: Vec<(&'static str, String)>| {
        let form: Vec<(&str, &str)> = form.iter().map(|(k, v)| (*k, v.as_str())).collect();
        stack
            .post(&path, &form)
            .header("cookie", cookie(&session))
            .send()
    };
    let text = async |path: String| {
        let page = get(path.clone()).await.expect("answered");
        assert_eq!(page.status(), StatusCode::OK, "{path}");
        page.text().await.expect("a page")
    };
    let settings = |action: &'static str, minutes: &'static str| {
        post(
            format!("{test_page}/settings"),
            vec![
                ("action", action.to_owned()),
                ("observation_minutes", minutes.to_owned()),
                ("holds_host", "1".to_owned()),
            ],
        )
    };
    let decide = |decision: &'static str, signature: &'static str| {
        post(
            format!("{test_page}/decide"),
            vec![
                ("decision", decision.to_owned()),
                ("platform", "windows".to_owned()),
                ("signature", signature.to_owned()),
            ],
        )
    };
    let resolve = |resolution: &'static str, reason: &'static str, seen: String| {
        post(
            format!("{signature_page}/resolve"),
            vec![
                ("technique", "T1547".to_owned()),
                ("resolution", resolution.to_owned()),
                ("reason", reason.to_owned()),
                ("seen", seen),
            ],
        )
    };
    let bulk = |rows: Vec<String>, resolution: &'static str, back: &'static str| {
        let mut form: Vec<(&'static str, String)> =
            rows.into_iter().map(|row| ("row", row)).collect();
        form.extend([
            ("resolution", resolution.to_owned()),
            ("reason", "bulk".to_owned()),
            ("back", back.to_owned()),
        ]);
        post("/svs/worklist/resolve".to_owned(), form)
    };
    let row_key = format!("{COVERAGE_SIGNATURE}|T1547");

    // without svs:run_read: nothing
    for path in &pages {
        assert_eq!(
            get(path.clone()).await.expect("answered").status(),
            StatusCode::FORBIDDEN,
            "{path}"
        );
    }
    for refused in [
        settings("set", "45").await,
        decide("undecide", COVERAGE_SIGNATURE).await,
        resolve("keep", "why", String::new()).await,
        bulk(vec![row_key.clone()], "keep", "/svs/worklist").await,
    ] {
        assert_eq!(refused.expect("answered").status(), StatusCode::FORBIDDEN);
    }

    // svs:run_read: the pages, with no forms
    grant_to(&stack, &alice, "svs", "run_read").await;
    let svs_writes = || {
        sqlx_count(
            &stack.test_db,
            "SELECT count(*) FROM service.audit WHERE action LIKE '%svs%'",
        )
    };
    let audit = svs_writes().await;
    let tests = text("/svs/tests?f=removed%3Afalse".to_owned()).await;
    assert!(
        tests.contains(&format!(r#"<a href="{test_page}">"#))
            && tests.contains(r#"<span class="badge disposition-secondary">never_run</span>"#)
            && tests.contains(r#"aria-current="page">Tests</a>"#)
            && !tests.contains("<script>alert"),
        "{tests}"
    );
    let folded = get("/svs/tests?technique=t1059&removed=false".to_owned())
        .await
        .expect("answered");
    assert_eq!(folded.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&folded),
        "/svs/tests?f=technique%3AT1059&f=removed%3Afalse"
    );
    let test = text(test_page.clone()).await;
    assert!(
        test.contains(COVERAGE_SIGNATURE)
            && test.contains("<td>expected</td>")
            && test.contains("Its runs get the computed window")
            && !test.contains("<script>alert")
            && !test.contains("<form method=\"post\" action=\"/svs"),
        "{test}"
    );
    let coverage = text("/svs/coverage".to_owned()).await;
    assert!(
        coverage.contains(r#"<a href="/svs/coverage/T1547">T1547</a>"#)
            && coverage.contains(r#"<span class="badge disposition-info">manual</span>"#)
            && coverage.contains("against ATT&#38;CK v99.0: 5 rows")
            && coverage.contains("5 rows: 1 manual, 2 untested, 2 none"),
        "{coverage}"
    );
    let narrowed = text("/svs/coverage?f=state%3Amanual".to_owned()).await;
    assert!(
        narrowed.contains("1 rows: 1 manual") && !narrowed.contains("/svs/coverage/T1059.001"),
        "{narrowed}"
    );
    let drill = text("/svs/coverage/t1547".to_owned()).await;
    assert!(
        drill.contains("Boot or Logon Autostart Execution")
            && drill.contains(&format!(
                "<code class=\"muted\">{COVERAGE_SIGNATURE}</code>"
            ))
            && drill.contains("<td>tagged T1547</td>")
            && drill.contains(&chrono::Utc::now().date_naive().to_string())
            && !drill.contains("<script>alert"),
        "{drill}"
    );
    let worklist = text("/svs/worklist?f=status%3Aopen".to_owned()).await;
    assert!(
        worklist.contains(&format!(r#"<a href="{signature_page}">"#))
            && worklist.contains(r#"<span class="badge disposition-warning">open</span>"#)
            && !worklist.contains("<script>alert")
            && !worklist.contains("<form method=\"post\" action=\"/svs"),
        "{worklist}"
    );
    let signature = text(signature_page.clone()).await;
    assert!(
        signature.contains(&format!(r#"<a href="{test_page}">"#))
            && signature.contains("PowerShell")
            && !signature.contains("<form method=\"post\" action=\"/svs"),
        "{signature}"
    );
    for (path, status) in [
        (
            "/svs/tests?f=technique%3Apowershell",
            StatusCode::BAD_REQUEST,
        ),
        ("/svs/tests?cursor=nope", StatusCode::BAD_REQUEST),
        ("/svs/tests/nope", StatusCode::BAD_REQUEST),
        (
            "/svs/tests/00000000-0000-0000-0000-00000000dead",
            StatusCode::NOT_FOUND,
        ),
        ("/svs/coverage?f=state%3Agreat", StatusCode::BAD_REQUEST),
        ("/svs/coverage?f=tactic%3ATA9999", StatusCode::BAD_REQUEST),
        ("/svs/coverage?cursor=nope", StatusCode::BAD_REQUEST),
        ("/svs/coverage/powershell", StatusCode::BAD_REQUEST),
        ("/svs/coverage/T9999", StatusCode::NOT_FOUND),
        ("/svs/worklist?f=status%3Adone", StatusCode::BAD_REQUEST),
        ("/svs/worklist?cursor=nope", StatusCode::BAD_REQUEST),
        ("/svs/worklist/no-such-signature", StatusCode::NOT_FOUND),
    ] {
        assert_eq!(
            get(path.to_owned()).await.expect("answered").status(),
            status,
            "{path}"
        );
    }
    // reading writes nothing, and a reader's post is the service's refusal
    for refused in [
        settings("set", "45").await,
        decide("undecide", COVERAGE_SIGNATURE).await,
        resolve("keep", "why", String::new()).await,
        bulk(vec![row_key.clone()], "keep", "/svs/worklist").await,
    ] {
        assert_eq!(refused.expect("answered").status(), StatusCode::FORBIDDEN);
    }
    assert_eq!(svs_writes().await, audit);

    // svs:run_manage: a test's settings and decisions
    grant_to(&stack, &alice, "svs", "run_manage").await;
    let test = text(test_page.clone()).await;
    assert!(
        test.contains(&format!(
            r#"<form method="post" action="{test_page}/settings" class="detection-add">"#
        )) && test.contains(r#"<input type="hidden" name="decision" value="undecide">"#)
            && !test.contains(r#"value="clear""#),
        "{test}"
    );
    let set = settings("set", "45").await.expect("answered");
    assert_eq!(set.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&set), format!("{test_page}?done=settings"));
    let after = text(location(&set).to_owned()).await;
    assert!(
        after.contains("The test&#39;s settings are set for runs registered from now on.")
            && after.contains("observed for 45 minutes")
            && after.contains(r#"value="clear""#),
        "{after}"
    );
    for (action, minutes, status) in [
        ("set", "soon", StatusCode::BAD_REQUEST),
        ("set", "0", StatusCode::BAD_REQUEST),
        ("burn", "45", StatusCode::BAD_REQUEST),
    ] {
        assert_eq!(
            settings(action, minutes).await.expect("answered").status(),
            status,
            "{action} {minutes}"
        );
    }
    let cleared = settings("clear", "").await.expect("answered");
    assert_eq!(location(&cleared), format!("{test_page}?done=cleared"));
    assert_eq!(
        settings("clear", "").await.expect("answered").status(),
        StatusCode::NOT_FOUND
    );
    for (decision, signature, status) in [
        ("promote", COVERAGE_SIGNATURE, StatusCode::BAD_REQUEST),
        // nothing is ignored, and a global ignore is svs:admin's
        ("unignore", COVERAGE_SIGNATURE, StatusCode::NOT_FOUND),
        (
            "unignore_globally",
            COVERAGE_SIGNATURE,
            StatusCode::FORBIDDEN,
        ),
        ("undecide", "no-such-signature", StatusCode::NOT_FOUND),
    ] {
        assert_eq!(
            decide(decision, signature)
                .await
                .expect("answered")
                .status(),
            status,
            "{decision}"
        );
    }
    assert_eq!(
        post(
            "/svs/tests/nope/settings".to_owned(),
            vec![("action", "clear".to_owned())]
        )
        .await
        .expect("answered")
        .status(),
        StatusCode::BAD_REQUEST
    );

    // the worklist's resolutions: one row from the signature's page, with what the page showed
    let signature = text(signature_page.clone()).await;
    let seen = signature
        .split(r#"name="seen" value=""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("the row's updated_at")
        .to_owned();
    assert!(
        signature.contains(&format!(
            r#"<form method="post" action="{signature_page}/resolve" class="inline">"#
        )) && !signature.contains(r#"value="reopen""#),
        "{signature}"
    );
    let kept = resolve("keep", "a test can't reach it", seen.clone())
        .await
        .expect("answered");
    assert_eq!(kept.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&kept), format!("{signature_page}?done=keep"));
    let after = text(location(&kept).to_owned()).await;
    assert!(
        after.contains("The tag is kept: it covers something no test reaches.")
            && after.contains(r#"<span class="badge disposition-info">kept</span>"#)
            && after.contains("keep: a test can&#39;t reach it")
            && after.contains(r#"value="reopen""#),
        "{after}"
    );
    // the same form again, from the page as it was: refused, not resolved twice
    assert_eq!(
        resolve("remove", "from a stale page", seen.clone())
            .await
            .expect("answered")
            .status(),
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(
        resolve("reopen", "", seen)
            .await
            .expect("answered")
            .status(),
        StatusCode::PRECONDITION_FAILED
    );
    for (resolution, reason, seen, status) in [
        ("maybe", "why", "", StatusCode::BAD_REQUEST),
        ("keep", " ", "", StatusCode::BAD_REQUEST),
        ("keep", "why", "yesterday", StatusCode::BAD_REQUEST),
    ] {
        assert_eq!(
            resolve(resolution, reason, seen.to_owned())
                .await
                .expect("answered")
                .status(),
            status,
            "{resolution}"
        );
    }
    let reopened = resolve("reopen", "", String::new())
        .await
        .expect("answered");
    assert_eq!(location(&reopened), format!("{signature_page}?done=reopen"));
    assert_eq!(
        resolve("reopen", "", String::new())
            .await
            .expect("answered")
            .status(),
        StatusCode::NOT_FOUND
    );
    // a row of another signature's page, and a row that can't be resolved
    assert_eq!(
        post(
            "/svs/worklist/no-such-signature/resolve".to_owned(),
            vec![
                ("technique", "T1547".to_owned()),
                ("resolution", "keep".to_owned()),
                ("reason", "why".to_owned()),
            ],
        )
        .await
        .expect("answered")
        .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        post(
            format!("{signature_page}/resolve"),
            vec![
                ("technique", "T1059.001".to_owned()),
                ("resolution", "keep".to_owned()),
                ("reason", "why".to_owned()),
            ],
        )
        .await
        .expect("answered")
        .status(),
        StatusCode::CONFLICT
    );

    // the ticked rows from the list
    let worklist = text("/svs/worklist?f=status%3Aopen".to_owned()).await;
    assert!(
        worklist.contains(&format!(
            r#"<input type="checkbox" name="row" value="{row_key}" form="worklist-resolve""#
        )) && worklist
            .contains(r#"<input type="hidden" name="back" value="/svs/worklist?f=status%3Aopen">"#),
        "{worklist}"
    );
    let done = bulk(
        vec![
            row_key.clone(),
            format!("{COVERAGE_SIGNATURE}|T1059.001"),
            "no-such-signature|T1547".to_owned(),
        ],
        "remove",
        "/svs/worklist?f=status%3Aopen",
    )
    .await
    .expect("answered");
    assert_eq!(done.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&done),
        "/svs/worklist?f=status%3Aopen&done=bulk&ok=1&left=1&missing=1"
    );
    let said = text(location(&done).to_owned()).await;
    assert!(
        said.contains(
            "1 row resolved. 1 row left alone: only open, kept and remove_pending rows can be \
             resolved. 1 row not found."
        ) && said.contains("No worklist rows."),
        "{said}"
    );
    // a notice is counts, never text from the address
    let forged = text("/svs/worklist?done=bulk&ok=%3Cb%3E&said=%3Cscript%3E".to_owned()).await;
    assert!(
        forged.contains("0 rows resolved.")
            && !forged.contains("<script>")
            && !forged.contains("<b>"),
        "{forged}"
    );
    // it goes back to the worklist and nowhere else
    let elsewhere = bulk(vec![row_key.clone()], "keep", "https://evil.example/")
        .await
        .expect("answered");
    assert!(
        location(&elsewhere).starts_with("/svs/worklist?done=bulk"),
        "{}",
        location(&elsewhere)
    );
    for (rows, resolution, status) in [
        (vec![], "keep", StatusCode::BAD_REQUEST),
        (vec!["no-bar".to_owned()], "keep", StatusCode::BAD_REQUEST),
        (vec![row_key.clone()], "maybe", StatusCode::BAD_REQUEST),
    ] {
        assert_eq!(
            bulk(rows, resolution, "/svs/worklist")
                .await
                .expect("answered")
                .status(),
            status,
            "{resolution}"
        );
    }

    // a post from another site's page is refused, and changes nothing
    let before = svs_writes().await;
    for path in [
        format!("{signature_page}/resolve"),
        "/svs/worklist/resolve".to_owned(),
        format!("{test_page}/settings"),
        format!("{test_page}/decide"),
    ] {
        let cross = stack
            .http
            .post(format!("{}{path}", stack.url))
            .header("origin", "https://evil.example")
            .header("cookie", cookie(&session))
            .form(&[
                ("technique", "T1547"),
                ("resolution", "reopen"),
                ("row", row_key.as_str()),
                ("action", "clear"),
                ("decision", "undecide"),
                ("signature", COVERAGE_SIGNATURE),
                ("platform", "windows"),
            ])
            .send()
            .await
            .expect("answered");
        assert_eq!(cross.status(), StatusCode::FORBIDDEN, "{path}");
    }
    assert_eq!(svs_writes().await, before);

    // the expectation's removal, last: the signature is no longer measured
    let undecided = decide("undecide", COVERAGE_SIGNATURE)
        .await
        .expect("answered");
    assert_eq!(location(&undecided), format!("{test_page}?done=undecide"));
    // settings set and cleared; kept, reopened, removed in bulk, kept in bulk; undecided
    assert_eq!(svs_writes().await, audit + 7);
    assert_eq!(last_action(&stack).await, "remove_svs_expectation");
}

// ---- the help area (PLAN.md 5.11's help area, built with 7.10 batch 9) ----
//
// ace3's tests/app/help: test_help_rendering.py (6), test_help_content.py (5 kinds) and
// test_help_pages.py (10). Each test names the cases it ports. What differs: guides and images are
// embedded in the binary, so "the file exists" is the build, an image is looked up by name and a path
// can't leave `images/`, and a guide's links to GUI pages are asked of the server, where ace3 asks its
// URL map.

use ace_gui::help::{GUIDE_SETS, GuideSet, RenderedGuide, render_markdown};

/// `test_guide_links_drop_the_md_suffix`.
#[test]
fn guide_links_drop_the_md_suffix() {
    let html =
        render_markdown("[review](users.md#reviewing-a-run) [admin](administrators.md)").html;
    let html = html.as_str();
    assert!(html.contains(r#"href="users#reviewing-a-run""#), "{html}");
    assert!(html.contains(r#"href="administrators""#), "{html}");
}

/// `test_only_absolute_links_open_in_a_new_tab`.
#[test]
fn only_absolute_links_open_in_a_new_tab() {
    let html = render_markdown("[out](https://example.com/x) [in](users.md) [here](#top)").html;
    let html = html.as_str();
    assert!(
        html.contains(
            r#"<a href="https://example.com/x" rel="noopener noreferrer" target="_blank">"#
        ),
        "{html}"
    );
    assert!(html.contains(r#"<a href="users">"#), "{html}");
    assert!(html.contains(r##"<a href="#top">"##), "{html}");
}

/// `test_github_alert_becomes_a_callout`.
#[test]
fn a_github_alert_becomes_a_callout() {
    let html = render_markdown("> [!WARNING]\n> Review sets SIMULATED.").html;
    let html = html.as_str();
    assert!(
        html.contains(r#"<div class="help-callout help-callout-warning">"#),
        "{html}"
    );
    assert!(
        html.contains(r#"<p class="help-callout-title">Warning</p>"#),
        "{html}"
    );
    assert!(!html.contains("[!WARNING]"), "{html}");
    assert!(html.contains("Review sets SIMULATED."), "{html}");
    assert!(html.trim_end().ends_with("</div>"), "{html}");
}

/// `test_plain_blockquote_is_left_alone`.
#[test]
fn a_plain_blockquote_is_left_alone() {
    let html = render_markdown("> just a quote").html;
    let html = html.as_str();
    assert!(html.contains("<blockquote>"), "{html}");
    assert!(!html.contains("help-callout"), "{html}");
}

/// `test_image_links_to_its_full_size_file`.
#[test]
fn an_image_links_to_its_full_size_file() {
    let html = render_markdown("![The runs list](images/runs.png)").html;
    assert!(
        html.as_str().contains(
            r#"<a class="help-image" href="images/runs.png" target="_blank" title="Open the full-size image"><img alt="The runs list" src="images/runs.png"></a>"#
        ),
        "{html}"
    );
}

/// `test_toc_holds_sections_and_subsections_only`, and the ids Python-Markdown's `toc` gives: a
/// heading's text slugged, and a repeated one numbered.
#[test]
fn the_toc_holds_sections_and_subsections_only() {
    let rendered = render_markdown("# Guide\n\n## First\n\n### Inner\n\n#### Deep\n\n## Second\n");
    let sections: Vec<(&str, &str)> = rendered
        .toc
        .iter()
        .map(|e| (e.id.as_str(), e.name.as_str()))
        .collect();
    assert_eq!(sections, [("first", "First"), ("second", "Second")]);
    let inner: Vec<(&str, usize)> = rendered.toc[0]
        .children
        .iter()
        .map(|e| (e.id.as_str(), e.children.len()))
        .collect();
    assert_eq!(inner, [("inner", 0)]);
    let html = rendered.html.as_str();
    assert!(
        html.contains(
            r##"<h2 id="first">First<a class="help-anchor" href="#first" title="Link to this section">#</a></h2>"##
        ),
        "{html}"
    );
    assert!(
        html.contains("<h1>Guide</h1>") && html.contains("<h4>Deep</h4>"),
        "{html}"
    );

    let rendered = render_markdown(
        "## Step 1: take `ownership`\n\n## The svs_samples pool -- and more\n\n## Logs\n\n## Logs\n",
    );
    let ids: Vec<&str> = rendered.toc.iter().map(|e| e.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "step-1-take-ownership",
            "the-svs_samples-pool-and-more",
            "logs",
            "logs_1"
        ]
    );
}

/// What ace-rs's renderer adds to ace3's: a guide's raw HTML is shown as text, and nothing it writes
/// is an inline style or a script, which the pages' policy would refuse.
#[test]
fn a_guide_s_raw_html_is_text_and_a_table_has_no_inline_style() {
    let rendered = render_markdown(
        "<script>alert(1)</script>\n\nan <img src=x onerror=alert(1)> inline\n\n\
         | a | b |\n|:--|--:|\n| 1 | 2 |\n\n[x](users.md \"a \\\"title\\\" <b>\")\n",
    );
    let html = rendered.html.as_str();
    assert!(
        !html.contains("<script") && !html.contains("<img"),
        "{html}"
    );
    assert!(
        html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
        "{html}"
    );
    assert!(
        html.contains("&lt;img src=x onerror=alert(1)&gt;"),
        "{html}"
    );
    assert!(
        html.contains("<table>") && html.contains("<th>a</th>"),
        "{html}"
    );
    assert!(!html.contains("style="), "{html}");
    assert!(
        html.contains(r#"<a href="users" title="a &quot;title&quot; &lt;b&gt;">"#),
        "{html}"
    );
}

/// What a rendered guide refers to: ace3's `_References`.
#[derive(Debug, Default)]
struct GuideReferences {
    hrefs: Vec<String>,
    images: Vec<String>,
    ids: BTreeSet<String>,
    /// Each tag, as written.
    tags: Vec<String>,
}

/// The value of `name="..."` in a tag the renderer wrote, with its entities read back.
fn attribute(tag: &str, name: &str) -> Option<String> {
    let start = tag.find(&format!(" {name}=\""))? + name.len() + 3;
    let end = start + tag[start..].find('"')?;
    Some(
        tag[start..end]
            .replace("&quot;", "\"")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&#39;", "'")
            .replace("&amp;", "&"),
    )
}

fn references(rendered: &RenderedGuide) -> GuideReferences {
    let html = rendered.html.as_str();
    let mut refs = GuideReferences::default();
    let mut rest = html;
    // text's `<` is an entity, so each `<` opens a tag the renderer wrote
    while let Some(open) = rest.find('<') {
        let close = open + rest[open..].find('>').expect("a tag closes");
        let tag = &rest[open..=close];
        rest = &rest[close + 1..];
        if tag.starts_with("</") {
            continue;
        }
        if let Some(id) = attribute(tag, "id") {
            refs.ids.insert(id);
        }
        if tag.starts_with("<a ")
            && let Some(href) = attribute(tag, "href")
        {
            refs.hrefs.push(href);
        }
        if tag.starts_with("<img ") {
            refs.images
                .push(attribute(tag, "src").expect("an image's src"));
        }
        refs.tags.push(tag.to_owned());
    }
    refs
}

fn guide_references(set: &GuideSet, slug: &str) -> GuideReferences {
    references(ace_gui::help::rendered(set.slug, slug).expect("a guide of the set"))
}

/// The files of a directory of this crate's `help/`, by name. A directory that isn't there has none: a set
/// with no images has no `images/`, and one that registered an image without the directory still differs.
/// A name that starts with a dot isn't a guide or an image: macOS's Finder leaves a `.DS_Store` in a
/// directory someone opened, which git ignores.
fn help_files(path: &str) -> BTreeSet<String> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("help")
        .join(path);
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return BTreeSet::new(),
        Err(error) => panic!("reads {}: {error}", directory.display()),
    };
    entries
        .map(|entry| entry.expect("an entry"))
        .filter(|entry| entry.path().is_file())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| !name.starts_with('.'))
        .collect()
}

/// A guide's links to pages of the GUI, as paths.
fn gui_links(refs: &GuideReferences) -> impl Iterator<Item = &str> {
    refs.hrefs
        .iter()
        .filter(|href| href.starts_with('/'))
        .map(|href| href.split(['#', '?']).next().unwrap_or(href))
}

/// test_help_content.py's `test_guide_file_exists`, `test_images_exist` and `test_links_resolve`, for
/// every guide: each guide in the registry is a file of its set and each file is in the registry, each
/// image is one of the set's, and each link is an http(s) or mailto URL, an image, a page of the GUI
/// (asked of the server in `the_help_pages_are_for_anyone_signed_in`), or a guide of the set with a
/// section that is there. And what ace-rs's pages need of a guide: no tag with an inline style, a
/// handler or a script, and none of ace3's screenshots or its `/ace` prefix.
#[test]
fn every_guide_s_links_sections_and_images_resolve() {
    let mut problems = Vec::new();
    for set in GUIDE_SETS {
        let files: BTreeSet<String> = set
            .guides
            .iter()
            .map(|g| format!("{}.md", g.slug))
            .collect();
        assert_eq!(help_files(set.slug), files, "{}", set.slug);
        for guide in set.guides {
            let at = format!("{}/{}", set.slug, guide.slug);
            assert!(guide.source.starts_with("# "), "{at} starts with its title");
            assert!(!guide.source.contains('\r'), "{at} has LF line endings");
            let refs = guide_references(set, guide.slug);
            assert!(!refs.ids.is_empty(), "{at} has sections");
            for tag in &refs.tags {
                let name = tag[1..]
                    .split(|c: char| !c.is_ascii_alphanumeric())
                    .next()
                    .unwrap_or("");
                if !inline_free(tag)
                    || ["script", "style", "iframe", "object", "embed"].contains(&name)
                {
                    problems.push(format!("{at}: {tag}: an inline style, handler or script"));
                }
            }
            for src in &refs.images {
                match src.strip_prefix("images/") {
                    Some(name) if set.image(name).is_some() => {}
                    _ => problems.push(format!("{at}: {src}: no such image in the set")),
                }
            }
            for href in &refs.hrefs {
                if ["http://", "https://", "mailto:"]
                    .iter()
                    .any(|scheme| href.starts_with(scheme))
                {
                    continue;
                }
                if let Some(name) = href.strip_prefix("images/") {
                    if set.image(name).is_none() {
                        problems.push(format!("{at}: {href}: no such image"));
                    }
                    continue;
                }
                if href.starts_with('/') {
                    if href.starts_with("/ace/") || href == "/ace" {
                        problems.push(format!("{at}: {href}: ace-rs's pages have no /ace prefix"));
                    }
                    continue;
                }
                let (path, fragment) = match href.split_once('#') {
                    Some((path, fragment)) => (path, Some(fragment)),
                    None => (href.as_str(), None),
                };
                let target = if path.is_empty() { guide.slug } else { path };
                if set.guide(target).is_none() {
                    problems.push(format!("{at}: {href}: no such guide in {}", set.slug));
                    continue;
                }
                if let Some(fragment) = fragment
                    && !guide_references(set, target).ids.contains(fragment)
                {
                    problems.push(format!("{at}: {href}: no section #{fragment} in {target}"));
                }
            }
        }
    }
    assert_eq!(problems, Vec::<String>::new());
}

/// `test_no_orphan_images`: the set's images are the files of its `images/`, and a guide uses each.
#[test]
fn no_guide_image_is_unused() {
    for set in GUIDE_SETS {
        let mut used = BTreeSet::new();
        for guide in set.guides {
            let refs = guide_references(set, guide.slug);
            for reference in refs.images.iter().chain(&refs.hrefs) {
                if let Some(name) = reference.strip_prefix("images/") {
                    used.insert(name.to_owned());
                }
            }
        }
        let registered: BTreeSet<String> = set.images.iter().map(|i| i.name.to_owned()).collect();
        assert_eq!(
            help_files(&format!("{}/images", set.slug)),
            registered,
            "{}",
            set.slug
        );
        assert_eq!(used, registered, "{}", set.slug);
        for image in set.images {
            assert!(image.content_type.starts_with("image/"), "{}", image.name);
            if image.content_type == "image/svg+xml" {
                // a diagram opened on its own is a document: nothing in it runs or loads
                let text = std::str::from_utf8(image.bytes).expect("an SVG is text");
                for banned in [
                    "<script",
                    "<style",
                    "style=",
                    "href=",
                    "<foreignObject",
                    "\r",
                ] {
                    assert!(!text.contains(banned), "{}: {banned}", image.name);
                }
                assert!(inline_free(text), "{}", image.name);
            } else {
                // a screenshot (tools/help-screenshots/run): a PNG, as wide as every other, and small
                assert_eq!(image.content_type, "image/png", "{}", image.name);
                assert!(image.name.ends_with(".png"), "{}", image.name);
                assert!(
                    image.bytes.starts_with(b"\x89PNG\r\n\x1a\n")
                        && &image.bytes[12..16] == b"IHDR",
                    "{} is a PNG",
                    image.name
                );
                let width = u32::from_be_bytes(image.bytes[16..20].try_into().expect("four bytes"));
                assert_eq!(width, 1280, "{}: every screenshot is this wide", image.name);
                assert!(
                    image.bytes.len() <= 150 * 1024,
                    "{} is {} bytes: shrink it, or cut the page shorter",
                    image.name,
                    image.bytes.len()
                );
            }
        }
        // the binary carries them all
        let screenshots: usize = set
            .images
            .iter()
            .filter(|image| image.content_type == "image/png")
            .map(|image| image.bytes.len())
            .sum();
        assert!(
            screenshots <= 2 * 1024 * 1024,
            "{}: {screenshots} bytes of screenshots",
            set.slug
        );
    }
    // the SVS guides have their diagrams and their screenshots
    let svs = GUIDE_SETS
        .iter()
        .find(|set| set.slug == "svs")
        .expect("the SVS set");
    let count = |kind: &str| {
        svs.images
            .iter()
            .filter(|image| image.content_type == kind)
            .count()
    };
    assert_eq!((count("image/svg+xml"), count("image/png")), (5, 39));
}

/// `test_guide_slugs_are_unique`.
#[test]
fn guide_slugs_are_unique() {
    let mut sets = BTreeSet::new();
    for set in GUIDE_SETS {
        assert!(sets.insert(set.slug), "{}", set.slug);
        let mut slugs = BTreeSet::new();
        for guide in set.guides {
            assert!(slugs.insert(guide.slug), "{}/{}", set.slug, guide.slug);
        }
        // a guide named "images" would be shadowed by the image route
        assert!(!slugs.contains("images"), "{}", set.slug);
        assert!(!set.guides.is_empty(), "{}", set.slug);
    }
}

/// test_help_pages.py through the server: `test_help_requires_login`, `test_help_area_serves_only_get`,
/// `test_index_lists_every_guide`, `test_every_guide_renders_without_permissions`,
/// `test_pager_links_neighbours`, `test_set_redirects_to_its_first_guide`,
/// `test_unknown_pages_are_404` (its five paths), `test_image_is_served`,
/// `test_image_route_stays_in_images` (its five names) and
/// `test_svs_tabs_and_signatures_hub_link_the_guides`; and test_help_content.py's GUI links, each of
/// which is a page this server has.
#[tokio::test]
async fn the_help_pages_are_for_anyone_signed_in() {
    let stack = stack().await;
    // a user holding no permission at all: the guides need only a login
    let reader = user(&stack, "help_reader").await;
    let set = &GUIDE_SETS[0];
    let first = &set.guides[0];
    let guide_path = |slug: &str| format!("/help/{}/{slug}", set.slug);
    let image_path = format!("/help/{}/images/{}", set.slug, set.images[0].name);

    for path in [
        "/help".to_owned(),
        guide_path(first.slug),
        set.href(),
        image_path.clone(),
    ] {
        let page = stack.get(&path).send().await.expect("answered");
        assert_eq!(page.status(), StatusCode::SEE_OTHER, "{path}");
        assert!(location(&page).starts_with("/login?next="), "{path}");
    }

    let session = session_of(&stack, "help_reader").await;
    let get = |path: String| stack.get(&path).header("cookie", cookie(&session)).send();

    // the area serves only GET
    for path in [
        "/help".to_owned(),
        guide_path(first.slug),
        set.href(),
        image_path.clone(),
    ] {
        let post = stack
            .post(&path, &[])
            .header("cookie", cookie(&session))
            .send()
            .await
            .expect("answered");
        assert_eq!(post.status(), StatusCode::METHOD_NOT_ALLOWED, "{path}");
    }

    let index = get("/help".to_owned()).await.expect("answered");
    assert_eq!(index.status(), StatusCode::OK);
    let index = index.text().await.expect("a page");
    assert!(
        index.contains(r#"<a href="/help" aria-current="page">Documentation</a>"#),
        "{index}"
    );
    // nothing here says the reader may open SVS
    assert!(!index.contains(r#"href="/svs""#), "{index}");
    for guide in set.guides {
        assert!(
            index.contains(&format!(r#"<a href="{}"><b>"#, guide_path(guide.slug))),
            "{}",
            guide.slug
        );
    }

    let mut gui_pages = BTreeSet::new();
    for guide in set.guides {
        let page = get(guide_path(guide.slug)).await.expect("answered");
        assert_eq!(page.status(), StatusCode::OK, "{}", guide.slug);
        let csp = page.headers()["content-security-policy"]
            .to_str()
            .expect("text")
            .to_owned();
        assert!(!csp.contains("unsafe"), "{csp}");
        let page = page.text().await.expect("a page");
        assert!(
            page.contains(r#"<article class="help-guide">"#),
            "{}",
            guide.slug
        );
        let title = guide.title.replace('\'', "&#39;");
        assert!(
            page.contains(&format!(r#"<b aria-current="page">{title}</b>"#)),
            "{}: {title}",
            guide.slug
        );
        assert!(page.contains("On this page"), "{}", guide.slug);
        // the page around the guide has no inline style or handler either
        let (head, rest) = page
            .split_once(r#"<article class="help-guide">"#)
            .expect("the guide");
        let (_, tail) = rest.rsplit_once("</article>").expect("the guide ends");
        assert!(inline_free(head) && inline_free(tail), "{}", guide.slug);
        let refs = guide_references(set, guide.slug);
        gui_pages.extend(gui_links(&refs).map(str::to_owned));
    }

    // each page of the GUI a guide links to is one this server has, whether or not this reader may
    // open it
    assert!(gui_pages.contains("/svs/runs"), "{gui_pages:?}");
    for path in &gui_pages {
        let page = get(path.clone()).await.expect("answered");
        assert!(
            ![StatusCode::NOT_FOUND, StatusCode::METHOD_NOT_ALLOWED].contains(&page.status())
                && !page.status().is_server_error(),
            "{path}: {}",
            page.status()
        );
    }

    // the pager links a guide's neighbours
    let [before, middle, after] = [&set.guides[0], &set.guides[1], &set.guides[2]];
    let page = get(guide_path(middle.slug))
        .await
        .expect("answered")
        .text()
        .await
        .expect("a page");
    let pager = page.split(r#"class="help-pager""#).nth(1).expect("a pager");
    assert!(
        pager.contains(&format!(r#"href="{}" rel="prev""#, guide_path(before.slug))),
        "{pager}"
    );
    assert!(
        pager.contains(&format!(r#"href="{}" rel="next""#, guide_path(after.slug))),
        "{pager}"
    );

    // the set goes to its first guide, with or without the slash
    for path in [set.href(), format!("/help/{}", set.slug)] {
        let home = get(path.clone()).await.expect("answered");
        assert_eq!(home.status(), StatusCode::SEE_OTHER, "{path}");
        assert_eq!(location(&home), guide_path(first.slug), "{path}");
    }

    for path in [
        "/help/nope/",
        "/help/nope/beginners",
        "/help/svs/nope",
        "/help/svs/images",
        "/help/nope/images/x.png",
        "/help/svs/beginners.md",
    ] {
        let missing = get(path.to_owned()).await.expect("answered");
        assert_eq!(missing.status(), StatusCode::NOT_FOUND, "{path}");
    }

    // an image is served as it is embedded, and only an image of the set
    for image in set.images {
        let served = get(format!("/help/{}/images/{}", set.slug, image.name))
            .await
            .expect("answered");
        assert_eq!(served.status(), StatusCode::OK, "{}", image.name);
        // a diagram as SVG and a screenshot as PNG
        assert_eq!(
            served.headers()["content-type"].to_str().expect("text"),
            if image.name.ends_with(".png") {
                "image/png"
            } else {
                "image/svg+xml"
            },
            "{}",
            image.name
        );
        assert_eq!(
            served.headers()["cache-control"],
            "private, max-age=3600",
            "{}",
            image.name
        );
        assert_eq!(served.headers()["x-content-type-options"], "nosniff");
        assert_eq!(
            served.bytes().await.expect("a body").as_ref(),
            image.bytes,
            "{}",
            image.name
        );
    }
    for name in [
        "..%2Fbeginners.md",
        "%2E%2E/beginners.md",
        "%2E%2E%2Fbeginners.md",
        "..%2F..%2F..%2Fsrc%2Fhelp.rs",
        "missing.png",
        "beginners.md",
    ] {
        let path = format!("/help/svs/images/{name}");
        let refused = get(path.clone()).await.expect("answered");
        assert_eq!(refused.status(), StatusCode::NOT_FOUND, "{path}");
    }

    // the SVS tabs and the signatures hub link the guides
    grant_to(&stack, &reader, "svs", "run_read").await;
    grant_to(&stack, &reader, "signature", "read").await;
    for path in ["/svs/runs", "/signatures"] {
        let page = get(path.to_owned()).await.expect("answered");
        assert_eq!(page.status(), StatusCode::OK, "{path}");
        let page = page.text().await.expect("a page");
        assert!(page.contains(r#"<a href="/help/svs/">"#), "{path}: {page}");
    }
}

/// PLAN.md 7.10 batch 9: the navigation's SVS entry says how many test runs need attention, to
/// whoever holds `svs:run_read`, as ace3's `svs_nav.js` fills it in: nothing when no run does, the
/// count when some do, and nothing at all for a viewer who can't open SVS.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_svs_link_counts_the_runs_that_need_attention() {
    let stack = stack_of_db(Catalog::new(vec![]), |service, _| {
        // read on every page here, rather than kept for a while
        Gui::new(service, Transport::Plain).with_svs_attention_fresh(std::time::Duration::ZERO)
    })
    .await;
    let alice = user(&stack, "alice").await;
    let _bob = user(&stack, "bob").await;
    let boss = user(&stack, "boss").await;
    for minor in ["admin", "run_register"] {
        grant_to(&stack, &boss, "svs", minor).await;
    }
    grant_to(&stack, &alice, "svs", "run_read").await;
    let alice_session = session_of(&stack, "alice").await;
    let bob_session = session_of(&stack, "bob").await;
    let pages = &stack;
    let home = |session: String| async move {
        pages
            .get("/help")
            .header("cookie", cookie(&session))
            .send()
            .await
            .expect("answered")
            .text()
            .await
            .expect("a page")
    };

    // no run needs attention: the link alone
    let page = home(alice_session.clone()).await;
    assert!(page.contains(r#"<a href="/svs">SVS</a>"#), "{page}");

    // an ended run does
    gui_run(&stack, &boss).await;
    let page = home(alice_session.clone()).await;
    assert!(
        page.contains(
            r#"<a href="/svs">SVS<span class="count" id="svs-nav-count" title="runs that need attention">(1)</span></a>"#
        ),
        "{page}"
    );
    // someone who can't open SVS has neither the link nor the count
    let page = home(bob_session).await;
    assert!(
        !page.contains(r#"href="/svs""#) && !page.contains("svs-nav-count"),
        "{page}"
    );

    // past the cap it says only that there are more
    sqlx::query(
        "INSERT INTO svs.runs
             (uuid, test_guid, platform, test_content_hash, catalog_commit, state, marker, launcher,
              observation_seconds, attribution_seconds)
         SELECT gen_random_uuid(), r.test_guid, 'windows', repeat('0', 64), repeat('a', 40), 'error',
                'svs-' || translate(substr(md5(n::text), 1, 26), '0189', 'abcd'), 'art', 3600, 90000
         FROM svs.runs r, generate_series(1, 120) n",
    )
    .execute(stack.test_db.db().pool())
    .await
    .expect("more runs");
    let page = home(alice_session).await;
    assert!(
        page.contains(r#"title="runs that need attention">(99+)</span>"#),
        "{page}"
    );
}

// ---- PLAN.md 7.17: alert ownership ----

use ace_gui::alert::OwnershipForms;
use ace_gui::list::{BulkPage, LeftAlone, OwnedPage, OwnerOption};
use ace_service::{AlertOwner, OwnerChoice, SkippedAlert};

fn hostile_owner(id: u128) -> AlertOwner {
    AlertOwner {
        id: UserId(uuid::Uuid::from_u128(id)),
        name: HOSTILE.to_owned(),
        username: "jane".to_owned(),
        enabled: true,
    }
}

/// The views of ownership (ace3's `test_manage.py` owner column cases, and its Take and Assign Ownership
/// buttons): the list's Owner column, whose cell narrows the list to that owner and whose header sorts by
/// it; the bulk form's two buttons and the users Assign offers, for a viewer who may; Reset's owner half;
/// the alert page's owner and forms; and the pages that say what was left with its owner, with the form
/// that takes it. An owner's name is a person's text, drawn escaped.
#[test]
fn the_ownership_views_draw_owners_as_text() {
    let (one, two) = (uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2));
    let at = chrono::DateTime::from_timestamp(1_793_000_000, 0).expect("a time");
    let page = ListedPage {
        alerts: vec![
            AlertSummary {
                owner: Some(hostile_owner(7)),
                owned_at: Some(at),
                ..fixture_summary(one, "owned", None)
            },
            fixture_summary(two, "nobody's", None),
        ],
        next: None,
        total: 2,
    };
    let query = ListQuery {
        filters: vec![FilterEntry::text("Owner", false, &["None", "$USER"])],
        ..ListQuery::default()
    };
    let choices = [
        OwnerChoice {
            id: UserId(uuid::Uuid::from_u128(7)),
            name: HOSTILE.to_owned(),
            username: "jane".to_owned(),
        },
        OwnerChoice {
            id: UserId(uuid::Uuid::from_u128(8)),
            name: "plain".to_owned(),
            username: "plain".to_owned(),
        },
    ];
    let draw = |owners: Option<&[OwnerChoice]>| {
        let view = list_view(
            &page,
            &query,
            &ManageColumnsPreference::default(),
            &[],
            &std::collections::HashMap::new(),
            chrono_tz::Tz::UTC,
            Vec::new(),
            None,
            &ace_service::Dispositions::ace3(),
            owners,
        );
        let html = drawn_safely(&ListPage::new(
            Layout::new("n0nce", Theme::Light, Some("alice".to_owned()), "/"),
            view.clone(),
        ));
        (view, html)
    };
    let (view, html) = draw(Some(&choices));

    // the column is where ace3 has it, between the queue and the disposition, and its header sorts
    let ids: Vec<&str> = view.list.headers.iter().map(|header| header.id).collect();
    assert_eq!(
        ids,
        [
            "date",
            "description",
            "queue",
            "owner",
            "disposition",
            "status"
        ]
    );
    let header = &view.list.headers[3];
    assert_eq!(header.label, "Owner");
    assert!(
        header
            .href
            .as_deref()
            .is_some_and(|href| href.contains("sort=owner") && href.contains("dir=asc")),
        "{header:?}"
    );
    // the owner's cell: their name, and a link that puts the Owner filter in place of the one in effect
    let cell = view.list.rows[0]
        .cells
        .iter()
        .find(|cell| cell.id == "owner")
        .expect("the owner's cell");
    assert_eq!(cell.text, HOSTILE);
    let narrows = cell.href.as_deref().expect("a link");
    let decoded = ListQuery::parse(
        &serde_urlencoded::from_str::<Vec<(String, String)>>(narrows.trim_start_matches("/?"))
            .expect("pairs"),
    )
    .expect("a list")
    .query
    .filters;
    assert_eq!(decoded, [FilterEntry::text("Owner", false, &[HOSTILE])]);
    assert!(
        html.contains(&format!(r#"">{HOSTILE_ESCAPED}</a></td>"#)),
        "{html}"
    );
    // nobody's alert has an empty cell and no link
    let empty = view.list.rows[1]
        .cells
        .iter()
        .find(|cell| cell.id == "owner")
        .expect("the owner's cell");
    assert_eq!((empty.text.as_str(), &empty.href), ("", &None));
    assert!(html.contains(r#"<td data-col-id="owner"></td>"#), "{html}");

    // Reset is ace3's default (`_default_filters`): open, nobody's or the viewer's, in the viewer's queue
    // a share link's value is quoted, then the URL's: the `$` of `$USER` twice
    assert_eq!(
        view.reset,
        "/?f=disposition%3AOPEN&f=owner%3ANone%2C%2524USER&f=queue%3A%2524USER_QUEUE"
    );
    // the bulk form's buttons, and who Assign offers
    assert!(view.can_own);
    assert_eq!(
        view.owners,
        [
            OwnerOption {
                id: uuid::Uuid::from_u128(7),
                name: format!("{HOSTILE} (jane)"),
            },
            OwnerOption {
                id: uuid::Uuid::from_u128(8),
                name: "plain".to_owned(),
            },
        ]
    );
    assert!(
        html.contains(r#"<button type="submit" formaction="/alerts/owner" name="owner" value="me""#)
            && html.contains(
                r#"<button type="submit" formaction="/alerts/owner" name="owner" value="assign">Assign</button>"#
            )
            && html.contains(r#"<option value="">nobody (unassign)</option>"#)
            && html.contains(&format!(
                r#"<option value="00000000-0000-0000-0000-000000000007">{HOSTILE_ESCAPED} (jane)</option>"#
            )),
        "{html}"
    );
    // someone who can't write has neither
    let (reader, html) = draw(None);
    assert!(!reader.can_own && reader.owners.is_empty());
    assert!(
        !html.contains("/alerts/owner") && !html.contains("bulk-assignee"),
        "{html}"
    );

    // the alert's page: who owns it and since when, and the forms for a viewer who may
    let (mut tree, comments) = fixture_tree();
    tree.alert.summary.owner = Some(hostile_owner(7));
    tree.alert.summary.owned_at = Some(at);
    let id = tree.alert.summary.id;
    let alert_page = |tree: &AlertTree, ownership: Option<OwnershipForms>| {
        drawn_safely(
            &AlertPage::new(
                Layout::new("n0nce", Theme::Light, Some("alice".to_owned()), "/alerts/x"),
                tree,
                &comments,
                &ObservableActions::empty(),
                &std::collections::BTreeMap::new(),
            )
            .expect("a page")
            .with_ownership(ownership),
        )
    };
    let users = || view.owners.clone();
    let theirs = alert_page(
        &tree,
        Some(OwnershipForms {
            mine: false,
            users: users(),
        }),
    );
    assert!(
        theirs.contains(&format!(
            "<th>Owner</th><td>{HOSTILE_ESCAPED}, since 2026-10-26 07:33:20 UTC</td>"
        )),
        "{theirs}"
    );
    assert!(
        theirs.contains(r#"<form method="post" action="/alerts/owner" class="inline ownership">"#)
            && theirs.contains(&format!(r#"<input type="hidden" name="alert" value="{id}">"#))
            && theirs.contains(&format!(
                r#"<input type="hidden" name="next" value="/alerts/{id}">"#
            ))
            && theirs.contains(r#"<button type="submit" name="owner" value="me""#)
            && theirs.contains(r#"<button type="submit" name="owner" value="assign">Assign</button>"#)
            && theirs.contains(&format!(
                r#"<option value="00000000-0000-0000-0000-000000000007">{HOSTILE_ESCAPED} (jane)</option>"#
            )),
        "{theirs}"
    );
    // their own alert has nothing to take, and can still be handed on
    let mine = alert_page(
        &tree,
        Some(OwnershipForms {
            mine: true,
            users: users(),
        }),
    );
    assert!(
        !mine.contains(r#"name="owner" value="me""#)
            && mine.contains(r#"name="owner" value="assign""#),
        "{mine}"
    );
    // a reader sees who owns it, and no form
    let read_only = alert_page(&tree, None);
    assert!(
        read_only.contains("<th>Owner</th><td>") && !read_only.contains("/alerts/owner"),
        "{read_only}"
    );
    tree.alert.summary.owner = None;
    tree.alert.summary.owned_at = None;
    assert!(alert_page(&tree, None).contains("<th>Owner</th><td>nobody</td>"));

    // what a bulk action left alone, in ace3's words, with the form that takes it
    let skipped = [
        SkippedAlert {
            alert: one,
            owner: UserId(uuid::Uuid::from_u128(7)),
            name: HOSTILE.to_owned(),
        },
        SkippedAlert {
            alert: two,
            owner: UserId(uuid::Uuid::from_u128(8)),
            name: "plain".to_owned(),
        },
    ];
    let left = LeftAlone::of(&skipped).expect("something was left alone");
    assert_eq!(
        left.summary,
        format!("left 2 alerts owned by other analysts alone ({HOSTILE} 1, plain 1)")
    );
    assert_eq!(
        left.take_owned,
        format!(
            "{one}:00000000-0000-0000-0000-000000000007,{two}:00000000-0000-0000-0000-000000000008"
        )
    );
    assert_eq!(LeftAlone::of(&[]), None);
    let layout = || Layout::new("n0nce", Theme::Light, Some("alice".to_owned()), "/");
    let bulk = drawn_safely(&BulkPage {
        layout: layout(),
        disposition: "FALSE_POSITIVE".to_owned(),
        done: vec![uuid::Uuid::from_u128(3)],
        failed: Vec::new(),
        left_alone: Some(left.clone()),
        next: "/?f=disposition:OPEN".to_owned(),
        save_to_event: false,
    });
    assert!(
        bulk.contains(&format!(
            "1 alert dispositioned; left 2 alerts owned by other analysts alone ({HOSTILE_ESCAPED} 1, plain 1)."
        )) && bulk.contains(&format!(
            r#"<li><a href="/alerts/{one}">{one}</a>: owned by {HOSTILE_ESCAPED}</li>"#
        )) && bulk.contains(r#"<form method="post" action="/alerts/disposition" class="take-owned">"#)
            && bulk.contains(&format!(
                r#"<input type="hidden" name="take_owned" value="{}">"#,
                left.take_owned
            ))
            && bulk.contains(r#"<input type="hidden" name="disposition" value="FALSE_POSITIVE">"#)
            && bulk.contains(&format!(r#"<input type="hidden" name="alert" value="{two}">"#)),
        "{bulk}"
    );
    // nothing left alone: no such form
    let plain = drawn_safely(&BulkPage {
        layout: layout(),
        disposition: "FALSE_POSITIVE".to_owned(),
        done: vec![one],
        failed: Vec::new(),
        left_alone: None,
        next: "/".to_owned(),
        save_to_event: false,
    });
    assert!(
        plain.contains("1 alert dispositioned.") && !plain.contains("take_owned"),
        "{plain}"
    );
    let owned = drawn_safely(&OwnedPage {
        layout: layout(),
        heading: "Assign Ownership",
        message: format!("assigned 1 alerts to {HOSTILE}; {}", left.summary),
        applied: vec![uuid::Uuid::from_u128(3)],
        left_alone: left.clone(),
        owner: "assign",
        assignee: "00000000-0000-0000-0000-000000000009".to_owned(),
        next: "/".to_owned(),
    });
    assert!(
        owned.contains("<h1>Assign Ownership</h1>")
            && owned.contains(&format!("<p>assigned 1 alerts to {HOSTILE_ESCAPED}; left 2 alerts"))
            && owned.contains(r#"<form method="post" action="/alerts/owner" class="take-owned">"#)
            && owned.contains(r#"<input type="hidden" name="owner" value="assign">"#)
            && owned.contains(
                r#"<input type="hidden" name="assignee" value="00000000-0000-0000-0000-000000000009">"#
            )
            && owned.contains(&format!(
                r#"<input type="hidden" name="take_owned" value="{}">"#,
                left.take_owned
            )),
        "{owned}"
    );
}

/// Ownership through the server (PLAN.md 7.17): ace3's Take Ownership and Assign Ownership of the ticked
/// alerts and of one from its page, with what another analyst owns left alone until it's confirmed; a
/// bulk disposition doing the same (ace3's `test_set_disposition_leaves_alert_owned_by_another_alone`
/// and `test_set_disposition_takes_confirmed_alert`, and `test_bulk_set_disposition_respects_ownership`,
/// whose event page posts to the same route here); the Owner column, filter and order; and the tip.
#[tokio::test]
async fn ownership_is_taken_and_assigned_through_the_server() {
    let stack = stack().await;
    let db = stack.test_db.db();
    let alice = user(&stack, "alice").await;
    grant_alert_read(&stack, &alice).await;
    let jane = user(&stack, "jane").await;
    grant_alert_read(&stack, &jane).await;
    grant_to(&stack, &jane, "alert", "write").await;
    let id_of = |actor: &Actor| match actor {
        Actor::User { id, .. } => id.0,
        _ => panic!("a user"),
    };
    let (alice_id, jane_id) = (id_of(&alice), id_of(&jane));
    sqlx::query("UPDATE service.users SET display_name = $2 WHERE id = $1")
        .bind(jane_id)
        .bind(HOSTILE)
        .execute(db.pool())
        .await
        .expect("names her");
    let session = session_of(&stack, "alice").await;
    let mut alerts = Vec::new();
    for (title, at) in [
        ("one", "2026-01-01T10:00:00Z"),
        ("two", "2026-01-02T10:00:00Z"),
        ("three", "2026-01-03T10:00:00Z"),
        ("four", "2026-01-04T10:00:00Z"),
        ("five", "2026-01-05T10:00:00Z"),
    ] {
        alerts.push(list_alert(&stack, title, at, None).await);
    }
    let (one, two, three, four, five) = (alerts[0], alerts[1], alerts[2], alerts[3], alerts[4]);
    let give = async |alert: uuid::Uuid, user: uuid::Uuid| {
        sqlx::query("UPDATE analysis.roots SET owner_id = $2, owned_at = now() WHERE id = $1")
            .bind(alert)
            .bind(user)
            .execute(db.pool())
            .await
            .expect("sets the owner");
    };
    let owner_of = async |alert: uuid::Uuid| -> Option<uuid::Uuid> {
        sqlx::query_scalar("SELECT owner_id FROM analysis.roots WHERE id = $1")
            .bind(alert)
            .fetch_one(db.pool())
            .await
            .expect("reads")
    };
    let disposition_of = async |alert: uuid::Uuid| -> Option<String> {
        sqlx::query_scalar("SELECT disposition FROM analysis.roots WHERE id = $1")
            .bind(alert)
            .fetch_one(db.pool())
            .await
            .expect("reads")
    };
    give(two, jane_id).await;
    give(three, jane_id).await;
    let post = |path: &'static str, form: Vec<(&'static str, String)>| {
        let request = stack
            .http
            .post(format!("{}{path}", stack.url))
            .header("origin", &stack.url)
            .header("cookie", cookie(&session))
            .form(&form);
        async move { request.send().await.expect("answered") }
    };
    let get = |path: String| {
        let request = stack.get(&path).header("cookie", cookie(&session));
        async move {
            let response = request.send().await.expect("answered");
            let status = response.status();
            (status, response.text().await.expect("a page"))
        }
    };
    let take = |ids: &[uuid::Uuid], take_owned: Option<String>| {
        let mut form = vec![("owner", "me".to_owned()), ("next", "/?size=10".to_owned())];
        form.extend(ids.iter().map(|id| ("alert", id.to_string())));
        form.extend(take_owned.map(|pairs| ("take_owned", pairs)));
        form
    };
    let escaped = HOSTILE_ESCAPED;

    // signed out, a post goes to the login; a reader's is refused, and the reader's pages have no forms
    let signed_out = stack
        .post(
            "/alerts/owner",
            &[("owner", "me"), ("alert", &one.to_string())],
        )
        .send()
        .await
        .expect("answered");
    assert_eq!(signed_out.status(), StatusCode::SEE_OTHER);
    assert!(location(&signed_out).starts_with("/login"));
    let audit = stack.audit_count().await;
    let refused = post("/alerts/owner", take(&[one], None)).await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(owner_of(one).await, None);
    assert_eq!(stack.audit_count().await, audit);
    let (status, list) = get("/".to_owned()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!list.contains("/alerts/owner"), "{list}");
    // the Owner column, where ace3 has it, with the owner's name as text
    assert!(
        list.contains(
            r#"<th data-col-id="owner"><a href="/?sort=owner&#38;dir=asc">Owner</a></th>"#
        ),
        "{list}"
    );
    assert_eq!(list.matches(&format!("{escaped}</a></td>")).count(), 2);
    let (_, page) = get(format!("/alerts/{two}")).await;
    assert!(
        page.contains(&format!("<th>Owner</th><td>{escaped}, since "))
            && !page.contains("/alerts/owner"),
        "{page}"
    );

    // alert:write: the forms
    grant_to(&stack, &alice, "alert", "write").await;
    let (_, list) = get("/".to_owned()).await;
    assert!(
        list.contains(r#"formaction="/alerts/owner" name="owner" value="me""#)
            && list.contains(&format!(
                r#"<option value="{jane_id}">{escaped} (jane)</option>"#
            ))
            && list.contains(&format!(r#"<option value="{alice_id}">alice</option>"#)),
        "{list}"
    );
    assert!(inline_free(&list.replace(escaped, "")), "{list}");

    // take: jane's alert is left alone, in ace3's words, and the page has the form that takes it
    let audit = stack.audit_count().await;
    let taken = post("/alerts/owner", take(&[one, two], None)).await;
    assert_eq!(taken.status(), StatusCode::OK);
    let page = taken.text().await.expect("a page");
    assert!(
        page.contains("<h1>Take Ownership</h1>")
            && page.contains(&format!(
                "<p>took ownership of 1 alerts; left 1 alert owned by {escaped} alone.</p>"
            ))
            && page.contains(&format!(
                r#"<li><a href="/alerts/{two}">{two}</a>: owned by {escaped}</li>"#
            ))
            && page.contains(&format!(
                r#"<input type="hidden" name="take_owned" value="{two}:{jane_id}">"#
            ))
            && page.contains(r#"<a href="/?size=10">Back</a>"#),
        "{page}"
    );
    assert!(!page.contains("<script>alert") && inline_free(&page.replace(escaped, "")));
    assert_eq!(owner_of(one).await, Some(alice_id));
    assert_eq!(owner_of(two).await, Some(jane_id));
    assert_eq!(stack.audit_count().await, audit + 1, "the one that changed");
    assert_eq!(last_action(&stack).await, "change_alert_owner");

    // a confirmation that names someone who doesn't have it changes nothing
    let stale = post(
        "/alerts/owner",
        take(&[two], Some(format!("{two}:{alice_id}"))),
    )
    .await;
    assert_eq!(stale.status(), StatusCode::OK);
    assert_eq!(owner_of(two).await, Some(jane_id));
    // confirmed: taken, and back where it came from
    let confirmed = post(
        "/alerts/owner",
        take(&[two], Some(format!("{two}:{jane_id}"))),
    )
    .await;
    assert_eq!(confirmed.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&confirmed), "/?size=10");
    assert_eq!(owner_of(two).await, Some(alice_id));

    // assign to jane, and to nobody
    let assign = |ids: &[uuid::Uuid], assignee: String| {
        let mut form = vec![
            ("owner", "assign".to_owned()),
            ("assignee", assignee),
            ("disposition", "IGNORE".to_owned()),
        ];
        form.extend(ids.iter().map(|id| ("alert", id.to_string())));
        form
    };
    let assigned = post("/alerts/owner", assign(&[four, one], jane_id.to_string())).await;
    assert_eq!(assigned.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&assigned), "/");
    assert_eq!(owner_of(four).await, Some(jane_id));
    assert_eq!(owner_of(one).await, Some(jane_id));
    assert_eq!(
        disposition_of(four).await,
        None,
        "the form's other fields do nothing"
    );
    let unassigned = post("/alerts/owner", assign(&[two], String::new())).await;
    assert_eq!(unassigned.status(), StatusCode::SEE_OTHER);
    assert_eq!(owner_of(two).await, None);
    // unassigning someone else's is left alone too
    let left = post("/alerts/owner", assign(&[four], String::new())).await;
    assert_eq!(left.status(), StatusCode::OK);
    let page = left.text().await.expect("a page");
    assert!(
        page.contains("<h1>Assign Ownership</h1>")
            && page.contains(&format!(
                "unassigned 0 alerts; left 1 alert owned by {escaped} alone"
            ))
            && page.contains(r#"<input type="hidden" name="owner" value="assign">"#)
            && page.contains(r#"<input type="hidden" name="assignee" value="">"#),
        "{page}"
    );
    assert_eq!(owner_of(four).await, Some(jane_id));

    // requests that aren't ones
    let audit = stack.audit_count().await;
    for bad in [
        vec![("owner", "them".to_owned()), ("alert", five.to_string())],
        vec![("alert", five.to_string())],
        vec![("owner", "me".to_owned())],
        vec![("owner", "me".to_owned()), ("alert", "x".to_owned())],
        assign(&[five], "x".to_owned()),
        // a user who isn't there
        assign(&[five], uuid::Uuid::new_v4().to_string()),
        std::iter::once(("owner", "me".to_owned()))
            .chain((0..=ace_gui::list::MAX_BULK).map(|_| ("alert", five.to_string())))
            .collect(),
    ] {
        let response = post("/alerts/owner", bad.clone()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{bad:?}");
    }
    // another site's page can't take an alert with alice's cookie
    let cross = stack
        .http
        .post(format!("{}/alerts/owner", stack.url))
        .header("origin", "https://evil.example")
        .header("cookie", cookie(&session))
        .form(&[("owner", "me"), ("alert", &five.to_string())])
        .send()
        .await
        .expect("answered");
    assert_eq!(cross.status(), StatusCode::FORBIDDEN);
    assert_eq!(owner_of(five).await, None);
    // and a GET is refused and changes nothing (ace3's `test_http_verbs.py`, whose `set_owner` once
    // wrote from a query string)
    let (status, _) = get(format!("/alerts/owner?owner=me&alert={five}")).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(owner_of(five).await, None);
    assert_eq!(stack.audit_count().await, audit);

    // a bulk disposition leaves jane's alert alone and takes the one nobody owned
    let dispose = |ids: &[uuid::Uuid], take_owned: Option<String>| {
        let mut form = vec![
            ("disposition", "FALSE_POSITIVE".to_owned()),
            ("next", "/".to_owned()),
        ];
        form.extend(ids.iter().map(|id| ("alert", id.to_string())));
        form.extend(take_owned.map(|pairs| ("take_owned", pairs)));
        form
    };
    let done = post("/alerts/disposition", dispose(&[three, five], None)).await;
    assert_eq!(done.status(), StatusCode::OK);
    let page = done.text().await.expect("a page");
    assert!(
        page.contains(&format!(
            "<p>1 alert dispositioned; left 1 alert owned by {escaped} alone.</p>"
        )) && page.contains(&format!(
            r#"<input type="hidden" name="take_owned" value="{three}:{jane_id}">"#
        )) && page
            .contains(r#"<form method="post" action="/alerts/disposition" class="take-owned">"#),
        "{page}"
    );
    assert!(inline_free(&page.replace(escaped, "")), "{page}");
    assert_eq!(disposition_of(three).await, None);
    assert_eq!(owner_of(three).await, Some(jane_id));
    assert_eq!(
        disposition_of(five).await.as_deref(),
        Some("FALSE_POSITIVE")
    );
    assert_eq!(
        owner_of(five).await,
        Some(alice_id),
        "a disposition takes it"
    );
    // the take_owned field is the analyst agreeing to take the alert from its owner
    let done = post(
        "/alerts/disposition",
        dispose(&[three], Some(format!("{three}:{jane_id}"))),
    )
    .await;
    assert_eq!(done.status(), StatusCode::OK);
    let page = done.text().await.expect("a page");
    assert!(
        page.contains("<p>1 alert dispositioned.</p>") && !page.contains("take_owned"),
        "{page}"
    );
    assert_eq!(
        disposition_of(three).await.as_deref(),
        Some("FALSE_POSITIVE")
    );
    assert_eq!(owner_of(three).await, Some(alice_id));

    // the list by owner: $USER is alice, and the order is by what each owner is called
    let ids = |list: &[uuid::Uuid]| list.iter().map(|id| id.to_string()).collect::<Vec<_>>();
    let (status, mine) = get("/?f=owner:$USER".to_owned()).await;
    assert_eq!(status, StatusCode::OK, "{mine}");
    assert_eq!(row_ids(&mine), ids(&[five, three]));
    let (_, nobodys) = get("/?f=owner:None".to_owned()).await;
    assert_eq!(row_ids(&nobodys), ids(&[two]));
    let (_, hers) = get("/?f=owner:jane".to_owned()).await;
    assert_eq!(row_ids(&hers), ids(&[four, one]));
    // nobody's first, then jane's by her display name, which starts with a quote, then alice's
    let (status, sorted) = get("/?sort=owner&dir=asc".to_owned()).await;
    assert_eq!(status, StatusCode::OK, "{sorted}");
    let by_id = |mut pair: [uuid::Uuid; 2]| {
        pair.sort();
        pair
    };
    let (janes, alices) = (by_id([one, four]), by_id([three, five]));
    assert_eq!(
        row_ids(&sorted),
        ids(&[two, janes[0], janes[1], alices[0], alices[1]])
    );
    assert!(sorted.contains("Owner↑"), "{sorted}");
    // paged one at a time, the cursor carries the owner's name, hostile text and all
    let mut seen = Vec::new();
    let mut path = "/?sort=owner&dir=asc&size=1".to_owned();
    loop {
        let (status, page) = get(path.clone()).await;
        assert_eq!(status, StatusCode::OK, "{path}: {page}");
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
    assert_eq!(seen, ids(&[two, janes[0], janes[1], alices[0], alices[1]]));
    // Reset is ace3's default: open alerts that are nobody's or the viewer's, in the viewer's queue
    assert!(
        sorted.contains(r#"<a href="/?f=disposition%3AOPEN&#38;f=owner%3ANone%2C%2524USER&#38;f=queue%3A%2524USER_QUEUE&#38;sort=owner&#38;dir=asc">Reset</a>"#),
        "{sorted}"
    );
    let reset_link = "/?f=disposition%3AOPEN&f=owner%3ANone%2C%2524USER&f=queue%3A%2524USER_QUEUE";
    let (status, reset) = get(reset_link.to_owned()).await;
    assert_eq!(status, StatusCode::OK, "{reset}");
    assert_eq!(row_ids(&reset), ids(&[two]));
    // its queue half: an open alert nobody owns in another queue isn't in it, and when the viewer works
    // that queue the same link shows it and not the one left behind
    let elsewhere = list_alert(
        &stack,
        "six, in another queue",
        "2026-01-06T10:00:00Z",
        None,
    )
    .await;
    sqlx::query("UPDATE analysis.roots SET queue = 'intel' WHERE id = $1")
        .bind(elsewhere)
        .execute(db.pool())
        .await
        .expect("sets its queue");
    let (_, reset) = get(reset_link.to_owned()).await;
    assert_eq!(
        row_ids(&reset),
        ids(&[two]),
        "another queue's alert is left out"
    );
    let (_, without_queue) =
        get("/?f=disposition%3AOPEN&f=owner%3ANone%2C%2524USER".to_owned()).await;
    assert_eq!(row_ids(&without_queue), ids(&[elsewhere, two]));
    sqlx::query("UPDATE service.users SET queue = 'intel' WHERE id = $1")
        .bind(alice_id)
        .execute(db.pool())
        .await
        .expect("alice works intel");
    let (_, reset) = get(reset_link.to_owned()).await;
    assert_eq!(row_ids(&reset), ids(&[elsewhere]), "the viewer's queue now");
    sqlx::query("UPDATE service.users SET queue = 'default' WHERE id = $1")
        .bind(alice_id)
        .execute(db.pool())
        .await
        .expect("alice works default again");

    // the alert's page: its owner, and the forms; taking from the page comes back to it
    let (_, page) = get(format!("/alerts/{four}")).await;
    assert!(
        page.contains(&format!("<th>Owner</th><td>{escaped}, since "))
            && page.contains(
                r#"<form method="post" action="/alerts/owner" class="inline ownership">"#
            )
            && page.contains(r#"<button type="submit" name="owner" value="me""#),
        "{page}"
    );
    let from_page = |take_owned: Option<String>| {
        let mut form = vec![
            ("owner", "me".to_owned()),
            ("alert", four.to_string()),
            ("next", format!("/alerts/{four}")),
        ];
        form.extend(take_owned.map(|pairs| ("take_owned", pairs)));
        post("/alerts/owner", form)
    };
    let asked = from_page(None).await;
    assert_eq!(asked.status(), StatusCode::OK);
    let asking = asked.text().await.expect("a page");
    assert!(
        asking.contains(&format!(
            "took ownership of 0 alerts; left 1 alert owned by {escaped} alone"
        )) && asking.contains(&format!(
            r#"<input type="hidden" name="next" value="/alerts/{four}">"#
        )),
        "{asking}"
    );
    let taken = from_page(Some(format!("{four}:{jane_id}"))).await;
    assert_eq!(taken.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&taken), format!("/alerts/{four}"));
    let (_, page) = get(format!("/alerts/{four}")).await;
    assert!(
        page.contains("<th>Owner</th><td>alice, since ")
            && !page.contains(r#"name="owner" value="me""#)
            && page.contains(r#"name="owner" value="assign""#),
        "{page}"
    );
    // a next that isn't this site's is the list
    let elsewhere = post(
        "/alerts/owner",
        vec![
            ("owner", "me".to_owned()),
            ("alert", four.to_string()),
            ("next", "//evil.example/".to_owned()),
        ],
    )
    .await;
    assert_eq!(location(&elsewhere), "/");

    // each change left its audit row, by alice
    let owners: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM service.audit
         WHERE action = 'change_alert_owner' AND actor ->> 'name' = 'alice'",
    )
    .fetch_one(db.pool())
    .await
    .expect("counts");
    assert_eq!(
        owners, 6,
        "one, two, four and one to jane, two to nobody, four back"
    );

    // the saved filters page's tip has its $USER half
    let (_, manage) = get("/filters/saved".to_owned()).await;
    assert!(
        manage.contains(
            "Tip: use <code>$USER_QUEUE</code> as a Queue value or <code>$USER</code> as an Owner value"
        ),
        "{manage}"
    );
}

/// Each screen ace3 seeds shows its quick filters, ace3's defaults the first time a person opens it (the
/// owner's decision of 2026-11-15), each a link to the screen with its filters, once: a deleted default
/// stays deleted, and a person's own pinned filter joins them, its name as text.
#[tokio::test]
async fn each_seeded_screen_shows_ace3_s_quick_filters_once() {
    let stack = stack().await;
    let db = stack.test_db.db();
    let alice = user(&stack, "alice").await;
    for (major, minor) in [
        ("svs", "run_read"),
        ("signature", "read"),
        ("remediation", "read"),
        ("file_collection", "read"),
    ] {
        grant_to(&stack, &alice, major, minor).await;
    }
    let session = session_of(&stack, "alice").await;
    let get = |path: &str, session: &str| {
        let request = stack.get(path).header("cookie", cookie(session));
        async move {
            let response = request.send().await.expect("answered");
            let status = response.status();
            (status, response.text().await.expect("a page"))
        }
    };
    let seeds = || {
        sqlx_count(
            &stack.test_db,
            "SELECT count(*) FROM service.saved_filter_seeds",
        )
    };
    let badge = |href: &str, title: &str, name: &str| {
        format!(r#"<a class="badge" href="{href}" title="{title}">{name}</a>"#)
    };
    let screens: [(&str, FilterScreen, Vec<String>); 8] = [
        (
            "/svs/runs",
            FilterScreen::SvsRuns,
            vec![
                badge(
                    "/svs/runs?f=needs_attention%3Atrue",
                    "Runs that ended and wait for review, failed, or changed since they were reviewed",
                    "Needs attention",
                ),
                badge(
                    "/svs/runs?f=state%3Astarted",
                    "Runs in flight: their observation window is open",
                    "Started",
                ),
            ],
        ),
        (
            "/svs/tests",
            FilterScreen::SvsTests,
            vec![badge(
                "/svs/tests?f=removed%3Afalse",
                "Tests still in their repository",
                "In the catalog",
            )],
        ),
        (
            "/svs/coverage",
            FilterScreen::SvsCoverage,
            vec![
                badge(
                    "/svs/coverage?f=platform%3Awindows%2Clinux%2Cmacos&#38;f=retired%3Afalse",
                    "Techniques on windows, linux and macos",
                    "Endpoint platforms",
                ),
                badge(
                    "/svs/coverage?f=platform%3Awindows%2Clinux%2Cmacos&#38;f=state%3Afailing%2Cstale%2Cuntested%2Cnone&#38;f=retired%3Afalse",
                    "Techniques on the endpoint platforms that are failing, stale, untested or not covered at all",
                    "Gaps and failures",
                ),
                badge(
                    "/svs/coverage?f=retired%3Afalse",
                    "Techniques on every platform",
                    "All",
                ),
            ],
        ),
        (
            "/svs/worklist",
            FilterScreen::SvsWorklist,
            vec![
                badge(
                    "/svs/worklist?f=status%3Aopen",
                    "Tags no test confirms that nobody has resolved",
                    "Needs decision",
                ),
                badge(
                    "/svs/worklist?f=status%3Aremove_pending",
                    "Tags resolved remove that the signature still has",
                    "Remove pending",
                ),
                badge(
                    "/svs/worklist?f=status%3Aundeclared",
                    "Techniques signatures are measured on that none of their tags names",
                    "Undeclared",
                ),
            ],
        ),
        (
            "/signatures/samples",
            FilterScreen::SvsSamples,
            vec![
                badge(
                    "/signatures/samples?f=label%3Aconflicted",
                    "Samples whose votes disagree; excluded from validation until relabeled",
                    "Conflicted",
                ),
                badge(
                    "/signatures/samples?f=missing_data%3Atrue",
                    "Samples with a capture that lacks its file or its match record",
                    "Missing data",
                ),
            ],
        ),
        (
            "/signatures/validations",
            FilterScreen::SvsValidations,
            vec![
                badge(
                    "/signatures/validations?f=has_regressions%3Atrue",
                    "Validations whose head no longer matches samples labeled TP",
                    "Has regressions",
                ),
                badge(
                    "/signatures/validations?f=state%3Afailed",
                    "Validations that could not run",
                    "Failed",
                ),
            ],
        ),
        (
            "/remediations",
            FilterScreen::Remediations,
            vec![
                badge(
                    "/remediations?f=status%3ANEW%2CIN_PROGRESS",
                    "Remediations queued or waiting to be tried again",
                    "Not completed",
                ),
                badge(
                    "/remediations?f=result%3AERROR%2CFAILED",
                    "Remediations whose latest attempt failed",
                    "Failed",
                ),
            ],
        ),
        (
            "/file-collections",
            FilterScreen::FileCollections,
            vec![
                badge(
                    "/file-collections?f=status%3ANEW%2CIN_PROGRESS",
                    "Requests queued or waiting to be tried again",
                    "Not completed",
                ),
                badge(
                    "/file-collections?f=result%3AERROR%2CFAILED",
                    "Requests whose latest attempt failed",
                    "Failed",
                ),
            ],
        ),
    ];
    assert_eq!(seeds().await, 0);
    for (at, (path, _, badges)) in screens.iter().enumerate() {
        let (status, page) = get(path, &session).await;
        assert_eq!(status, StatusCode::OK, "{path}: {page}");
        let line = page
            .split(r#"<p class="quick-filters">"#)
            .nth(1)
            .and_then(|rest| rest.split("</p>").next())
            .unwrap_or_else(|| panic!("{path} has no quick filters: {page}"));
        assert_eq!(
            line.trim(),
            format!(
                r#"<span class="label">Quick filters</span> {}"#,
                badges.join(" ")
            ),
            "{path}"
        );
        assert_eq!(
            seeds().await,
            i64::try_from(at).expect("small") + 1,
            "{path}"
        );
        assert!(inline_free(&page), "{path}");
        // each link opens the screen: the screen's own list takes its filters
        for badge in badges {
            let href = badge
                .split("href=\"")
                .nth(1)
                .and_then(|rest| rest.split('"').next())
                .expect("a link")
                .replace("&#38;", "&");
            let (status, opened) = get(&href, &session).await;
            assert_eq!(status, StatusCode::OK, "{href}: {opened}");
        }
    }
    // once: drawing each again seeds nothing more and shows the same
    let audit = stack.audit_count().await;
    for (path, _, badges) in &screens {
        let (_, page) = get(path, &session).await;
        assert!(page.contains(&badges[0]), "{path}");
    }
    assert_eq!(seeds().await, 8);
    assert_eq!(
        stack.audit_count().await,
        audit,
        "a page drawn again writes nothing"
    );

    // a deleted default stays deleted, and the person's own pinned filter is there, as text
    let runs = stack
        .service
        .saved_filters(&alice, FilterScreen::SvsRuns)
        .await
        .expect("lists");
    stack
        .service
        .delete_saved_filter(&alice, runs[0].id)
        .await
        .expect("deletes");
    stack
        .service
        .create_saved_filter(
            &alice,
            FilterScreen::SvsRuns,
            &NewSavedFilter {
                name: HOSTILE.to_owned(),
                description: Some(HOSTILE.to_owned()),
                filters: vec![FilterEntry::text("Launcher", false, &[HOSTILE])],
                quick_filter: true,
                quick_filter_indicator: false,
            },
        )
        .await
        .expect("saves");
    let (_, page) = get("/svs/runs", &session).await;
    let line = page
        .split(r#"<p class="quick-filters">"#)
        .nth(1)
        .and_then(|rest| rest.split("</p>").next())
        .expect("quick filters");
    assert!(
        !line.contains(">Needs attention</a>")
            && line.contains(">Started</a>")
            && line.contains(&format!(
                r#"title="{HOSTILE_ESCAPED}">{HOSTILE_ESCAPED}</a>"#
            )),
        "{line}"
    );
    assert!(
        !page.contains("<script>alert") && inline_free(&page.replace(HOSTILE_ESCAPED, "")),
        "{page}"
    );

    // someone who can't open a screen is refused it and given nothing
    user(&stack, "bob").await;
    let bobs = session_of(&stack, "bob").await;
    for (path, _, _) in &screens {
        let (status, _) = get(path, &bobs).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
    }
    assert_eq!(seeds().await, 8, "alice's eight");
    let _ = db;
}

/// The saved filters pages of a screen that isn't the alert list (the owner's decision of 2026-11-15),
/// called directly: the manage page with the screen's name, its rows opening the screen with their
/// filters, and no alert list's tip; the form a screen's page saves its filter with; and the rename
/// form without the alert list's count. Every name, description and filter value is text.
#[test]
fn another_screen_s_saved_filter_views_draw_as_text() {
    use ace_gui::saved_filters::{
        QuickBar, QuickLink, SaveForm, manage_url_of, manage_view_of, screen_place,
    };

    let mut pinned = fixture_filter(1, HOSTILE, Some(HOSTILE), Some(0));
    pinned.screen = FilterScreen::SvsRuns;
    pinned.quick_filter_indicator = false;
    pinned.filters = vec![FilterEntry::text("Launcher", false, &[HOSTILE])];
    let mut loose = fixture_filter(2, "Started", None, None);
    loose.screen = FilterScreen::SvsRuns;
    loose.filters = vec![FilterEntry::text("State", false, &["started"])];
    let back = "/svs/runs?f=state%3Astarted";
    let view = manage_view_of(FilterScreen::SvsRuns, &[pinned, loose], back);
    assert_eq!(
        view.here,
        "/filters/saved?screen=svs_runs&next=%2Fsvs%2Fruns%3Ff%3Dstate%253Astarted"
    );
    assert_eq!(view.here, manage_url_of(FilterScreen::SvsRuns, back));
    assert_eq!(
        manage_url_of(FilterScreen::SvsRuns, "/svs/runs"),
        "/filters/saved?screen=svs_runs",
        "the screen's own page is where it goes back to anyway"
    );
    assert_eq!(
        (view.screen_label, view.alerts, view.back.as_str()),
        ("SVS Runs", false, back)
    );
    assert_eq!(view.rows[1].href, "/svs/runs?f=state%3Astarted");
    assert_eq!(
        view.rows[1].rename,
        format!(
            "/filters/saved/{}?next=%2Fsvs%2Fruns%3Ff%3Dstate%253Astarted",
            uuid::Uuid::from_u128(2)
        )
    );
    // the hostile launcher is one value of the link, and nothing of the page
    let decoded = ace_service::filters::decode(
        FilterScreen::SvsRuns,
        &serde_urlencoded::from_str::<Vec<(String, String)>>(
            view.rows[0]
                .href
                .strip_prefix("/svs/runs?")
                .expect("the screen's path"),
        )
        .expect("a query")
        .into_iter()
        .map(|(_, f)| f)
        .collect::<Vec<_>>(),
        true,
    )
    .expect("the screen's filters")
    .0;
    assert_eq!(decoded, [FilterEntry::text("Launcher", false, &[HOSTILE])]);
    let page = ManagePage {
        layout: Layout::signed_out("n"),
        view,
    }
    .render()
    .expect("renders");
    assert!(
        page.contains(r#"<a href="/svs/runs?f=state%3Astarted">Back to SVS Runs</a>"#)
            && page.contains(
                "Pinned filters appear as quick filters above the filter form of SVS Runs, in the \
                 order shown here."
            )
            && !page.contains("USER_QUEUE")
            && !page.contains("with its count"),
        "{page}"
    );
    assert_eq!(page.matches(HOSTILE_ESCAPED).count(), 2, "{page}");
    assert!(
        !page.contains("<script>alert") && inline_free(&page.replace(HOSTILE_ESCAPED, "")),
        "{page}"
    );
    let empty = ManagePage {
        layout: Layout::signed_out("n"),
        view: manage_view_of(FilterScreen::SvsWorklist, &[], "/svs/worklist"),
    }
    .render()
    .expect("renders");
    assert!(
        empty.contains(
            "You have no saved filters on the SVS Worklist yet. Set a filter there, then save it \
             under Saved filters."
        ) && empty.contains(r#"<a href="/svs/worklist">Back to the SVS Worklist</a>"#),
        "{empty}"
    );

    // every screen with these pages, and the two without
    let with: Vec<&str> = FilterScreen::ALL
        .iter()
        .filter_map(|screen| screen_place(*screen).map(|(path, _)| path))
        .collect();
    assert_eq!(
        with,
        [
            "/",
            "/remediations",
            "/file-collections",
            "/signatures/samples",
            "/signatures/validations",
            "/svs/tests",
            "/svs/runs",
            "/svs/coverage",
            "/svs/worklist"
        ]
    );
    assert!(screen_place(FilterScreen::DetectionPoints).is_none());
    assert!(screen_place(FilterScreen::SvsCoverageHistory).is_none());

    // the form on a screen's page, in the runs page
    let f = ace_service::filters::encode(
        FilterScreen::SvsRuns,
        &[FilterEntry::text("Launcher", false, &[HOSTILE])],
    )
    .expect("encodes");
    let save = SaveForm::new(FilterScreen::SvsRuns, "/svs/runs", &f);
    assert_eq!(save.screen, "svs_runs");
    assert!(save.next.starts_with("/svs/runs?f=launcher%3A"), "{save:?}");
    assert!(
        save.manage
            .starts_with("/filters/saved?screen=svs_runs&next=%2Fsvs%2Fruns%3Ff%3Dlauncher"),
        "{save:?}"
    );
    assert_eq!(
        SaveForm::new(FilterScreen::SvsRuns, "/svs/runs", &[]).manage,
        "/filters/saved?screen=svs_runs"
    );
    let runs = RunsPage {
        layout: Layout::signed_out("n"),
        quick: QuickBar {
            links: vec![QuickLink {
                label: HOSTILE.to_owned(),
                description: HOSTILE.to_owned(),
                href: "/svs/runs?f=state%3Astarted".to_owned(),
            }],
            save: Some(save),
        },
        view: runs_view(
            Tabs {
                open: "runs",
                admin: false,
            },
            &RunQuery::default(),
            &f,
            0,
            &SuppressionShare {
                missing: 0,
                possibly_suppressed: 0,
                reviewed_runs: 0,
                first_reviewed_at: None,
                trigger_reached: false,
            },
            &[],
            None,
            None,
            false,
            None,
        ),
    }
    .render()
    .expect("renders");
    assert!(
        runs.contains(r#"<summary>Saved filters</summary>"#)
            && runs.contains(r#"<form method="post" action="/filters/saved" class="save-filter">"#)
            && runs.contains(r#"<input type="hidden" name="screen" value="svs_runs">"#)
            && runs.contains(r#"<button type="submit">Save this filter</button>"#)
            && runs.contains(">Manage…</a>"),
        "{runs}"
    );
    // the filter's value is in the form's f and next and the manage link, each time escaped
    assert!(
        runs.contains(&format!(
            r#"title="{HOSTILE_ESCAPED}">{HOSTILE_ESCAPED}</a>"#
        )) && !runs.contains("<script>alert")
            && !runs.contains("<img"),
        "{runs}"
    );
    assert!(
        !runs.contains(r#"name="indicator""#),
        "only the alert list's count"
    );

    // the rename form of another screen's filter has no count
    let edit = EditPage {
        layout: Layout::signed_out("n"),
        id: uuid::Uuid::from_u128(2),
        draft: FilterDraft {
            name: HOSTILE.to_owned(),
            description: HOSTILE.to_owned(),
            indicator: false,
        },
        quick: false,
        next: "/svs/runs".to_owned(),
        manage: "/filters/saved?screen=svs_runs".to_owned(),
        problem: None,
        max_name: 255,
        max_description: 1024,
        alerts: false,
    }
    .render()
    .expect("renders");
    assert!(
        !edit.contains(r#"name="indicator""#)
            && edit.contains("Pin it on Saved filters to show it above its screen's filters.")
            && edit
                .contains(r#"<a href="/filters/saved?screen=svs_runs">Back to Saved filters</a>"#),
        "{edit}"
    );
    assert_eq!(edit.matches(HOSTILE_ESCAPED).count(), 2, "{edit}");
    assert!(inline_free(&edit.replace(HOSTILE_ESCAPED, "")), "{edit}");
}

/// Saved filters of the eight other screens, through the server: each screen's page has the form that
/// saves its filter and the link to its manage page; a filter is saved, pinned, moved, renamed and
/// deleted with the alert list's forms, each under its own screen's permission and with the alert
/// list's audit rows; another person's filter is no filter; a screen's name that isn't one is 404; and
/// a filter's name is text wherever it's drawn.
#[tokio::test]
async fn the_other_screens_manage_their_saved_filters() {
    let stack = stack().await;
    let db = stack.test_db.db();
    // alice opens every screen but the alert list; bob only the alert list; carol nothing
    let alice = user(&stack, "alice").await;
    for (major, minor) in [
        ("svs", "run_read"),
        ("signature", "read"),
        ("remediation", "read"),
        ("file_collection", "read"),
    ] {
        grant_to(&stack, &alice, major, minor).await;
    }
    let bob = user(&stack, "bob").await;
    grant_alert_read(&stack, &bob).await;
    user(&stack, "carol").await;
    let session = session_of(&stack, "alice").await;
    let bobs = session_of(&stack, "bob").await;
    let carols = session_of(&stack, "carol").await;
    let get = |path: String, session: &str| {
        let request = stack.get(&path).header("cookie", cookie(session));
        async move {
            let response = request.send().await.expect("answered");
            let status = response.status();
            (status, response.text().await.expect("a page"))
        }
    };
    let post = |path: String, form: Vec<(&'static str, String)>, session: &str| {
        let request = stack
            .http
            .post(format!("{}{path}", stack.url))
            .header("origin", &stack.url)
            .header("cookie", cookie(session))
            .form(&form);
        async move { request.send().await.expect("answered") }
    };
    let saved = |actor: &Actor, screen: FilterScreen| {
        let (service, actor) = (stack.service.clone(), actor.clone());
        async move { service.saved_filters(&actor, screen).await.expect("lists") }
    };
    let audits_of = |action: &'static str| async move {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM service.audit WHERE action = $1 AND actor ->> 'name' = 'alice'",
        )
        .bind(action)
        .fetch_one(db.pool())
        .await
        .expect("counts")
    };

    // each screen: its page has the form and the link, and a save through it lands on that screen
    let screens: [(&str, FilterScreen, &str, &str); 8] = [
        (
            "/svs/runs",
            FilterScreen::SvsRuns,
            "state:started",
            "SVS Runs",
        ),
        (
            "/svs/tests",
            FilterScreen::SvsTests,
            "removed:false",
            "SVS Tests",
        ),
        (
            "/svs/coverage",
            FilterScreen::SvsCoverage,
            "retired:false",
            "SVS Coverage",
        ),
        (
            "/svs/worklist",
            FilterScreen::SvsWorklist,
            "status:open",
            "the SVS Worklist",
        ),
        (
            "/signatures/samples",
            FilterScreen::SvsSamples,
            "label:conflicted",
            "Samples",
        ),
        (
            "/signatures/validations",
            FilterScreen::SvsValidations,
            "state:failed",
            "Validations",
        ),
        (
            "/remediations",
            FilterScreen::Remediations,
            "status:NEW,IN_PROGRESS",
            "Remediations",
        ),
        (
            "/file-collections",
            FilterScreen::FileCollections,
            "result:ERROR,FAILED",
            "File Collections",
        ),
    ];
    for (path, screen, f, label) in screens {
        let name = screen.name();
        let query = serde_urlencoded::to_string([("f", f)]).expect("encodes");
        let here = format!("{path}?{query}");
        let (status, page) = get(here.clone(), &session).await;
        assert_eq!(status, StatusCode::OK, "{here}: {page}");
        let manage = format!(
            "/filters/saved?{}",
            serde_urlencoded::to_string([("screen", name), ("next", here.as_str())])
                .expect("encodes")
        );
        for part in [
            r#"<form method="post" action="/filters/saved" class="save-filter">"#.to_owned(),
            format!(r#"<input type="hidden" name="screen" value="{name}">"#),
            format!(
                r#"<input type="hidden" name="next" value="{}">"#,
                here.replace('&', "&#38;")
            ),
            format!(r#"<input type="hidden" name="f" value="{f}">"#),
            format!(r#"<a href="{}">Manage…</a>"#, manage.replace('&', "&#38;")),
        ] {
            assert!(page.contains(&part), "{path} lacks {part}: {page}");
        }
        assert!(inline_free(&page), "{path}");
        let before = saved(&alice, screen).await.len();
        let created = audits_of("create_saved_filter").await;
        let made = post(
            "/filters/saved".to_owned(),
            vec![
                ("screen", name.to_owned()),
                ("next", here.clone()),
                ("f", f.to_owned()),
                ("name", HOSTILE.to_owned()),
                ("description", HOSTILE.to_owned()),
                ("quick", "on".to_owned()),
                // only the alert list's quick filters count
                ("indicator", "on".to_owned()),
            ],
            &session,
        )
        .await;
        assert_eq!(made.status(), StatusCode::SEE_OTHER, "{path}");
        assert_eq!(location(&made), here, "{path}");
        assert_eq!(
            audits_of("create_saved_filter").await,
            created + 1,
            "{path}"
        );
        let now = saved(&alice, screen).await;
        assert_eq!(now.len(), before + 1, "{path}");
        let mine = now
            .iter()
            .find(|filter| filter.name == HOSTILE)
            .unwrap_or_else(|| panic!("{path}: {now:?}"));
        assert_eq!(mine.screen, screen);
        assert!(mine.quick_filter_order.is_some() && !mine.quick_filter_indicator);
        assert_eq!(
            ace_service::filters::encode(screen, &mine.filters).expect("encodes"),
            [f.to_owned()],
            "{path}"
        );
        // it's a quick filter on the screen's page, its name as text, and a row of the manage page
        let (_, page) = get(path.to_owned(), &session).await;
        assert!(
            page.contains(&format!(
                r#"title="{HOSTILE_ESCAPED}">{HOSTILE_ESCAPED}</a>"#
            )) && !page.contains("<script>alert")
                && inline_free(&page.replace(HOSTILE_ESCAPED, "")),
            "{path}: {page}"
        );
        let (status, managed) = get(manage.clone(), &session).await;
        assert_eq!(status, StatusCode::OK, "{manage}: {managed}");
        assert!(
            managed.contains(&format!(
                r#"<a href="{}">Back to {label}</a>"#,
                here.replace('&', "&#38;")
            )) && managed.contains(&format!(
                r#"<a href="{here}" title="Open the list with this filter; the link carries the filter, to copy and share">{HOSTILE_ESCAPED}</a>"#
            )) && managed.contains(&format!(r#"<td class="muted">{HOSTILE_ESCAPED}</td>"#))
                && managed.contains(&format!(
                    r#"<form method="post" action="/filters/saved/{}/delete" class="inline">"#,
                    mine.id
                )),
            "{manage}: {managed}"
        );
        assert!(
            !managed.contains("<script>alert")
                && inline_free(&managed.replace(HOSTILE_ESCAPED, "")),
            "{managed}"
        );
        // a second with the same name is refused, as the alert list's is
        let again = post(
            "/filters/saved".to_owned(),
            vec![
                ("screen", name.to_owned()),
                ("f", f.to_owned()),
                ("name", HOSTILE.to_owned()),
            ],
            &session,
        )
        .await;
        assert_eq!(again.status(), StatusCode::CONFLICT, "{path}");
        // the same name on another screen is another filter, so the next screen's save isn't refused

        // bob, who can't open the screen, is refused its manage page and a save on it; carol too
        for other in [&bobs, &carols] {
            let (status, refused) = get(manage.clone(), other).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{manage}");
            assert!(!refused.contains(HOSTILE_ESCAPED), "{refused}");
            let audit = stack.audit_count().await;
            let refused = post(
                "/filters/saved".to_owned(),
                vec![
                    ("screen", name.to_owned()),
                    ("f", f.to_owned()),
                    ("name", "Mine".to_owned()),
                ],
                other,
            )
            .await;
            assert_eq!(refused.status(), StatusCode::FORBIDDEN, "{path}");
            assert_eq!(stack.audit_count().await, audit);
            // and each form on alice's filter finds no filter of theirs
            for (form, fields) in [
                ("", vec![("name", "Theirs".to_owned())]),
                ("/delete", vec![]),
                ("/quick", vec![("pin", "true".to_owned())]),
                ("/move", vec![("to", "up".to_owned())]),
            ] {
                let response =
                    post(format!("/filters/saved/{}{form}", mine.id), fields, other).await;
                assert!(
                    matches!(
                        response.status(),
                        StatusCode::NOT_FOUND | StatusCode::FORBIDDEN | StatusCode::BAD_REQUEST
                    ),
                    "{path}{form}: {}",
                    response.status()
                );
            }
            assert_eq!(
                stack.audit_count().await,
                audit,
                "{path}: nothing was written"
            );
        }
        assert_eq!(
            saved(&alice, screen).await,
            now,
            "{path}: hers are as they were"
        );
    }
    // alice can't open the alert list, so its saved filters aren't hers to manage, as before
    let (status, _) = get("/filters/saved".to_owned(), &session).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let refused = post(
        "/filters/saved".to_owned(),
        vec![
            ("f", "disposition:OPEN".to_owned()),
            ("name", "Open".to_owned()),
        ],
        &session,
    )
    .await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    // a screen that isn't one, or has no page of quick filters
    for name in ["nope", "detection_points", "svs_coverage_history", ""] {
        let (status, page) = get(format!("/filters/saved?screen={name}"), &session).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{name}: {page}");
        let refused = post(
            "/filters/saved".to_owned(),
            vec![("screen", name.to_owned()), ("name", "x".to_owned())],
            &session,
        )
        .await;
        assert_eq!(refused.status(), StatusCode::NOT_FOUND, "{name}");
    }
    // a filter of another screen isn't this screen's: the runs screen has no `status`
    let wrong = post(
        "/filters/saved".to_owned(),
        vec![
            ("screen", "svs_runs".to_owned()),
            ("f", "status:open".to_owned()),
            ("name", "Wrong".to_owned()),
        ],
        &session,
    )
    .await;
    assert_eq!(wrong.status(), StatusCode::BAD_REQUEST);
    // signed out
    let signed_out = stack
        .get("/filters/saved?screen=svs_runs")
        .send()
        .await
        .expect("answered");
    assert_eq!(signed_out.status(), StatusCode::SEE_OTHER);
    assert!(location(&signed_out).starts_with("/login"));
    // from another site
    let audit = stack.audit_count().await;
    let cross = stack
        .http
        .post(format!("{}/filters/saved", stack.url))
        .header("origin", "https://evil.example")
        .header("cookie", cookie(&session))
        .form(&[
            ("screen", "svs_runs"),
            ("f", "state:started"),
            ("name", "Cross"),
        ])
        .send()
        .await
        .expect("answered");
    assert_eq!(cross.status(), StatusCode::FORBIDDEN);
    assert_eq!(stack.audit_count().await, audit);

    // the runs screen: unpin, pin, move, rename and delete, each on its own screen with its audit row
    let runs = || saved(&alice, FilterScreen::SvsRuns);
    let order = || async {
        runs()
            .await
            .into_iter()
            .map(|filter| (filter.name, filter.quick_filter_order))
            .collect::<Vec<_>>()
    };
    // ace3's two defaults, then hers
    assert_eq!(
        order().await,
        [
            ("Needs attention".to_owned(), Some(0)),
            ("Started".to_owned(), Some(1)),
            (HOSTILE.to_owned(), Some(2))
        ]
    );
    let id_of = |name: &'static str| async move {
        runs()
            .await
            .into_iter()
            .find(|filter| filter.name == name)
            .expect("the filter")
            .id
    };
    let (attention, started, mine) = (
        id_of("Needs attention").await,
        id_of("Started").await,
        id_of(HOSTILE).await,
    );
    let manage = "/filters/saved?screen=svs_runs".to_owned();
    let quick = audits_of("set_quick_filters").await;
    let unpinned = post(
        format!("/filters/saved/{started}/quick"),
        vec![("pin", "false".to_owned()), ("next", manage.clone())],
        &session,
    )
    .await;
    assert_eq!(unpinned.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&unpinned), manage);
    assert_eq!(
        order().await,
        [
            ("Needs attention".to_owned(), Some(0)),
            (HOSTILE.to_owned(), Some(1)),
            ("Started".to_owned(), None)
        ]
    );
    let up = post(
        format!("/filters/saved/{mine}/move"),
        vec![("to", "up".to_owned())],
        &session,
    )
    .await;
    assert_eq!(up.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        location(&up),
        "/svs/runs",
        "back to the filter's own screen"
    );
    let pinned = post(
        format!("/filters/saved/{started}/quick"),
        vec![("pin", "true".to_owned())],
        &session,
    )
    .await;
    assert_eq!(location(&pinned), "/svs/runs");
    assert_eq!(
        order().await,
        [
            (HOSTILE.to_owned(), Some(0)),
            ("Needs attention".to_owned(), Some(1)),
            ("Started".to_owned(), Some(2))
        ]
    );
    assert_eq!(audits_of("set_quick_filters").await, quick + 3);
    // a move that isn't one
    for (form, why) in [
        (
            vec![("to", "sideways".to_owned())],
            "a direction that isn't one",
        ),
        (vec![], "no direction"),
    ] {
        let refused = post(format!("/filters/saved/{mine}/move"), form, &session).await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "{why}");
    }
    // the other screens' quick filters are as they were: a pin sets only its own screen's
    assert_eq!(
        saved(&alice, FilterScreen::SvsTests)
            .await
            .iter()
            .map(|filter| filter.quick_filter_order)
            .collect::<Vec<_>>(),
        [Some(0), Some(1)]
    );
    // the manage page: her filter first, with its forms, and no alert list's tip
    let (_, managed) = get(manage.clone(), &session).await;
    assert!(
        managed.contains(r#"<a href="/svs/runs">Back to SVS Runs</a>"#)
            && managed.contains(&format!(r#"<a href="/filters/saved/{mine}">Rename</a>"#))
            && managed.contains(
                r#"<input type="hidden" name="next" value="/filters/saved?screen=svs_runs">"#
            )
            && !managed.contains("USER_QUEUE"),
        "{managed}"
    );
    // rename: the page, without the alert list's count, and the write
    let (status, edit) = get(format!("/filters/saved/{mine}"), &session).await;
    assert_eq!(status, StatusCode::OK, "{edit}");
    assert!(
        edit.contains(&format!(r#"name="name" value="{HOSTILE_ESCAPED}""#))
            && edit
                .contains(r#"<a href="/filters/saved?screen=svs_runs">Back to Saved filters</a>"#)
            && edit.contains(r#"<input type="hidden" name="next" value="/svs/runs">"#)
            && !edit.contains(r#"name="indicator""#),
        "{edit}"
    );
    assert!(inline_free(&edit.replace(HOSTILE_ESCAPED, "")), "{edit}");
    let updated = audits_of("update_saved_filter").await;
    let taken = post(
        format!("/filters/saved/{mine}"),
        vec![("name", "Started".to_owned())],
        &session,
    )
    .await;
    assert_eq!(taken.status(), StatusCode::CONFLICT);
    let renamed = post(
        format!("/filters/saved/{mine}"),
        vec![
            ("name", "In flight <b>".to_owned()),
            ("description", "Mine".to_owned()),
            ("indicator", "on".to_owned()),
            ("next", "/svs/runs".to_owned()),
        ],
        &session,
    )
    .await;
    assert_eq!(renamed.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&renamed), manage);
    assert_eq!(audits_of("update_saved_filter").await, updated + 1);
    let now = stack
        .service
        .saved_filter(&alice, mine)
        .await
        .expect("reads");
    assert_eq!(
        (now.name.as_str(), now.description.as_deref(), now.screen),
        ("In flight <b>", Some("Mine"), FilterScreen::SvsRuns)
    );
    assert!(!now.quick_filter_indicator, "no count off the alert list");
    assert_eq!(now.quick_filter_order, Some(0), "its place is kept");
    let (_, page) = get("/svs/runs".to_owned(), &session).await;
    assert!(
        page.contains(r#"title="Mine">In flight &#60;b&#62;</a>"#)
            && !page.contains("In flight <b>"),
        "{page}"
    );
    // delete
    let deleted_before = audits_of("delete_saved_filter").await;
    let deleted = post(
        format!("/filters/saved/{attention}/delete"),
        vec![("next", manage.clone())],
        &session,
    )
    .await;
    assert_eq!(deleted.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&deleted), manage);
    assert_eq!(audits_of("delete_saved_filter").await, deleted_before + 1);
    assert_eq!(
        order().await,
        [
            ("In flight <b>".to_owned(), Some(0)),
            ("Started".to_owned(), Some(2))
        ]
    );
    let gone = post(
        format!("/filters/saved/{attention}/delete"),
        vec![],
        &session,
    )
    .await;
    assert!(
        matches!(gone.status(), StatusCode::NOT_FOUND | StatusCode::FORBIDDEN),
        "{}",
        gone.status()
    );
    // the audit row of a write names the filter and its screen, as the alert list's does
    let (target, screen_recorded): (String, Option<String>) = sqlx::query_as(
        "SELECT target_id, COALESCE(before ->> 'screen', after ->> 'screen') FROM service.audit
         WHERE action = 'delete_saved_filter' ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(db.pool())
    .await
    .expect("the row");
    assert!(target.contains(&attention.to_string()), "{target}");
    assert_eq!(screen_recorded.as_deref(), Some("svs_runs"));

    // alice loses svs:run_read: the runs screen's filters are no longer hers to manage by id either
    let Actor::User { id: alice_id, .. } = &alice else {
        panic!("a user");
    };
    stack
        .service
        .grant(
            &bootstrap(),
            &Holder::User(*alice_id),
            &PermissionPattern::new("svs", "run_read").expect("a pattern"),
            Effect::Deny,
        )
        .await
        .expect("denies");
    let audit = stack.audit_count().await;
    let (status, _) = get(manage.clone(), &session).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = get(format!("/filters/saved/{mine}"), &session).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    for (form, fields) in [
        ("", vec![("name", "Still mine".to_owned())]),
        ("/delete", vec![]),
        ("/quick", vec![("pin", "false".to_owned())]),
        ("/move", vec![("to", "down".to_owned())]),
    ] {
        let response = post(format!("/filters/saved/{mine}{form}"), fields, &session).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{form}");
    }
    assert_eq!(stack.audit_count().await, audit);
    // and a screen she still opens is still hers
    let (status, _) = get("/filters/saved?screen=svs_samples".to_owned(), &session).await;
    assert_eq!(status, StatusCode::OK);
}

/// PLAN.md 7.11: the search page, `ace_gui::search`, ace3's manage-page search box and its "similar
/// alerts". The view called directly and through the server, with a viewer who may search, one who
/// may not and one signed out, its errors, and hostile text as text. ace3's
/// `tests/app/analysis/views/test_manage.py` search cases are these: the box, the evidence under each
/// alert, the notices, and the count of test-run alerts left out with its link.
mod search_pages {
    use ace_gui::search::{MAX_SNIPPET_CHARS, SearchPage, SearchQuery, search_view};
    use ace_service::search::{
        IndexFuture, Indexed, LaneResult, Scoped, SearchConfig, SearchHit, SearchIndex, SearchLane,
        SearchResponse, SearchResult, Tier,
    };
    use uuid::Uuid;

    use super::*;

    fn pairs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn hit(lane: SearchLane, kind: &str, title: Option<&str>, text: &str) -> SearchHit {
        SearchHit {
            lane,
            kind: kind.to_owned(),
            key: format!("{kind}:{text}"),
            title: title.map(str::to_owned),
            text: text.to_owned(),
            score: 1.0,
            result_id: None,
            observable_id: None,
        }
    }

    /// The view draws what a search found: each alert with its tier and its hits as text, the notices,
    /// the count with the test-run alerts left out, and the pager, with every value escaped.
    #[test]
    fn the_search_view_draws_results_as_text() {
        let (one, two, three) = (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
        let (query, warnings) = SearchQuery::parse(&pairs(&[
            ("q", HOSTILE),
            ("f", "disposition:OPEN"),
            ("f", "!tag:whitelisted"),
            ("page", "2"),
        ]))
        .expect("a search");
        assert!(warnings.is_empty());
        assert_eq!(
            (
                query.q.as_str(),
                query.page,
                query.tests,
                query.filters.len()
            ),
            (HOSTILE, 2, false, 2)
        );
        let long = "x".repeat(MAX_SNIPPET_CHARS + 50);
        let result = |id, title: &str, rank, tier, hits| SearchResult {
            alert: fixture_summary(id, title, None),
            rank,
            tier,
            score: 0.5,
            lanes: vec![SearchLane::Semantic],
            hits,
            dense_score: None,
            sparse_score: None,
        };
        let response = SearchResponse {
            query: HOSTILE.to_owned(),
            total: 47,
            offset: 20,
            limit: 20,
            results: vec![
                result(
                    one,
                    HOSTILE,
                    21,
                    Some(Tier::Exact),
                    vec![
                        hit(
                            SearchLane::Lexical,
                            "observable",
                            Some("ipv4"),
                            "10.20.30.40",
                        ),
                        hit(SearchLane::Semantic, "analysis", Some(HOSTILE), HOSTILE),
                        hit(SearchLane::Semantic, "comment", None, &long),
                        hit(
                            SearchLane::Semantic,
                            "detection",
                            Some("detections"),
                            "a rule matched",
                        ),
                        hit(SearchLane::Semantic, "made-up kind", None, "fifth"),
                        hit(
                            SearchLane::Semantic,
                            "alert",
                            None,
                            "a sixth hit isn't shown",
                        ),
                    ],
                ),
                result(two, "second", 22, Some(Tier::Weak), vec![]),
                result(three, "a listed alert", 23, None, vec![]),
            ],
            lanes_used: vec![SearchLane::Lexical, SearchLane::Semantic],
            excluded_test_alerts: Some(3),
            hint: Some(format!("did you mean ipv4:{HOSTILE}")),
            warnings: vec![
                "The text search failed, so its matches are missing. Try again.".to_owned(),
            ],
            ..SearchResponse::default()
        };
        let view = search_view(
            &query,
            Some(&response),
            vec![HOSTILE.to_owned()],
            chrono_tz::Tz::UTC,
        );
        assert_eq!(view.rows.len(), 3);
        assert_eq!(view.rows[0].tier, Some("exact"));
        assert_eq!(view.rows[0].hits.len(), 5, "ace3's five");
        assert_eq!(
            view.rows[0].hits[2].text.chars().count(),
            MAX_SNIPPET_CHARS + 1,
            "cut, with a mark"
        );
        assert_eq!(
            view.rows[0].hits[4].kind, "other",
            "a kind is one of the index's or none"
        );
        assert_eq!(view.rows[2].tier, None);
        assert_eq!(view.left_out.as_ref().map(|left| left.0), Some(3));
        let html = drawn_safely(&SearchPage {
            layout: Layout::new("n0nce", Theme::Dark, Some("alice".to_owned()), "/search"),
            view,
        });
        for part in [
            // the query back in the box, the filters kept, and the list they lead to
            &format!(r#"name="q" maxlength="2000" value="{HOSTILE_ESCAPED}""#) as &str,
            r#"<input type="hidden" name="f" value="disposition:OPEN">"#,
            r#"<input type="hidden" name="f" value="!tag:whitelisted">"#,
            r#"href="/?f=disposition%3AOPEN&#38;f=%21tag%3Awhitelisted""#,
            r#"href="/help/search/query-language""#,
            // the notices
            &format!(r#"<p class="warning">{HOSTILE_ESCAPED}</p>"#),
            r#"<p class="warning">The text search failed, so its matches are missing. Try again.</p>"#,
            &format!(r#"<p class="search-hint">did you mean ipv4:{HOSTILE_ESCAPED}</p>"#),
            // the count, and what was left out with the link that includes it
            "47 alerts",
            "3 test-run alerts left out.",
            r#"tests=1">Include them</a>"#,
            // each alert, its tier as text, its hits with where they came from
            "<td>21</td>",
            &format!(r#"<a href="/alerts/{one}">{HOSTILE_ESCAPED}</a>"#),
            r#"<span class="search-tier search-tier-exact">exact match</span>"#,
            r#"<div class="search-hit search-hit-observable"><span class="search-hit-kind">observable</span> <span class="search-hit-title">ipv4</span> <span class="search-hit-text">10.20.30.40</span></div>"#,
            &format!(
                r#"<span class="search-hit-title">{HOSTILE_ESCAPED}</span> <span class="search-hit-text">{HOSTILE_ESCAPED}</span>"#
            ),
            r#"<span class="search-tier search-tier-weak">weak match</span>"#,
            r#"<div class="search-hit search-hit-other">"#,
            &format!(r#"<a href="/alerts/{three}">a listed alert</a>"#),
            // the pages either side
            r#"rel="prev">Previous</a>"#,
            r#"page=3" rel="next">Next</a>"#,
        ] {
            assert!(html.contains(part), "{part}: {html}");
        }
        assert!(!html.contains("a sixth hit"), "{html}");
        assert_eq!(
            html.matches("search-evidence").count(),
            2,
            "a listing has no evidence row: {html}"
        );
        assert!(
            !html.contains("data-on-interval"),
            "a search doesn't refresh itself"
        );

        // a query the language refused: its errors, and no count
        let refused = SearchResponse {
            errors: vec![format!("alert_date:{HOSTILE} can't be used")],
            ..SearchResponse::default()
        };
        let html = drawn_safely(&SearchPage {
            layout: Layout::new("n0nce", Theme::Dark, Some("alice".to_owned()), "/search"),
            view: search_view(&query, Some(&refused), Vec::new(), chrono_tz::Tz::UTC),
        });
        assert!(
            html.contains(&format!(
                r#"<p class="error">alert_date:{HOSTILE_ESCAPED} can&#39;t be used</p>"#
            )),
            "{html}"
        );
        assert!(!html.contains(r#"class="count""#), "{html}");
        // nothing asked: the box alone
        let (blank, _) = SearchQuery::parse(&[]).expect("a search");
        let html = drawn_safely(&SearchPage {
            layout: Layout::new("n0nce", Theme::Dark, Some("alice".to_owned()), "/search"),
            view: search_view(&blank, None, Vec::new(), chrono_tz::Tz::UTC),
        });
        assert!(
            html.contains(r#"name="q""#) && !html.contains("Nothing matched"),
            "{html}"
        );
        // similar alerts, with the test runs included and the link that leaves them out
        let (similar, _) =
            SearchQuery::parse(&pairs(&[("similar", &one.to_string()), ("tests", "1")]))
                .expect("a search");
        let found = SearchResponse {
            total: 0,
            ..SearchResponse::default()
        };
        let html = drawn_safely(&SearchPage {
            layout: Layout::new("n0nce", Theme::Dark, Some("alice".to_owned()), "/search"),
            view: search_view(&similar, Some(&found), Vec::new(), chrono_tz::Tz::UTC),
        });
        for part in [
            "<h1>Similar alerts</h1>",
            &format!(r#"Alerts whose text is like <a href="/alerts/{one}">{one}</a>"#) as &str,
            "test-run alerts included.",
            &format!(r#"<a href="/search?similar={one}">Leave them out</a>"#),
            "Nothing matched.",
        ] {
            assert!(html.contains(part), "{part}: {html}");
        }

        // a URL only a hand makes is refused
        for bad in [
            pairs(&[("similar", "not-an-id")]),
            pairs(&[("q", "x"), ("page", "0")]),
            pairs(&[("q", "x"), ("page", "501")]),
            pairs(&[("q", "x"), ("page", "two")]),
            pairs(&[("q", "x"), ("f", "no_such_filter:x")]),
            pairs(&[("q", &"x".repeat(2001))]),
        ] {
            assert!(SearchQuery::parse(&bad).is_err(), "{bad:?}");
        }
    }

    /// An index for the pages' tests: an alert matches a text its title contains.
    #[derive(Debug)]
    struct TitleIndex(ace_core::Db);

    impl TitleIndex {
        async fn titled(&self, pattern: String, scope: &Scoped) -> LaneResult {
            let rows: Vec<(Uuid, String)> = sqlx::query_as(
                "SELECT id, description FROM analysis.roots
                 WHERE alerted_at IS NOT NULL AND description ILIKE $1
                   AND ($2::text[] IS NULL OR NOT queue = ANY ($2)) AND ($3::text[] IS NULL OR queue = ANY ($3))
                   AND ($4::uuid[] IS NULL OR NOT id = ANY ($4))
                 ORDER BY alerted_at, id",
            )
            .bind(pattern)
            .bind(&scope.not_queues)
            .bind(&scope.queues)
            .bind(&scope.except)
            .fetch_all(self.0.pool())
            .await
            .expect("reads");
            rows.into_iter()
                .map(|(alert, title)| {
                    (
                        alert,
                        vec![hit(SearchLane::Semantic, "alert", None, &title)],
                    )
                })
                .collect()
        }
    }

    impl SearchIndex for TitleIndex {
        fn dense<'a>(
            &'a self,
            text: &'a str,
            scope: &'a Scoped,
            _: usize,
            _: usize,
            _: f64,
        ) -> IndexFuture<'a, LaneResult> {
            Box::pin(async move { Ok(self.titled(format!("%{text}%"), scope).await) })
        }

        fn sparse<'a>(
            &'a self,
            _: &'a str,
            _: &'a Scoped,
            _: usize,
            _: usize,
        ) -> IndexFuture<'a, Option<LaneResult>> {
            Box::pin(async { Ok(None) })
        }

        fn similar<'a>(
            &'a self,
            _: Uuid,
            scope: &'a Scoped,
            _: usize,
            _: usize,
            _: f64,
        ) -> IndexFuture<'a, LaneResult> {
            Box::pin(async move { Ok(self.titled("%invoice%".to_owned(), scope).await) })
        }

        fn index_next(&self) -> IndexFuture<'_, Option<Indexed>> {
            Box::pin(async { Ok(None) })
        }
    }

    /// The page through the server: the login page for someone signed out, 403 without `alert:read`, a
    /// search, an exact term, a listing, similar alerts, the test-run alerts left out and included, the
    /// errors, and the two places that lead to it.
    #[tokio::test]
    async fn search_is_asked_through_the_server() {
        let stack = stack_of_db(Catalog::new(vec![]), |service, db| {
            Gui::with_limits(
                service.with_search(Arc::new(TitleIndex(db.clone())), SearchConfig::default()),
                Transport::Plain,
                LiveLimits::default(),
            )
        })
        .await;
        let hostile_title = format!("{HOSTILE} docusign invoice");
        let first = list_alert(&stack, &hostile_title, "2026-03-01T00:00:00Z", None).await;
        let second = list_alert(
            &stack,
            "docusign reminder",
            "2026-03-02T00:00:00Z",
            Some("DELIVERY"),
        )
        .await;
        let test_run = list_alert(
            &stack,
            "docusign invoice test run",
            "2026-03-03T00:00:00Z",
            None,
        )
        .await;
        sqlx::query("UPDATE analysis.roots SET queue = 'svs' WHERE id = $1")
            .bind(test_run)
            .execute(stack.test_db.db().pool())
            .await
            .expect("moved");
        sqlx::query("INSERT INTO analysis.observables (root_id, type, value) VALUES ($1, 'ipv4', '10.20.30.41')")
            .bind(second)
            .execute(stack.test_db.db().pool())
            .await
            .expect("an observable");

        // signed out: the login page, and back here after
        let page = stack
            .get("/search?q=docusign")
            .send()
            .await
            .expect("answered");
        assert_eq!(page.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&page), "/login?next=%2Fsearch%3Fq%3Ddocusign");

        let analyst = user(&stack, "analyst").await;
        grant_alert_read(&stack, &analyst).await;
        let _outsider = user(&stack, "outsider").await;
        let (an, out) = (
            session_of(&stack, "analyst").await,
            session_of(&stack, "outsider").await,
        );
        let get =
            |session: &str, path: &str| stack.get(path).header("cookie", cookie(session)).send();
        let text =
            |response: reqwest::Response| async move { response.text().await.expect("a page") };

        // without alert:read: 403, whatever is asked, and nothing of the alerts
        for path in [
            "/search",
            "/search?q=docusign",
            &format!("/search?similar={first}") as &str,
            "/search?f=disposition:OPEN",
        ] {
            let refused = get(&out, path).await.expect("answered");
            assert_eq!(refused.status(), StatusCode::FORBIDDEN, "{path}");
            let body = text(refused).await;
            assert!(
                body.contains("alert:read") && !body.contains("docusign reminder"),
                "{path}: {body}"
            );
        }

        // the box alone
        let blank = get(&an, "/search").await.expect("answered");
        assert_eq!(blank.status(), StatusCode::OK);
        let body = text(blank).await;
        assert!(
            body.contains(
                r#"<form method="get" action="/search" class="search-box" role="search">"#
            ),
            "{body}"
        );
        assert!(!body.contains("Nothing matched"), "{body}");

        // a search: the alerts found, best first, a hostile title as text, the test run left out and counted
        let found = get(&an, "/search?q=docusign").await.expect("answered");
        assert_eq!(found.status(), StatusCode::OK);
        let body = text(found).await;
        assert!(
            body.contains("2 alerts, and 1 test-run alert left out."),
            "{body}"
        );
        assert!(
            body.contains(&format!(
                r#"<a href="/alerts/{first}">{HOSTILE_ESCAPED} docusign invoice</a>"#
            )),
            "{body}"
        );
        assert!(
            body.contains(&format!(
                r#"<a href="/alerts/{second}">docusign reminder</a>"#
            )),
            "{body}"
        );
        assert!(
            body.contains(r#"<span class="search-hit-text">docusign reminder</span>"#),
            "{body}"
        );
        assert!(body.contains("strong match"), "{body}");
        assert!(
            !body.contains("<script>alert") && !body.contains("test run</a>"),
            "{body}"
        );
        assert!(
            body.contains(r#"href="/search?q=docusign&#38;tests=1">Include them</a>"#),
            "{body}"
        );
        // including them
        let body = text(
            get(&an, "/search?q=docusign&tests=1")
                .await
                .expect("answered"),
        )
        .await;
        assert!(
            body.contains("3 alerts, test-run alerts included."),
            "{body}"
        );
        assert!(
            body.contains(r#"<a href="/search?q=docusign">Leave them out</a>"#),
            "{body}"
        );
        // an exact term first, with what it matched; a filter from a share link narrows it
        let body = text(
            get(&an, "/search?q=docusign+ipv4:10.20.30.41")
                .await
                .expect("answered"),
        )
        .await;
        assert!(
            body.contains("exact match")
                && body.contains(r#"<span class="search-hit-title">ipv4</span>"#),
            "{body}"
        );
        let exact_at = body.find("docusign reminder</a>").expect("the exact match");
        assert!(
            exact_at < body.find("docusign invoice</a>").expect("the other"),
            "exact matches come first: {body}"
        );
        let body = text(
            get(&an, "/search?q=docusign&f=disposition:DELIVERY")
                .await
                .expect("answered"),
        )
        .await;
        assert!(
            body.contains("1 alert")
                && body.contains("docusign reminder</a>")
                && !body.contains("docusign invoice</a>"),
            "{body}"
        );
        assert!(
            body.contains(r#"<input type="hidden" name="f" value="disposition:DELIVERY">"#),
            "{body}"
        );
        // a listing: filters and no text, with no evidence under an alert
        let body = text(
            get(&an, "/search?q=disposition:DELIVERY")
                .await
                .expect("answered"),
        )
        .await;
        assert!(
            body.contains("docusign reminder</a>") && !body.contains("search-evidence"),
            "{body}"
        );
        // similar alerts: the alert itself is never among them
        let body = text(
            get(&an, &format!("/search?similar={second}"))
                .await
                .expect("answered"),
        )
        .await;
        assert!(
            body.contains("<h1>Similar alerts</h1>") && body.contains(&format!("/alerts/{first}")),
            "{body}"
        );
        assert!(
            body.contains("1 alert, and 1 test-run alert left out."),
            "{body}"
        );
        // nothing found, and a bare indicator's hint
        let body = text(get(&an, "/search?q=10.99.99.99").await.expect("answered")).await;
        assert!(
            body.contains("Nothing matched.") && body.contains("ipv4:10.99.99.99"),
            "{body}"
        );
        // a term the language can't honor is said, and nothing is searched
        let wrong = get(&an, "/search?q=docusign+alert_date:-7dd")
            .await
            .expect("answered");
        assert_eq!(wrong.status(), StatusCode::OK);
        let body = text(wrong).await;
        assert!(
            body.contains(r#"<p class="error">alert_date:"#)
                && !body.contains("docusign reminder</a>"),
            "{body}"
        );

        // what only a hand-made URL asks
        for (path, status) in [
            (
                "/search?similar=not-an-id".to_owned(),
                StatusCode::BAD_REQUEST,
            ),
            ("/search?q=x&page=0".to_owned(), StatusCode::BAD_REQUEST),
            (
                "/search?q=x&f=no_such_filter:x".to_owned(),
                StatusCode::BAD_REQUEST,
            ),
            (
                format!("/search?q={}", "x".repeat(2001)),
                StatusCode::BAD_REQUEST,
            ),
            (
                format!("/search?similar={}", Uuid::new_v4()),
                StatusCode::NOT_FOUND,
            ),
        ] {
            let refused = get(&an, &path).await.expect("answered");
            assert_eq!(refused.status(), status, "{path}");
        }

        // the two places that lead here: the alert list's box, with the list's filters, and an alert's page
        let body = text(
            get(&an, "/?f=disposition:DELIVERY")
                .await
                .expect("answered"),
        )
        .await;
        let form = body
            .split(r#"<form method="get" action="/search" class="search-box" role="search">"#)
            .nth(1)
            .and_then(|rest| rest.split("</form>").next())
            .expect("the search box");
        assert!(
            form.contains(r#"<input type="hidden" name="f" value="disposition:DELIVERY">"#),
            "{form}"
        );
        assert!(form.contains(r#"name="q""#), "{form}");
        let body = text(
            get(&an, &format!("/alerts/{second}"))
                .await
                .expect("answered"),
        )
        .await;
        assert!(
            body.contains(&format!(r#"<a href="/search?similar={second}""#)),
            "{body}"
        );
        // and the guide the box links to
        let guide = get(&an, "/help/search/query-language")
            .await
            .expect("answered");
        assert_eq!(guide.status(), StatusCode::OK);
        assert!(text(guide).await.contains("Searching alerts"));
        // nothing here wrote anything
        let audited: i64 = sqlx::query_scalar("SELECT count(*) FROM service.audit WHERE action LIKE '%search%' OR action LIKE '%similar%'")
            .fetch_one(stack.test_db.db().pool())
            .await
            .expect("counts");
        assert_eq!(audited, 0);
    }
}

// ----- pivot links (PLAN.md decision 32 part (b))

/// The smallest PNG the icon check takes: its signature and an IHDR.
const ICON_PNG: &[u8] = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89";

fn icons() -> ace_gui::PivotIcons {
    ace_gui::PivotIcons::builtin()
        .with(ace_gui::PivotIcon::new("example_portal", ICON_PNG).expect("an icon"))
}

/// A result's pivot links are drawn beside it, as ace3 draws an analysis's: each a link out, opened
/// apart, with the registered icon as an image of ACE's own and the label as its alternative text,
/// or the label alone when the binary has no icon of that name; a root's links are the summary's
/// External links. Every label is escaped.
#[test]
fn pivot_links_are_drawn_beside_their_result_and_in_the_summary() {
    let (mut tree, comments) = fixture_tree();
    tree.observables[2].results[0].pivot_links = vec![
        ace_results::PivotLink::new("https://portal.example.com/m/1?a=b&c=d", "Portal <b>")
            .with_icon("example_portal"),
        ace_results::PivotLink::new("https://portal.example.com/m/2", "No icon here")
            .with_icon("unregistered"),
    ];
    tree.alert.pivot_links = vec![ace_results::PivotLink::new(
        "https://hunt.example.com/search?q=1",
        "Hunt search",
    )];
    let icons = icons();
    let icon = icons.get("example_portal").expect("registered").url();
    let view = ace_gui::alert::tree_view_drawn(
        &tree,
        &comments,
        &ObservableActions::empty(),
        &icons,
        ace_gui::alert::TreeMode::Full,
    );
    let html = AlertTreeFragment { tree: view }.render().expect("renders");
    let compact: String = html.lines().map(str::trim).collect();
    let with_icon = format!(
        r#"<a class="pivot" href="https://portal.example.com/m/1?a=b&#38;c=d" rel="noreferrer noopener" target="_blank" title="Portal &#60;b&#62;"><img src="{icon}" alt="Portal &#60;b&#62;" width="12" height="12"></a>"#
    );
    assert!(compact.contains(&with_icon), "{compact}");
    assert!(
        compact.contains(r#"title="No icon here">No icon here</a>"#),
        "an icon the binary hasn't is the label: {compact}"
    );
    // without the binary's icons, the label alone
    let plain = AlertTreeFragment {
        tree: tree_view(&tree, &comments, &ObservableActions::empty()),
    }
    .render()
    .expect("renders");
    assert!(!plain.contains("<img"), "{plain}");
    let layout = || Layout::new("n0nce", Theme::Light, Some("alice".to_owned()), "/alerts/x");
    let page = AlertPage::with(
        layout(),
        &tree,
        &comments,
        &ObservableActions::empty(),
        &std::collections::BTreeMap::new(),
        PageOptions {
            icons: Some(&icons),
            ..PageOptions::default()
        },
    )
    .expect("a page")
    .render()
    .expect("renders");
    let compact: String = page.lines().map(str::trim).collect();
    assert!(
        compact.contains(r#"<h2 id="external-links-title">External links</h2><ul class="plain"><li><a class="pivot" href="https://hunt.example.com/search?q=1" rel="noreferrer noopener" target="_blank">Hunt search</a></li></ul>"#),
        "{compact}"
    );
    // an alert without links draws no such section
    let (bare, comments) = fixture_tree();
    let page = AlertPage::new(
        layout(),
        &bare,
        &comments,
        &ObservableActions::empty(),
        &std::collections::BTreeMap::new(),
    )
    .expect("a page")
    .render()
    .expect("renders");
    assert!(!page.contains("External links"), "{page}");
}

/// The GUI serves each registered icon itself, under a hash of its bytes, as a PNG cached for a year,
/// and nothing else under `/icons/`; the pages' policy still loads images from this origin alone.
#[tokio::test]
async fn the_gui_serves_the_registered_icons_and_nothing_else() {
    let stack = stack_from(|service| Gui::new(service, Transport::Plain).with_icons(icons())).await;
    let url = icons().get("example_portal").expect("registered").url();
    let response = stack.get(&url).send().await.expect("answered");
    assert_eq!(response.status(), StatusCode::OK, "{url}");
    assert_eq!(response.headers()["content-type"], "image/png");
    assert_eq!(
        response.headers()["cache-control"],
        "public, max-age=31536000, immutable"
    );
    let policy = response.headers()["content-security-policy"]
        .to_str()
        .expect("text")
        .to_owned();
    assert!(policy.contains("img-src 'self';"), "{policy}");
    assert_eq!(response.bytes().await.expect("bytes"), ICON_PNG);
    for missing in [
        "/icons/example_portal.png",
        "/icons/example_portal.0000000000000000.png",
        "/icons/unregistered.png",
    ] {
        let response = stack.get(missing).send().await.expect("answered");
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{missing}");
    }
}

/// An icon is a PNG of at most 64 KiB with an icon's name, served under a hash of its bytes; a link
/// shows its icon only when the binary has one by that name, and isn't drawn at all when the core
/// wouldn't have taken it. ace-rs registers none.
#[test]
fn an_icon_is_a_named_png_and_a_link_shows_it_only_when_registered() {
    use ace_gui::icons::{DrawnLink, MAX_ICON_BYTES};
    let icon = ace_gui::PivotIcon::new("example", ICON_PNG).expect("an icon");
    let hash = hex::encode(Sha256::digest(ICON_PNG));
    assert_eq!(icon.url(), format!("/icons/example.{}.png", &hash[..16]));
    assert!(ace_gui::PivotIcon::new("Example", ICON_PNG).is_err());
    assert!(ace_gui::PivotIcon::new("example", b"<svg/>").is_err());
    let big: &'static [u8] = Box::leak(
        [ICON_PNG, &vec![0u8; MAX_ICON_BYTES]]
            .concat()
            .into_boxed_slice(),
    );
    assert!(ace_gui::PivotIcon::new("big", big).is_err());
    let icons = ace_gui::PivotIcons::builtin().with(icon);
    let links = [
        ace_results::PivotLink::new("https://example.com/a", "A").with_icon("example"),
        ace_results::PivotLink::new("https://example.com/b", "B").with_icon("unknown"),
        ace_results::PivotLink::new("http://example.com/c", "C"),
    ];
    let drawn = DrawnLink::of(&links, &icons);
    assert_eq!(drawn.len(), 2, "a link the core wouldn't take isn't drawn");
    assert_eq!(
        drawn[0].icon,
        icons.get("example").map(ace_gui::PivotIcon::url)
    );
    assert_eq!(drawn[1].icon, None);
    assert!(
        ace_gui::PivotIcons::builtin().names().is_empty(),
        "ace-rs ships none"
    );
}

/// The alert list's Observable Pattern filter (PLAN.md decision 39) through the server: a share link and
/// the editor take one, a pattern no index serves is refused as the link is read and saving it writes
/// nothing, and one past its bounds lists nothing and says why, in the page, its refresh and a quick
/// filter's badge, every value escaped.
#[tokio::test]
async fn the_observable_pattern_filter_through_the_list() {
    let stack = stack().await;
    let alice = user(&stack, "alice").await;
    grant_alert_read(&stack, &alice).await;
    let session = session_of(&stack, "alice").await;
    let hit = list_alert(&stack, "hit", "2026-01-01T10:00:00Z", None).await;
    let miss = list_alert(&stack, "miss", "2026-01-02T10:00:00Z", None).await;
    let many = list_alert(&stack, "many", "2026-01-03T10:00:00Z", None).await;
    let db = stack.test_db.db();
    sqlx::query(
        "INSERT INTO analysis.observables (root_id, type, value)
         VALUES ($1, 'fqdn', 'mail.evil.com'), ($2, 'fqdn', 'evil.com.attacker.net')",
    )
    .bind(hit)
    .bind(miss)
    .execute(db.pool())
    .await
    .expect("adds them");
    // 501 observables whose values hold markup
    sqlx::query(
        "INSERT INTO analysis.observables (root_id, type, value)
         SELECT $1, 'fqdn', 'h' || n || '.p<b>st.example' FROM generate_series(1, 501) n",
    )
    .bind(many)
    .execute(db.pool())
    .await
    .expect("adds them");
    let get = |path: &str| {
        let request = stack.get(path).header("cookie", cookie(&session));
        async move {
            let response = request.send().await.expect("answered");
            let status = response.status();
            (status, response.text().await.expect("a page"))
        }
    };

    // a share link's pattern, its chip naming it
    let (status, page) = get("/?f=observable_pattern:fqdn:%2A.evil.com").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(row_ids(&page), [hit.to_string()]);
    assert!(page.contains("Observable Pattern</a>:"), "{page}");
    assert!(
        page.contains(r#"title="Remove this value">fqdn:*.evil.com</a>"#),
        "{page}"
    );
    // the editor offers it, with its hint, and folds one in
    assert!(
        page.contains(r#"<option value="observable_pattern">Observable Pattern</option>"#),
        "{page}"
    );
    assert!(
        page.contains("<dt>Observable Pattern</dt><dd>a type, or Any, and a value with * at its start or end, such as *.evil.com</dd>"),
        "{page}"
    );
    let response = stack
        .get("/?add=observable_pattern&type=fqdn&value=evil.com%2A")
        .header("cookie", cookie(&session))
        .send()
        .await
        .expect("answered");
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let to = location(&response).to_owned();
    assert_eq!(to, "/?f=observable_pattern%3Afqdn%3Aevil.com%252A");
    let (_, page) = get(&to).await;
    assert_eq!(row_ids(&page), [miss.to_string()]);

    // a pattern no index serves: the editor and a link say why, escaped, and list without it
    let (status, page) =
        get("/?add=observable_pattern&type=fqdn&value=%2A%3Ci%3Eevil%3C%2Fi%3E%2A").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains(
            "That filter couldn't be used: observable pattern &#34;*&#60;i&#62;evil&#60;/i&#62;*&#34; \
             has a wildcard at both ends"
        ),
        "{page}"
    );
    assert!(!page.contains("<i>evil"), "{page}");
    let (status, page) = get("/?f=observable_pattern:fqdn:%2Aevil%2A").await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("has a wildcard at both ends"), "{page}");
    assert_eq!(
        row_ids(&page).len(),
        3,
        "the list without the link's filters"
    );

    // past its bound: nothing listed, and why, in the page and in its refresh
    let past = "f=observable_pattern:fqdn:%2A.p%3Cb%3Est.example";
    let why = "observable pattern fqdn:*.p&#60;b&#62;st.example matches more than 500 observables; make it \
               more specific";
    for path in [format!("/?{past}"), format!("/alerts/list?{past}")] {
        let (status, page) = get(&path).await;
        assert_eq!(status, StatusCode::OK, "{path}: {page}");
        assert!(row_ids(&page).is_empty(), "{path}");
        assert!(
            page.contains(&format!(
                r#"<p class="error filter-refused">These filters can't be run, so no alerts are listed: {why}</p>"#
            )),
            "{path}: {page}"
        );
        assert!(!page.contains("No alerts match"), "{path}");
        assert!(!page.contains("p<b>st"), "{path}: {page}");
    }

    // and in search, where a refused pattern is a term that can't be honored
    let (status, page) = get("/search?q=observable_pattern%3Afqdn%3A%2A.p%3Cb%3Est.example").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(page.contains(why), "{page}");
    assert!(!page.contains("p<b>st"), "{page}");

    // a quick filter that can't be counted is marked with why, not drawn as one with no alerts
    let post = |form: Vec<(&str, &str)>| {
        let request = stack
            .post("/filters/saved", &form)
            .header("cookie", cookie(&session));
        async move { request.send().await.expect("answered") }
    };
    let saved = post(vec![
        ("name", "Past"),
        ("f", "observable_pattern:fqdn:*.p<b>st.example"),
        ("quick", "on"),
        ("indicator", "on"),
        ("next", "/"),
    ])
    .await;
    assert_eq!(saved.status(), StatusCode::SEE_OTHER);
    let (_, page) = get("/").await;
    assert!(
        page.contains(&format!(
            r#"title="{why}">Past <span class="refused" aria-label="can't be counted">!</span></a>"#
        )),
        "{page}"
    );
    assert!(!page.contains(r#"Past <span class="count">"#), "{page}");

    // saving a link with a pattern no index serves writes nothing
    let audit = stack.audit_count().await;
    let refused = post(vec![
        ("name", "Both ends"),
        ("f", "observable_pattern:fqdn:*evil*"),
        ("next", "/"),
    ])
    .await;
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    let body = refused.text().await.expect("a page");
    assert!(body.contains("has a wildcard at both ends"), "{body}");
    assert_eq!(stack.audit_count().await, audit);
    assert_eq!(
        stack
            .service
            .saved_filters(&alice, FilterScreen::Alerts)
            .await
            .expect("lists")
            .iter()
            .filter(|filter| filter.name == "Both ends")
            .count(),
        0
    );
}

/// A summary that reads its emails' bodies (PLAN.md decision 55): each body part as text, with how much
/// more it has.
#[derive(Template)]
#[template(
    source = r#"<section class="type-summary bodies">{% for body in bodies %}<pre data-result="{{ body.result }}" data-html="{{ body.html }}" data-more="{{ body.more }}">{{ body.text }}</pre>{% endfor %}</section>"#,
    ext = "html"
)]
struct BodiesView {
    bodies: Vec<ace_gui::EmailBody>,
}

struct BodiesSummary;

impl ace_gui::AlertSummary for BodiesSummary {
    const ALERT_TYPE: &'static str = "bodies";
    const READS_EMAIL_BODIES: bool = true;
    type View<'a> = BodiesView;
    fn view<'a>(alert: &ace_gui::SummaryInput<'a>) -> Option<BodiesView> {
        Some(BodiesView {
            bodies: alert.bodies.to_vec(),
        })
    }
}

/// The same alert type's summary, which doesn't read bodies: it is given none.
#[derive(Template)]
#[template(
    source = r#"<section class="type-summary bodies">given {{ count }} bodies</section>"#,
    ext = "html"
)]
struct NoBodiesView {
    count: usize,
}

struct NoBodiesSummary;

impl ace_gui::AlertSummary for NoBodiesSummary {
    const ALERT_TYPE: &'static str = "bodies";
    type View<'a> = NoBodiesView;
    fn view<'a>(alert: &ace_gui::SummaryInput<'a>) -> Option<NoBodiesView> {
        Some(NoBodiesView {
            count: alert.bodies.len(),
        })
    }
}

/// An alert of type `bodies` with `emails` email results, each adding a plain text and an HTML body
/// part, and an attachment that is no body, stored in the bucket held by the root. The first email's
/// text is `first_text`; the rest are their number.
async fn bodies_alert(
    stack: &Stack,
    bucket: &ace_core::bucket::Bucket,
    emails: usize,
    first_text: &[u8],
) -> uuid::Uuid {
    use ace_core::tree;
    let db = stack.test_db.db();
    let root = tree::NewRoot::new("correlation");
    let mut tx = db.begin().await.expect("begins");
    tree::create_root(&mut tx, &root).await.expect("creates");
    sqlx::query(
        "UPDATE analysis.roots SET alerted_at = now(), origin = '{\"alert_type\": \"bodies\"}'
         WHERE id = $1",
    )
    .bind(root.id)
    .execute(tx.conn())
    .await
    .expect("an alert");
    let hold = ace_core::bucket::Hold::root(root.id);
    for n in 0..emails {
        let email = tree::upsert_observable(
            &mut tx,
            root.id,
            &ace_results::NewObservable::new(
                ace_results::ObservableKind::File,
                hex::encode(Sha256::digest(format!("email {n}"))),
            ),
        )
        .await
        .expect("the email")
        .id;
        let paths = [
            format!("e{n}.unknown_text_plain_000.txt"),
            format!("e{n}.unknown_text_html_001.html"),
            format!("notes{n}.txt"),
        ];
        let result: ace_results::ResultEnvelope<serde_json::Value> =
            serde_json::from_value(serde_json::json!({
                "analysis_type": "email_analysis", "schema_version": 1,
                "details": {"parts": [
                    {"path": paths[0], "content_type": "text/plain", "role": "body"},
                    {"path": paths[1], "content_type": "text/html", "role": "body"},
                    {"path": paths[2], "content_type": "text/plain", "role": "attachment"},
                ]},
            }))
            .expect("a result");
        let result = tree::insert_result(&mut tx, root.id, email, "email_analysis", &result)
            .await
            .expect("stores");
        let bytes: [Vec<u8>; 3] = [
            if n == 0 {
                first_text.to_vec()
            } else {
                format!("plain {n}").into_bytes()
            },
            format!("<p onclick=x>html {n}</p><script>alert(1)</script>").into_bytes(),
            format!("attachment {n}").into_bytes(),
        ];
        for (path, bytes) in paths.iter().zip(bytes) {
            let spooled = bucket.store().spool_bytes(&bytes).await.expect("spools");
            bucket
                .put_in(
                    &mut tx,
                    ace_core::bucket::ALERT_FILES,
                    &spooled,
                    Some(&hold),
                )
                .await
                .expect("stores the bytes");
            let file = tree::upsert_observable(
                &mut tx,
                root.id,
                &ace_results::NewObservable::new(
                    ace_results::ObservableKind::File,
                    spooled.sha256.to_hex(),
                ),
            )
            .await
            .expect("the part")
            .id;
            tree::add_file(&mut tx, root.id, file, path, &[])
                .await
                .expect("the file");
            tree::add_result_addition(&mut tx, root.id, result, file, Some(path))
                .await
                .expect("the addition");
        }
    }
    tx.commit().await.expect("commits");
    root.id
}

/// PLAN.md decision 55, through the server. A summary that reads its emails' bodies is given each
/// email's first plain text and HTML body part, never an attachment, as text: escaped, invalid UTF-8
/// replaced, at most 64 KiB of each with the rest counted, of at most 8 emails, and reading them writes
/// no audit row. A summary that doesn't read them is given none. The site's alert actions are drawn
/// beside Graph and Similar alerts, each only for a viewer with its permission, in a new tab with no
/// opener or referrer, their text escaped, and a link that isn't one to draw for an alert is left out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_alert_page_shows_a_summary_its_email_bodies_and_the_site_s_actions() {
    let cache = std::env::temp_dir().join(format!("ace-rs-gui-cache-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&cache).expect("a cache directory");
    let store = ace_store::Store::new(
        &ace_store::BucketConfig::from_env().expect("the ACE_RS_BUCKET_* variables"),
        ace_store::NodeCache::new(&cache, 1 << 30).expect("a cache"),
    )
    .await;
    let read = ace_service::PermissionName::new("alert", "read").expect("a name");
    let write = ace_service::PermissionName::new("alert", "write").expect("a name");
    let actions = ace_gui::AlertActions::empty()
        .with(
            ace_gui::AlertAction::new("triage_open", "Open <in> Triage tool", read.clone(), |t| {
                Some(format!("http://127.0.0.1:28563/#triage={}", t.alert))
            })
            .with_title("The UI \"must\" run on this machine"),
        )
        .with(ace_gui::AlertAction::new(
            "writers_only",
            "Writers",
            write,
            |_| Some("/writers".to_owned()),
        ))
        .with(ace_gui::AlertAction::new(
            "elsewhere",
            "Elsewhere",
            read,
            |_| Some("http://203.0.113.9/".to_owned()),
        ));
    let bucket_slot: Arc<Mutex<Option<ace_core::bucket::Bucket>>> = Arc::new(Mutex::new(None));
    let slot = bucket_slot.clone();
    let stack = stack_of_db(Catalog::new(vec![]), move |service, db| {
        let bucket = ace_core::bucket::Bucket::new(
            db.clone(),
            store,
            ace_core::bucket::BucketSettings::default(),
        );
        *slot.lock().expect("the slot") = Some(bucket.clone());
        Gui::new(service.with_bucket(bucket), Transport::Plain)
            .with_summaries(
                ace_gui::AlertSummaries::builtin()
                    .with(ace_gui::SummaryEntry::of::<BodiesSummary>()),
            )
            .with_alert_actions(actions)
    })
    .await;
    let bucket = bucket_slot
        .lock()
        .expect("the slot")
        .clone()
        .expect("a bucket");
    let alice = user(&stack, "alice").await;
    grant_to(&stack, &alice, "alert", "read").await;
    let session = session_of(&stack, "alice").await;
    let page = |id: uuid::Uuid| {
        let request = stack
            .get(&format!("/alerts/{id}"))
            .header("cookie", cookie(&session));
        async move {
            let page = request.send().await.expect("answered");
            assert_eq!(page.status(), StatusCode::OK);
            page.text().await.expect("text")
        }
    };

    // a body past the bound, cut inside a character, with a byte that isn't UTF-8
    let mut long = b"<b>bold</b> \xff ".to_vec();
    long.resize(ace_gui::MAX_BODY_BYTES - 1, b'a');
    long.extend_from_slice("é".as_bytes());
    long.extend_from_slice(&[b'z'; 99]);
    let id = bodies_alert(&stack, &bucket, 9, &long).await;
    let audit = stack.audit_count().await;
    let html = page(id).await;
    assert_eq!(
        stack.audit_count().await,
        audit,
        "showing a body is no audited read"
    );
    let bodies: Vec<&str> = html.split("<pre data-result=").skip(1).collect();
    assert_eq!(
        bodies.len(),
        2 * ace_gui::MAX_BODY_EMAILS,
        "eight emails, a plain and an HTML part each: {html}"
    );
    let shown = ace_gui::MAX_BODY_BYTES - 1 - b"<b>bold</b> \xff ".len();
    assert!(
        bodies[0].contains(&format!(
            r#"data-html="false" data-more="101">&#60;b&#62;bold&#60;/b&#62; {} {}</pre>"#,
            '\u{fffd}',
            "a".repeat(shown)
        )),
        "{}",
        &bodies[0][..200]
    );
    assert!(
        bodies[1].contains(
            r#"data-html="true" data-more="0">&#60;p onclick=x&#62;html 0&#60;/p&#62;&#60;script&#62;alert(1)&#60;/script&#62;</pre>"#
        ),
        "{}",
        bodies[1]
    );
    assert!(bodies[2].contains(">plain 1</pre>"), "{}", bodies[2]);
    assert!(!html.contains("attachment 1"), "an attachment is no body");
    assert!(
        !html.contains("plain 8"),
        "the ninth email is past the bound"
    );
    assert!(!html.contains("<script>alert(1)"), "{html}");

    // the actions: the reader's, not the writers', and not one that leads off this machine
    assert!(
        html.contains(&format!(
            r#"<a class="alert-action" href="http://127.0.0.1:28563/#triage={id}" target="_blank" rel="noopener noreferrer" title="The UI &#34;must&#34; run on this machine">Open &#60;in&#62; Triage tool</a></p>"#
        )),
        "{html}"
    );
    assert!(!html.contains(">Writers</a>"), "{html}");
    assert!(!html.contains("Elsewhere"), "{html}");
    grant_to(&stack, &alice, "alert", "write").await;
    let html = page(id).await;
    assert!(
        html.contains(r#"<a class="alert-action" href="/writers" target="_blank" rel="noopener noreferrer">Writers</a>"#),
        "{html}"
    );

    // a summary that doesn't read bodies is given none, and nothing is read
    let plain = stack_of_db(Catalog::new(vec![]), |service, _| {
        Gui::new(service, Transport::Plain).with_summaries(
            ace_gui::AlertSummaries::builtin().with(ace_gui::SummaryEntry::of::<NoBodiesSummary>()),
        )
    })
    .await;
    let id = bodies_alert(&plain, &bucket, 1, b"text").await;
    let bob = user(&plain, "bob").await;
    grant_to(&plain, &bob, "alert", "read").await;
    let session = session_of(&plain, "bob").await;
    let html = plain
        .get(&format!("/alerts/{id}"))
        .header("cookie", cookie(&session))
        .send()
        .await
        .expect("answered")
        .text()
        .await
        .expect("text");
    assert!(html.contains("given 0 bodies"), "{html}");
    assert!(!html.contains("class=\"alert-action\""), "{html}");
}

#[test]
fn alert_action_a_link_is_a_site_path_https_or_http_to_this_machine() {
    for good in [
        "/alerts/x",
        "https://example.com/a?b=c#d",
        "https://example.com:8443/",
        "http://127.0.0.1:28563/#triage=3f2c91ab",
        "http://127.9.9.9/",
        "http://localhost:9999/",
        "http://LOCALHOST/",
        "http://[::1]:28563/",
        "http://[::1]/",
    ] {
        assert!(ace_gui::alert_actions::drawable(good), "{good}");
    }
    for bad in [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "http://203.0.113.9:28563/",
        "http://triage.example.com/",
        "http://127.0.0.1.example.com/",
        "http://localhost.example.com/",
        "http://user:pass@127.0.0.1/",
        "http://ace.example.com@127.0.0.1/",
        "https://ace.example.com@203.0.113.9/",
        "https:///nohost",
        "http://127.0.0.1:99999/",
        "http://127.0.0.1:port/",
        "http://[::2]/",
        "http://[::1/",
        "//evil.example.com/",
        "/\\evil.example.com",
        "http://127.0.0.1/\"onmouseover=x",
        "http://127.0.0.1/a b",
        "http://127.0.0.1/\u{e9}",
        "",
    ] {
        assert!(!ace_gui::alert_actions::drawable(bad), "{bad}");
    }
    assert!(!ace_gui::alert_actions::drawable(&format!(
        "/{}",
        "a".repeat(4096)
    )));
}

#[test]
fn alert_action_an_action_is_refused_for_its_name_label_or_sample_link() {
    let action = |name: &'static str, label: &str, link: &'static str| {
        ace_gui::AlertAction::new(
            name,
            label,
            ace_service::PermissionName::new("alert", "read").expect("a name"),
            move |target| Some(format!("{link}#triage={}", target.alert)),
        )
    };
    assert_eq!(
        action(
            "triage_open",
            "Open in Triage tool",
            "http://127.0.0.1:28563/"
        )
        .refusal(),
        None
    );
    for (name, label, link, says) in [
        ("Triage", "x", "/a", "name"),
        ("", "x", "/a", "name"),
        ("triage_open", " ", "/a", "no label"),
        ("triage_open", "x", "http://203.0.113.9/", "isn't a path"),
        ("triage_open", "x", "javascript:alert(1)", "isn't a path"),
    ] {
        let refused = action(name, label, link).refusal().expect("refused");
        assert!(refused.contains(says), "{refused}");
    }
    // a link the action doesn't give the sample alert is no refusal: it isn't drawn there
    let none = ace_gui::AlertAction::new(
        "sometimes",
        "Sometimes",
        ace_service::PermissionName::new("alert", "read").expect("a name"),
        |_| None,
    );
    assert_eq!(none.refusal(), None);
}

#[test]
fn alert_action_links_follow_the_order_the_permission_and_each_alert() {
    let read = ace_service::PermissionName::new("alert", "read").expect("a name");
    let write = ace_service::PermissionName::new("alert", "write").expect("a name");
    let actions = ace_gui::AlertActions::empty()
        .with(
            ace_gui::AlertAction::new("first", "First", read.clone(), |t| {
                Some(format!("/x/{}", t.alert))
            })
            .with_title("the first"),
        )
        .with(ace_gui::AlertAction::new(
            "writers",
            "Writers",
            write.clone(),
            |_| Some("/w".to_owned()),
        ))
        .with(ace_gui::AlertAction::new(
            "typed",
            "Typed",
            read.clone(),
            |t| (t.alert_type == Some("mailbox")).then(|| "http://evil.example.com/".to_owned()),
        ))
        .with(ace_gui::AlertAction::new(
            "first",
            "First again",
            read.clone(),
            |_| Some("/again".to_owned()),
        ));
    assert_eq!(
        actions.names().collect::<Vec<_>>(),
        ["first", "writers", "typed"]
    );
    let origin = serde_json::Value::Null;
    let target = ace_gui::AlertActionTarget {
        alert: uuid::Uuid::nil(),
        alert_type: Some("mailbox"),
        origin: &origin,
    };
    let links = actions.links(&target, |p| *p == read);
    assert_eq!(
        links,
        [ace_gui::alert_actions::AlertActionLink {
            name: "first",
            label: "First again".to_owned(),
            title: None,
            href: "/again".to_owned(),
        }],
        "the writers' action is left out, and a link that isn't drawable is too"
    );
    assert_eq!(actions.links(&target, |_| true).len(), 2);
}

#[test]
fn a_body_s_text_leaves_out_a_character_the_cut_split() {
    use ace_gui::analysis::summary::body_text;
    assert_eq!(body_text(b"plain"), ("plain".to_owned(), 5));
    assert_eq!(
        body_text("caf\u{e9}".as_bytes()),
        ("caf\u{e9}".to_owned(), 5)
    );
    assert_eq!(body_text(b"caf\xc3"), ("caf".to_owned(), 3));
    assert_eq!(body_text(b"x\xf0\x9f\x98"), ("x".to_owned(), 1));
    // a byte that isn't UTF-8 is replaced, not left out
    assert_eq!(body_text(b"a\xffb"), ("a\u{fffd}b".to_owned(), 3));
    assert_eq!(body_text(b"a\xff"), ("a\u{fffd}".to_owned(), 2));
    assert_eq!(body_text(b""), (String::new(), 0));
}

#[test]
fn bodies_are_read_for_a_summary_that_reads_them_by_name_or_by_type() {
    let summaries = ace_gui::AlertSummaries::builtin()
        .with(ace_gui::SummaryEntry::of::<BodiesSummary>())
        .with_template(
            "site/reads.html",
            ace_gui::SummaryEntry::of::<BodiesSummary>(),
        );
    let none = serde_json::Value::Null;
    let named = serde_json::json!({"extensions": {"alert_template": " site/reads.html "}});
    assert!(summaries.reads_email_bodies("bodies - sub", &none));
    assert!(!summaries.reads_email_bodies("mailbox", &none));
    assert!(!summaries.reads_email_bodies("", &none));
    assert!(summaries.reads_email_bodies("mailbox", &named));
    assert!(
        !ace_gui::AlertSummaries::builtin().reads_email_bodies("mailbox", &named),
        "a name with no summary falls to the type"
    );
}
