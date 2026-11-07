//! Where a request came from, for its audit row's `src_ip` (PLAN.md 5.5). ace3 records it on its hunt and
//! AI audit lines, taking the first `X-Forwarded-For` entry, which any client can set.
//!
//! An adapter knows the address and the service layer doesn't, and every write would otherwise take one
//! more argument that an internal caller has no value for. So an adapter runs the request inside
//! `with_source_ip`, and `Gate::write` reads it for the row. A call outside one, such as a component's,
//! records none. It's a task-local, so it follows the request's own future and not a task it spawns,
//! and nothing in this crate spawns one.

use std::future::Future;
use std::net::IpAddr;

tokio::task_local! {
    static SOURCE_IP: Option<IpAddr>;
}

/// Runs `request` with `ip` as the address its writes record.
pub async fn with_source_ip<F: Future>(ip: Option<IpAddr>, request: F) -> F::Output {
    SOURCE_IP.scope(ip, request).await
}

/// The address the running request came from, if an adapter gave one.
pub(crate) fn source_ip() -> Option<IpAddr> {
    SOURCE_IP.try_with(|ip| *ip).ok().flatten()
}
