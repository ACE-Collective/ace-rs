//! A bound on how many of something run at once, in all and for one user: 5.8's alert streams and 5.10's
//! list refreshes. Past either bound a request is refused, and the place goes back when its holder is
//! dropped, so a client that goes leaves nothing held.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ace_service::Actor;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Debug)]
pub(crate) struct Places {
    total: usize,
    per_user: usize,
    free: Arc<Semaphore>,
    users: Arc<Mutex<HashMap<String, usize>>>,
}

impl Places {
    pub(crate) fn new(total: usize, per_user: usize) -> Self {
        Places {
            total,
            per_user,
            free: Arc::new(Semaphore::new(total)),
            users: Arc::default(),
        }
    }

    /// A place for one more of this actor's, or None past a bound.
    pub(crate) fn admit(&self, actor: &Actor) -> Option<Place> {
        let permit = self.free.clone().try_acquire_owned().ok()?;
        let user = actor.to_string();
        let mut users = self.users.lock().unwrap_or_else(|e| e.into_inner());
        let open = users.entry(user.clone()).or_default();
        if *open >= self.per_user {
            return None;
        }
        *open += 1;
        Some(Place {
            _permit: permit,
            user,
            users: self.users.clone(),
        })
    }

    /// How many places are held.
    pub(crate) fn held(&self) -> usize {
        self.total - self.free.available_permits()
    }
}

/// One place, given back when it's dropped.
pub(crate) struct Place {
    _permit: OwnedSemaphorePermit,
    user: String,
    users: Arc<Mutex<HashMap<String, usize>>>,
}

impl Drop for Place {
    fn drop(&mut self) {
        let mut users = self.users.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(open) = users.get_mut(&self.user) {
            *open -= 1;
            if *open == 0 {
                users.remove(&self.user);
            }
        }
    }
}
