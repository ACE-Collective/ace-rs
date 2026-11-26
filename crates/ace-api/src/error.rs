//! A failure as the client sees it: a status and `{"error": "..."}`. Each `ServiceError` has one status,
//! and a failure that isn't the client's says only "internal error", with the detail in the log.

use ace_core::bucket::BucketError;
use ace_core::orchestrator::OrchestratorError;
use ace_service::ServiceError;
use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use utoipa::ToSchema;

/// The body of every failure.
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorBody {
    /// What went wrong, for a person to read.
    pub error: String,
}

#[derive(Debug)]
pub(crate) struct ApiError {
    status: StatusCode,
    message: String,
    /// How many seconds a refused client should wait, as a 429's `Retry-After`.
    retry_after: Option<u64>,
}

impl ApiError {
    pub(crate) fn new(status: StatusCode, message: impl Into<String>) -> Self {
        ApiError {
            status,
            message: message.into(),
            retry_after: None,
        }
    }

    pub(crate) fn bad_request(message: impl Into<String>) -> Self {
        ApiError::new(StatusCode::BAD_REQUEST, message)
    }

    pub(crate) fn internal(detail: impl std::fmt::Display) -> Self {
        tracing::error!("the API failed: {detail}");
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
    }
}

impl From<ServiceError> for ApiError {
    fn from(error: ServiceError) -> Self {
        use ace_core::db::Retryable;
        let status = match &error {
            // says nothing more, as the service's error doesn't
            ServiceError::NotAuthenticated => StatusCode::UNAUTHORIZED,
            ServiceError::CrossSiteRequest | ServiceError::Forbidden(_) => StatusCode::FORBIDDEN,
            ServiceError::PermissionDenied { permission, .. } => {
                return ApiError::new(StatusCode::FORBIDDEN, format!("this needs {permission}"));
            }
            ServiceError::InvalidRequest(_)
            | ServiceError::FilterRefused(_)
            | ServiceError::WeakPassword
            | ServiceError::InvalidKeyName
            | ServiceError::CantDisableYourself
            | ServiceError::CantDropYourOwnUserWrite => StatusCode::BAD_REQUEST,
            ServiceError::NotFound(_)
            | ServiceError::NoUser(_)
            | ServiceError::Orchestrator(OrchestratorError::NoRoot(_)) => StatusCode::NOT_FOUND,
            ServiceError::TooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            ServiceError::Gone(_) => StatusCode::GONE,
            // a write made from a row that changed since it was read (an `If-Match` that no longer
            // holds): the client reads the row again
            ServiceError::StaleWrite(_) => StatusCode::PRECONDITION_FAILED,
            ServiceError::UsernameTaken
            | ServiceError::GroupNameTaken
            | ServiceError::FilterNameTaken(_)
            | ServiceError::Conflict(_)
            | ServiceError::AlertOwned { .. }
            | ServiceError::UsersExist => StatusCode::CONFLICT,
            ServiceError::Bucket(BucketError::Deleting { .. }) => StatusCode::SERVICE_UNAVAILABLE,
            // its message is an operator's, such as a missing key, and holds nothing secret; the
            // operator hears of it, as ace3 since e7cd8be8 reports a missing key
            ServiceError::Unconfigured(why) => {
                tracing::error!("a request needs what this node lacks: {why}");
                StatusCode::INTERNAL_SERVER_ERROR
            }
            ServiceError::RateLimited {
                detail,
                retry_after_seconds,
            } => {
                return ApiError {
                    status: StatusCode::TOO_MANY_REQUESTS,
                    message: detail.clone(),
                    retry_after: Some(*retry_after_seconds),
                };
            }
            ServiceError::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            // a data source's failure, 502 or 504, or its throttling, 429, which says no
            // `Retry-After` since the source's wait isn't known (ace3 sends none either): the
            // service lets no other status through
            ServiceError::Upstream { status, .. } => match *status {
                504 => StatusCode::GATEWAY_TIMEOUT,
                429 => StatusCode::TOO_MANY_REQUESTS,
                _ => StatusCode::BAD_GATEWAY,
            },
            error if error.is_retryable() => StatusCode::SERVICE_UNAVAILABLE,
            ServiceError::Orchestrator(_)
            | ServiceError::Bucket(_)
            | ServiceError::InvalidPermission(_)
            | ServiceError::AuditEncoding(_)
            | ServiceError::Hashing(_) => return ApiError::internal(&error),
        };
        ApiError::new(status, error.to_string())
    }
}

impl From<JsonRejection> for ApiError {
    fn from(rejection: JsonRejection) -> Self {
        match rejection.status() {
            StatusCode::PAYLOAD_TOO_LARGE => {
                ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "the body is too large")
            }
            StatusCode::UNSUPPORTED_MEDIA_TYPE => ApiError::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "the body has to be application/json",
            ),
            _ => ApiError::bad_request(rejection.body_text()),
        }
    }
}

impl From<QueryRejection> for ApiError {
    fn from(rejection: QueryRejection) -> Self {
        ApiError::bad_request(rejection.body_text())
    }
}

impl From<PathRejection> for ApiError {
    fn from(rejection: PathRejection) -> Self {
        ApiError::bad_request(rejection.body_text())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response();
        if let Some(seconds) = self.retry_after {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(seconds));
        }
        if self.status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
}
