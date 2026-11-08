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
}

impl ApiError {
    pub(crate) fn new(status: StatusCode, message: impl Into<String>) -> Self {
        ApiError {
            status,
            message: message.into(),
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
            | ServiceError::WeakPassword
            | ServiceError::InvalidKeyName
            | ServiceError::CantDisableYourself => StatusCode::BAD_REQUEST,
            ServiceError::NotFound(_)
            | ServiceError::NoUser(_)
            | ServiceError::Orchestrator(OrchestratorError::NoRoot(_)) => StatusCode::NOT_FOUND,
            ServiceError::TooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            ServiceError::UsernameTaken
            | ServiceError::GroupNameTaken
            | ServiceError::UsersExist => StatusCode::CONFLICT,
            ServiceError::Bucket(BucketError::Deleting { .. }) => StatusCode::SERVICE_UNAVAILABLE,
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
        if self.status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
}
