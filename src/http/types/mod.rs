use serde::{Deserialize, Serialize};

pub mod runtime;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BenchmarkRequest {
    pub class_name: String,
    pub method_name: String,
    pub time_in_milliseconds: i64
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthResponse {
    pub token: String,
    pub refresh_token: String
}