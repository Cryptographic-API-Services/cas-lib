use reqwest::{cookie::Jar, Client, Response};
use std::sync::{Arc, Mutex};
use tokio::task;
use url::Url;

pub mod types;
use crate::http::types::BenchmarkRequest;

static API_KEY: Mutex<String> = Mutex::new(String::new());
static BASE_URL: Mutex<String> = Mutex::new(String::new());

static TOKEN: Mutex<String> = Mutex::new(String::new());
static REFRESH_TOKEN: Mutex<String> = Mutex::new(String::new());
static BENCHMARK_SENDER_CLIENT: Mutex<Option<Client>> = Mutex::new(None);

fn create_benchmark_sender_client(token: String, refresh_token: String) -> Client {
    let cookie_store = Arc::new(Jar::default());
    let base_url = Url::parse(BASE_URL.lock().unwrap().as_str()).unwrap();
    cookie_store.add_cookie_str(&format!("Token={}; Path=/", token), &base_url);
    cookie_store.add_cookie_str(&format!("RefreshToken={}; Path=/", refresh_token), &base_url);
    Client::builder()
        .cookie_provider(cookie_store)
        .build()
        .unwrap()
}

fn determine_api_route() -> String {
    let base_url = BASE_URL.lock().unwrap();
    if base_url.contains("cryptographicapiservices.com") {
        "api/userapi".to_string()
    } else {
        "api".to_string()
    }
}

pub async fn set_api_key_in_cache(api_key: String) {
    let mut key = API_KEY.lock().unwrap();
    *key = api_key.clone();
    set_tokens_in_cache(api_key).await;
}

pub async fn set_base_url_in_cache(base_url: String) {
    let mut url = BASE_URL.lock().unwrap();
    *url = base_url
}

async fn set_tokens_in_cache(api_key: String) {
    let client = Client::new();
    let testing = BASE_URL.lock().unwrap().clone();
    let url = format!("{}/{}/APIKey/GetToken", testing, determine_api_route());
    let response_task = client
        .get(url)
        .header("Authorization", api_key)
        .send()
        .await;
    let response = response_task.unwrap().json::<types::AuthResponse>();
    let mut token = TOKEN.lock().unwrap();
    let mut refresh_token = REFRESH_TOKEN.lock().unwrap();
    let mut bench_mark_client = BENCHMARK_SENDER_CLIENT.lock().unwrap();
    match response.await {
        Ok(auth_response) => {
            *token = auth_response.token.clone();
            *refresh_token = auth_response.refresh_token.clone();
            *bench_mark_client = Some(create_benchmark_sender_client(auth_response.token, auth_response.refresh_token));
        }
        Err(_) => {
            *token = String::new();
            *refresh_token = String::new();
        }
    }
}

pub async fn send_benchmark(time_in_milliseconds: i64, class_name: String, method_name: String) {
    let payload = BenchmarkRequest {
        class_name,
        method_name,
        time_in_milliseconds,
    };
    // Spawn a background task
    task::spawn(async move {
        let base_url = BASE_URL.lock().unwrap().clone();
        let client = BENCHMARK_SENDER_CLIENT.lock().unwrap().as_ref().unwrap().clone();
        client
            .post(format!("{}/{}/Benchmark", base_url, determine_api_route()))
            .json(&payload)
            .send()
            .await
    });
}