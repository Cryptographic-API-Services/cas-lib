use reqwest::{Client, Response};
use tokio::task;
use serde::Serialize;


#[derive(Serialize)]
struct BenchmarkRequest {
    name: String,
    time_in_milliseconds: i64
}

pub async fn send_benchmark(algorithm_name: String, time_in_milliseconds: i64) -> Response {
    let client = Client::new();
    let payload = BenchmarkRequest {
        name: algorithm_name,
        time_in_milliseconds
    };

    // Spawn a background task
    let response_task = task::spawn(async move {
        client.post("http://localhost:5000/api/Benchmark")
            .json(&payload)
            .send()
            .await
    });
    return response_task.await.unwrap().unwrap();
}