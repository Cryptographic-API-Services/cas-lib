#[cfg(test)]
mod http {
    use cas_lib::http::send_benchmark;

    #[tokio::test]
    async fn test_send_fire_and_forget() {
        // Since the function is fire-and-forget, we just ensure it runs without panicking.
        send_benchmark(String::from("My Name"), 42).await;
    }
}