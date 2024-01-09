fn main() {}

#[cfg(test)]
mod test {
    use poem::test::TestClient;
    use poem::web::headers;
    use poem::{http, Request};
    use poem_openapi::auth::{ApiKey, Bearer};
    use poem_openapi::payload::PlainText;
    use poem_openapi::SecurityScheme;

    #[derive(SecurityScheme)]
    enum ComplexScheme {
        Bearer(BearerScheme),
        Cookie(CookieScheme),
    }

    impl ComplexScheme {
        fn value(&self) -> &str {
            match self {
                ComplexScheme::Bearer(bearer) => &bearer.0,
                ComplexScheme::Cookie(cookie) => &cookie.0,
            }
        }
    }

    #[derive(SecurityScheme)]
    #[oai(rename = "Checker Option", ty = "bearer", checker = "extract_bearer")]
    struct BearerScheme(String);

    #[derive(SecurityScheme)]
    #[oai(
        ty = "api_key",
        key_in = "cookie",
        key_name = "X-SESSION",
        checker = "extract_cookie"
    )]
    struct CookieScheme(String);

    async fn extract_bearer(_req: &Request, bearer: Bearer) -> poem::Result<String> {
        verify(bearer.token)
    }

    async fn extract_cookie(_req: &Request, cookie: ApiKey) -> poem::Result<String> {
        verify(cookie.key)
    }

    fn verify(auth: impl Into<String>) -> poem::Result<String> {
        let auth = auth.into();
        if auth != "Disabled" {
            Ok(auth)
        } else {
            Err(AccountDisabledError)?
        }
    }

    #[derive(Debug)]
    struct AccountDisabledError;

    impl std::error::Error for AccountDisabledError {}

    impl std::fmt::Display for AccountDisabledError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("Your account is disabled")
        }
    }

    impl poem::error::ResponseError for AccountDisabledError {
        fn status(&self) -> http::StatusCode {
            http::StatusCode::FORBIDDEN
        }
    }

    struct MyApi;

    #[poem_openapi::OpenApi]
    impl MyApi {
        #[oai(path = "/test", method = "get")]
        async fn test(&self, auth: ComplexScheme) -> PlainText<String> {
            PlainText(format!("Authed: {}", auth.value()))
        }
    }

    #[tokio::test]
    async fn checker_result() {
        let service = poem_openapi::OpenApiService::new(MyApi, "test", "1.0");
        let client = TestClient::new(service);

        // Cookie enabled.
        let resp = client
            .get("/test")
            .header(
                http::header::COOKIE,
                poem::web::cookie::Cookie::new_with_str("X-SESSION", "Enabled").to_string(),
            )
            .send()
            .await;
        resp.assert_status_is_ok();
        resp.assert_text("Authed: Enabled").await;

        // Bearer Enabled.
        let resp = client
            .get("/test")
            .typed_header(headers::Authorization::bearer("Enabled").unwrap())
            .send()
            .await;
        resp.assert_status_is_ok();
        resp.assert_text("Authed: Enabled").await;

        // Cookie disabled.
        let resp = client
            .get("/test")
            .header(
                http::header::COOKIE,
                poem::web::cookie::Cookie::new_with_str("X-SESSION", "Disabled").to_string(),
            )
            .send()
            .await;

        resp.assert_status(http::StatusCode::FORBIDDEN);
        resp.assert_text("Your account is disabled").await;

        // Bearer disabled.
        // THIS TEST IS FAILING.
        // The error is being swallowed, and the default response is being returned instead.
        // Status: 401
        // Body: authorization error
        //
        // NOTE: If we switch the order of the enum values in `ComplexScheme`, then this test will pass and the above one will fail with the same error.
        // It seems to only affect the first enum value.
        let resp = client
            .get("/test")
            .typed_header(headers::Authorization::bearer("Disabled").unwrap())
            .send()
            .await;
        let status = resp.0.status();
        let body = resp.0.into_body().into_string().await.unwrap();

        println!("FAILING TEST RESPONSE - Status: {status}, Body: {body}");

        assert_eq!(status, http::StatusCode::FORBIDDEN);
        assert_eq!(body, "Your account is disabled")
    }
}
