use graph_rs_sdk::{
    oauth::OAuth,
    serde::{Deserialize, Serialize},
};
use serde::{de, Deserializer};
use serde_json::Value;
use std::convert::Infallible;
use std::env;
use warp::{Filter, Future, Rejection, Reply};

#[derive(Clone)]
pub struct AzureCredentials {
    pub client_id: String,
    pub client_secret: String,
}

pub fn read_client_credentials_from_env() -> Result<AzureCredentials, Box<dyn std::error::Error>> {
    Ok(AzureCredentials {
        client_id: env::var("AZURE_CLIENT_ID")?,
        client_secret: env::var("AZURE_CLIENT_SECRET")?,
    })
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClientCredentialsResponse {
    #[serde(deserialize_with = "parse_bool")]
    admin_consent: bool,
    tenant: String,
}

async fn handle_redirect(
    resp_with_cred: (Option<ClientCredentialsResponse>, AzureCredentials),
) -> Result<Box<dyn warp::Reply>, warp::Rejection> {
    match resp_with_cred.0 {
        Some(client_credential_response) => {
            // Print out for debugging purposes.
            println!("{:#?}", client_credential_response);

            // Request an access token.
            match request_access_token(resp_with_cred.1).await {
                Ok(_) => Ok(()),
                Err(_) => Err(warp::reject()),
            };

            // Generic login page response.
            Ok(Box::new(
                "Successfully Logged In! You can close your browser.",
            ))
        }
        None => Err(warp::reject()),
    }
}

/// Extends boolean parsing to also work with 'True' and 'False' instead of only 'true' and
/// 'false'.
fn parse_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(match Value::deserialize(deserializer)? {
        Value::Bool(b) => b,
        Value::String(s) => s.to_lowercase().as_str() == "true",
        _ => return Err(de::Error::custom("Wrong type, expected boolean")),
    })
}

fn get_oauth_client(cred: AzureCredentials) -> OAuth {
    let mut oauth = OAuth::new();
    oauth
        .client_id(&cred.client_id)
        .client_secret(&cred.client_secret)
        .add_scope("https://graph.microsoft.com/.default")
        .redirect_uri("http://localhost:23456/redirect")
        .authorize_url("https://login.microsoftonline.com/common/adminconsent")
        .access_token_url("https://login.microsoftonline.com/common/oauth2/v2.0/token");
    oauth
}

async fn request_access_token(cred: AzureCredentials) -> Result<(), Box<dyn std::error::Error>> {
    let mut oauth = get_oauth_client(cred);
    let mut request = oauth.build_async().client_credentials();
    let access_token = request.access_token().send().await?;

    println!("{:#?}", access_token);
    oauth.access_token(access_token);
    Ok(())
}

/// Sets up the routes for the OAuth Client Credentials flow.
/// [Microsoft Client Credentials](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow)
fn get_routes<F, R>(
    redirection_handler: F,
    cred: AzureCredentials,
) -> Result<
    impl Filter<Extract = (Box<(dyn Reply)>,), Error = Rejection> + Clone,
    Box<dyn std::error::Error>,
>
where
    F: Fn((Option<ClientCredentialsResponse>, AzureCredentials)) -> R
        + std::clone::Clone
        + std::marker::Send,
    R: Future<Output = Result<Box<(dyn Reply)>, Rejection>> + std::marker::Send,
{
    let query =
        warp::query::<ClientCredentialsResponse>().map(move |resp: ClientCredentialsResponse| {
            match resp {
                v => (Some(v), cred.clone()),
                _ => (None, cred.clone()),
            }
        });

    let routes = warp::get()
        .and(warp::path("redirect"))
        .and(query)
        .and_then(redirection_handler);

    Ok(routes)
}

pub async fn start_server(cred: AzureCredentials) -> Result<(), Box<dyn std::error::Error>> {
    let routes = match get_routes(handle_redirect, cred.clone()) {
        Ok(routes) => routes,
        Err(err) => {
            eprintln!("Failed to setup routes for OAuth communication: {err}");
            panic! {"Exiting the program."};
        }
    };

    // Get the oauth client and request a browser sign in
    let mut oauth = get_oauth_client(cred);
    let mut request = oauth.build_async().client_credentials();
    request.browser_authorization().open()?;

    warp::serve(routes).run(([127, 0, 0, 1], 23456)).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn empty_redirect(
        resp_with_cred: (Option<ClientCredentialsResponse>, AzureCredentials),
    ) -> Result<Box<dyn warp::Reply>, warp::Rejection> {
        match resp_with_cred.0 {
            Some(client_credential_response) => {
                Ok(Box::new(warp::reply::json(&client_credential_response)))
            }
            None => Err(warp::reject()),
        }
    }

    #[tokio::test]
    async fn oauth_redirect_response_ismatched() {
        let routes = get_routes(
            empty_redirect,
            AzureCredentials {
                client_id: "foo".to_string(),
                client_secret: "bar".to_string(),
            },
        )
        .unwrap();
        // http://localhost:8000/redirect?admin_consent=True&tenant=foo
        let response_bytes = warp::test::request()
            .method("GET")
            .path("/redirect?admin_consent=true&tenant=foo")
            .reply(&routes)
            .await;
        let parsed_body = std::str::from_utf8(&response_bytes.body()).unwrap();
        let got: ClientCredentialsResponse = serde_json::from_str(parsed_body).unwrap();
        let want = ClientCredentialsResponse {
            admin_consent: true,
            tenant: "foo".to_string(),
        };
        assert_eq!(want, got)
    }
}
