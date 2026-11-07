//! The backend's endpoints, one function each.
//!
//! Nothing here decides anything: a request is made and the answer read into
//! a struct. What happens next is in [`super::sync`] and [`super::mod`].
//!
//! Two halves, and they come from different houses. Everything under
//! `/api/auth/` is answered by better-auth — accounts, organizations, teams,
//! invitations; everything else is our own. That is also the reason for two
//! error forms, see [`super::http`].

use rust_i18n::t;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::cache::Grant;
use super::http::{Api, ApiError, Jar};
use super::model::{ApiSnippet, MemberKey, ShareRole, SyncResponse, WorkspaceRow};
use super::wirecloud::{claims_of, WcError};

type Answer<T> = Result<T, ApiError>;

fn parse<T: serde::de::DeserializeOwned>(value: Value) -> Answer<T> {
    serde_json::from_value(value).map_err(|e| ApiError::Api {
        status: 200,
        code: "I-IP".to_string(),
        detail: t!("cloud.response_unexpected", error = e).to_string(),
    })
}

// ---- Account -----------------------------------------------------------------

/// Who is signed in.
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub email: String,
}

/// Sign-up. Along the way the server creates "Personal" — an organization
/// that belongs only to the new user.
pub async fn sign_up(
    api: &Api,
    jar: &mut Jar,
    email: &str,
    password: &str,
    name: &str,
) -> Answer<User> {
    let answer = api
        .post(
            "/api/auth/sign-up/email",
            json!({
                "email": email,
                "password": password,
                "name": name,
                "locale": crate::locale::current(),
            }),
            jar,
        )
        .await?;
    user_of(answer)
}

/// Stores the UI language with the account, so the backend's mails to it
/// (password reset, invitations) arrive in that language.
pub async fn set_locale(api: &Api, jar: &mut Jar, locale: &str) -> Answer<()> {
    api.post("/api/auth/update-user", json!({ "locale": locale }), jar)
        .await?;
    Ok(())
}

pub async fn sign_in(api: &Api, jar: &mut Jar, email: &str, password: &str) -> Answer<User> {
    let answer = api
        .post(
            "/api/auth/sign-in/email",
            json!({ "email": email, "password": password }),
            jar,
        )
        .await?;
    user_of(answer)
}

/// Both answers carry the user under `user`; older versions put it flat
/// next to it.
fn user_of(answer: Value) -> Answer<User> {
    match answer.get("user") {
        Some(user) => parse(user.clone()),
        None => parse(answer),
    }
}

/// Whether the stored session is still valid. `None` means: it is not.
pub async fn session(api: &Api, jar: &mut Jar) -> Answer<Option<User>> {
    // In WireCloud mode there is no `get-session`. Whether the session is
    // valid, WireCloud says: fetching a tool token only works with a live
    // session (and renews the access token if needed). The name comes from
    // the token.
    if let Some(wc) = jar.wirecloud().cloned() {
        return match wc.tool_token(false).await {
            Ok(token) => {
                let claims = claims_of(&token).unwrap_or_default();
                Ok(Some(User {
                    id: wc.user_id(),
                    name: claims.name,
                    email: claims.email,
                }))
            }
            Err(WcError::Ended) | Err(WcError::Unauthorized) => Ok(None),
            Err(other) => Err(other.into()),
        };
    }
    match api.get("/api/auth/get-session", &[], jar).await {
        Ok(Value::Null) => Ok(None),
        Ok(answer) => match answer.get("user") {
            Some(user) if !user.is_null() => parse(user.clone()).map(Some),
            _ => Ok(None),
        },
        Err(ApiError::Unauthorized) => Ok(None),
        Err(error) => Err(error),
    }
}

pub async fn sign_out(api: &Api, jar: &mut Jar) -> Answer<()> {
    // In WireCloud mode the session ends at WireCloud, not at the backend.
    if let Some(wc) = jar.wirecloud().cloned() {
        wc.sign_out().await;
        jar.clear();
        return Ok(());
    }
    api.post("/api/auth/sign-out", json!({}), jar).await?;
    jar.clear();
    Ok(())
}

/// Resets the **sign-in password**, not the master password. Whoever loses
/// their master password does not get to their secrets this way — that is
/// what the recovery codes are for.
pub async fn request_password_reset(api: &Api, jar: &mut Jar, email: &str) -> Answer<()> {
    api.post(
        "/api/auth/request-password-reset",
        json!({ "email": email }),
        jar,
    )
    .await
    .map(|_| ())
}

// ---- WireCloud mode ----------------------------------------------------------

/// Links an existing local account with the same email address to the
/// WireCloud account of this session. Required is the previous **sign-in
/// password** of the local account; it is checked by the backend, which also
/// counts how often it was wrong.
pub async fn link_wirecloud(api: &Api, jar: &mut Jar, password: &str) -> Answer<()> {
    api.post("/api/wirecloud/link", json!({ "password": password }), jar)
        .await
        .map(|_| ())
}

/// Who the person is **in the backend**.
///
/// In cookie mode `sign-in` says so. In WireCloud mode the client only knows
/// the WireCloud ID (`sub`), not the local one that keys and memberships hang
/// on. `GET /api/wirecloud/me` names it. Like every other route it answers
/// with `409 WC-EC` as long as an old local account still has to be linked.
pub async fn own_user(api: &Api, jar: &mut Jar) -> Answer<User> {
    parse(api.get("/api/wirecloud/me", &[], jar).await?)
}

// ---- Key material ------------------------------------------------------------

/// A ciphertext with everything needed to open it — except the password.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct WrappedKey {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub wrap_algorithm: String,
    /// base64.
    pub nonce: String,
    /// base64.
    pub encrypted_private_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kdf: String,
    /// base64.
    pub kdf_salt: String,
    /// JSON, e.g. `{"m":65536,"t":3,"p":4}`. Travels **along**, so that the
    /// parameters can be raised without locking out existing accounts.
    pub kdf_params: String,
}

/// A recovery code: the same private key, wrapped once more.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryRow {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    /// The first group of the code in plaintext. The matching row is
    /// recognized by it, instead of trying eight Argon2id runs.
    pub label: String,
    #[serde(flatten)]
    pub wrapped: WrappedKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used_at: Option<String>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct KeyMaterial {
    #[serde(default)]
    pub algorithm: String,
    /// base64.
    pub public_key: String,
    pub master: WrappedKey,
    #[serde(default)]
    pub recovery_keys: Vec<RecoveryRow>,
}

/// `None` means: this user has not set up a master password yet.
/// Not an error, but the information that the setup is still ahead.
pub async fn keys(api: &Api, jar: &mut Jar) -> Answer<Option<KeyMaterial>> {
    match api.get("/api/keys/me", &[], jar).await {
        Ok(answer) => parse(answer).map(Some),
        Err(ApiError::Api { code, .. }) if code == "K-NF" => Ok(None),
        Err(error) => Err(error),
    }
}

/// Works **exactly once**. A second call answers `409 K-EX`, and that is not
/// a protection against typos but against data loss: every project key of
/// this user is wrapped to the old public key.
pub async fn create_keys(
    api: &Api,
    jar: &mut Jar,
    algorithm: &str,
    public_key: &str,
    master: &WrappedKey,
    recovery: &[RecoveryRow],
) -> Answer<()> {
    api.post(
        "/api/keys/me",
        json!({
            "algorithm": algorithm,
            "publicKey": public_key,
            "master": master,
            "recoveryKeys": recovery,
        }),
        jar,
    )
    .await
    .map(|_| ())
}

/// The master password has changed — or a recovery code was redeemed. The
/// key pair stays the same, only the wrapping is new, and that is why all
/// project keys stay valid.
pub async fn rewrap(
    api: &Api,
    jar: &mut Jar,
    master: &WrappedKey,
    recovery: Option<&[RecoveryRow]>,
) -> Answer<()> {
    let mut body = json!({ "master": master });
    if let (Some(recovery), Some(object)) = (recovery, body.as_object_mut()) {
        object.insert("recoveryKeys".to_string(), json!(recovery));
    }
    api.post("/api/keys/me/rewrap", body, jar).await.map(|_| ())
}

/// A code is valid once. It is used up in the client — the server only
/// learns that it happened, so that the UI can show it.
pub async fn mark_recovery_used(api: &Api, jar: &mut Jar, id: &str) -> Answer<()> {
    api.post(
        format!("/api/keys/me/recovery/{id}/used").as_str(),
        json!({}),
        jar,
    )
    .await
    .map(|_| ())
}

// ---- The tree ----------------------------------------------------------------

/// One row per organization this user is a member of.
pub async fn workspaces(api: &Api, jar: &mut Jar) -> Answer<Vec<WorkspaceRow>> {
    parse(api.get("/api/workspaces", &[], jar).await?)
}

pub async fn sync(api: &Api, jar: &mut Jar, org: &str, since: &str) -> Answer<SyncResponse> {
    parse(
        api.get(
            &format!("/api/workspaces/{org}/sync"),
            &[("since", since.to_string())],
            jar,
        )
        .await?,
    )
}

pub async fn create_project(
    api: &Api,
    jar: &mut Jar,
    org: &str,
    id: &str,
    name: &str,
    position: i64,
) -> Answer<()> {
    api.post(
        &format!("/api/workspaces/{org}/projects"),
        json!({ "id": id, "name": name, "position": position }),
        jar,
    )
    .await
    .map(|_| ())
}

pub async fn update_project(
    api: &Api,
    jar: &mut Jar,
    org: &str,
    id: &str,
    name: &str,
    position: i64,
    expected_revision: Option<&str>,
) -> Answer<()> {
    let mut body = json!({ "name": name, "position": position });
    if let Some(revision) = expected_revision {
        body["expectedRevision"] = json!(revision);
    }
    api.patch(&format!("/api/workspaces/{org}/projects/{id}"), body, jar)
        .await
        .map(|_| ())
}

pub async fn delete_project(api: &Api, jar: &mut Jar, org: &str, id: &str) -> Answer<()> {
    api.delete(&format!("/api/workspaces/{org}/projects/{id}"), jar)
        .await
        .map(|_| ())
}

pub async fn create_snippet(
    api: &Api,
    jar: &mut Jar,
    org: &str,
    snippet: &ApiSnippet,
) -> Answer<()> {
    api.post(
        &format!("/api/workspaces/{org}/snippets"),
        json!({
            "id": snippet.id,
            "name": snippet.name,
            "folder": snippet.folder,
            "command": snippet.command,
            "position": snippet.position,
        }),
        jar,
    )
    .await
    .map(|_| ())
}

pub async fn update_snippet(
    api: &Api,
    jar: &mut Jar,
    org: &str,
    snippet: &ApiSnippet,
    expected_revision: Option<&str>,
) -> Answer<()> {
    let mut body = json!({
        "name": snippet.name,
        "folder": snippet.folder,
        "command": snippet.command,
        "position": snippet.position,
    });
    if let Some(revision) = expected_revision {
        body["expectedRevision"] = json!(revision);
    }
    api.patch(
        &format!("/api/workspaces/{org}/snippets/{}", snippet.id),
        body,
        jar,
    )
    .await
    .map(|_| ())
}

pub async fn delete_snippet(api: &Api, jar: &mut Jar, org: &str, id: &str) -> Answer<()> {
    api.delete(&format!("/api/workspaces/{org}/snippets/{id}"), jar)
        .await
        .map(|_| ())
}

pub async fn create_connection(
    api: &Api,
    jar: &mut Jar,
    org: &str,
    project: &str,
    body: Value,
) -> Answer<()> {
    api.post(
        &format!("/api/workspaces/{org}/projects/{project}/connections"),
        body,
        jar,
    )
    .await
    .map(|_| ())
}

pub async fn update_connection(
    api: &Api,
    jar: &mut Jar,
    org: &str,
    id: &str,
    body: Value,
) -> Answer<()> {
    api.patch(
        &format!("/api/workspaces/{org}/connections/{id}"),
        body,
        jar,
    )
    .await
    .map(|_| ())
}

pub async fn delete_connection(api: &Api, jar: &mut Jar, org: &str, id: &str) -> Answer<()> {
    api.delete(&format!("/api/workspaces/{org}/connections/{id}"), jar)
        .await
        .map(|_| ())
}

/// Mind the order: the server rejects a `secret` with an unknown `keyId`,
/// because a ciphertext nobody can open would be silent data loss. The
/// project key therefore has to be uploaded first.
pub async fn put_secret(
    api: &Api,
    jar: &mut Jar,
    org: &str,
    connection: &str,
    key_id: &str,
    nonce: &str,
    ciphertext: &str,
) -> Answer<()> {
    api.put(
        &format!("/api/workspaces/{org}/connections/{connection}/secret"),
        json!({
            "algorithm": super::crypto::SECRET_ALGORITHM,
            "keyId": key_id,
            "nonce": nonce,
            "ciphertext": ciphertext,
        }),
        jar,
    )
    .await
    .map(|_| ())
}

pub async fn delete_secret(api: &Api, jar: &mut Jar, org: &str, connection: &str) -> Answer<()> {
    match api
        .delete(
            &format!("/api/workspaces/{org}/connections/{connection}/secret"),
            jar,
        )
        .await
    {
        // Already gone is the goal of the call.
        Err(ApiError::Api { code, .. }) if code == "S-NF" => Ok(()),
        other => other.map(|_| ()),
    }
}

// ---- Shares and keys ---------------------------------------------------------

/// The public keys of all members. Whoever wants to grant a share needs them
/// for wrapping.
pub async fn member_keys(api: &Api, jar: &mut Jar, org: &str) -> Answer<Vec<MemberKey>> {
    parse(
        api.get(&format!("/api/workspaces/{org}/member-keys"), &[], jar)
            .await?,
    )
}

/// Who is still missing a key for this project. The step only a client can
/// take — the server can record a share, but not grant one.
pub async fn key_requests(
    api: &Api,
    jar: &mut Jar,
    org: &str,
    project: &str,
) -> Answer<Vec<MemberKey>> {
    parse(
        api.get(
            &format!("/api/workspaces/{org}/projects/{project}/key-requests"),
            &[],
            jar,
        )
        .await?,
    )
}

pub async fn grant_keys(
    api: &Api,
    jar: &mut Jar,
    org: &str,
    project: &str,
    key_id: &str,
    grants: &[Grant],
) -> Answer<()> {
    if grants.is_empty() {
        return Ok(());
    }
    api.post(
        &format!("/api/workspaces/{org}/projects/{project}/keys"),
        json!({
            "keyId": key_id,
            "algorithm": super::crypto::GRANT_ALGORITHM,
            "grants": grants,
        }),
        jar,
    )
    .await
    .map(|_| ())
}

pub async fn revoke_key(
    api: &Api,
    jar: &mut Jar,
    org: &str,
    project: &str,
    user: &str,
) -> Answer<()> {
    api.delete(
        &format!("/api/workspaces/{org}/projects/{project}/keys/{user}"),
        jar,
    )
    .await
    .map(|_| ())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StaleKeys {
    project_ids: Vec<String>,
}

/// The projects whose current version `user` holds without being allowed to
/// see them any more — after removal exactly those that need renewing.
pub async fn stale_keys(api: &Api, jar: &mut Jar, org: &str, user: &str) -> Answer<Vec<String>> {
    let answer: StaleKeys = parse(
        api.get(
            &format!("/api/workspaces/{org}/members/{user}/stale-keys"),
            &[],
            jar,
        )
        .await?,
    )?;
    Ok(answer.project_ids)
}

pub async fn shares(
    api: &Api,
    jar: &mut Jar,
    org: &str,
    project: &str,
) -> Answer<Vec<super::model::ApiShare>> {
    parse(
        api.get(
            &format!("/api/workspaces/{org}/projects/{project}/shares"),
            &[],
            jar,
        )
        .await?,
    )
}

/// Replaces the **whole set**. Whoever is no longer in the list loses
/// access — and the server deletes their wrapped copy of the project key
/// along the way.
pub async fn put_shares(
    api: &Api,
    jar: &mut Jar,
    org: &str,
    project: &str,
    shares: &[(Option<String>, ShareRole)],
) -> Answer<()> {
    let list: Vec<Value> = shares
        .iter()
        .map(|(team, role)| json!({ "teamId": team, "role": role }))
        .collect();
    api.put(
        &format!("/api/workspaces/{org}/projects/{project}/shares"),
        json!({ "shares": list }),
        jar,
    )
    .await
    .map(|_| ())
}

// ---- Vault accounts and host keys --------------------------------------------

pub async fn put_vault_account(
    api: &Api,
    jar: &mut Jar,
    org: &str,
    provider: &str,
    account: &str,
    server: &str,
    accept_invalid_cert: bool,
) -> Answer<()> {
    api.put(
        &format!("/api/workspaces/{org}/vault-accounts/{provider}"),
        json!({
            "account": account,
            "server": server,
            "acceptInvalidCert": accept_invalid_cert,
        }),
        jar,
    )
    .await
    .map(|_| ())
}

pub async fn delete_vault_account(
    api: &Api,
    jar: &mut Jar,
    org: &str,
    provider: &str,
) -> Answer<()> {
    api.delete(
        &format!("/api/workspaces/{org}/vault-accounts/{provider}"),
        jar,
    )
    .await
    .map(|_| ())
}

pub async fn add_known_host(
    api: &Api,
    jar: &mut Jar,
    org: &str,
    host: &str,
    port: u16,
    algorithm: &str,
    public_key: &str,
) -> Answer<()> {
    api.post(
        &format!("/api/workspaces/{org}/known-hosts"),
        json!({
            "host": host,
            "port": port,
            "algorithm": algorithm,
            "publicKey": public_key,
        }),
        jar,
    )
    .await
    .map(|_| ())
}

pub async fn remove_known_host(api: &Api, jar: &mut Jar, org: &str, id: &str) -> Answer<()> {
    api.delete(&format!("/api/workspaces/{org}/known-hosts/{id}"), jar)
        .await
        .map(|_| ())
}

/// The paths of WireCloud mode against a small real server.
#[cfg(test)]
mod wirecloud_tests {
    use super::*;
    use crate::cloud::http::Server;
    use crate::cloud::test_server::server;
    use crate::cloud::wirecloud::{CountingEndpoint, Wc};

    fn run<F: std::future::Future>(future: F) -> F::Output {
        tauri::async_runtime::block_on(future)
    }

    fn api(url: &str) -> Api {
        Api::new(&Server::resolve(url, false).expect("resolves")).expect("builds")
    }

    fn jar() -> Jar {
        let mut jar = Jar::default();
        jar.set_wirecloud(Wc::for_test(CountingEndpoint::new(), "refresh-0"));
        jar
    }

    /// The backend names the local ID itself, asked with the tool token.
    #[test]
    fn the_local_id_comes_from_the_backend() {
        run(async {
            let (url, seen) = server(vec![(
                200,
                "",
                r#"{"id":"local-1","name":"Max Muster","email":"max@example.test"}"#,
            )])
            .await;
            let user = own_user(&api(&url), &mut jar()).await.expect("answers");
            assert_eq!(user.id, "local-1");
            assert_eq!(user.name, "Max Muster");
            assert_eq!(user.email, "max@example.test");
            let seen = seen.lock().unwrap();
            assert_eq!(seen.len(), 1);
            assert_eq!(seen[0].method, "GET");
            assert_eq!(seen[0].path, "/api/wirecloud/me");
            assert_eq!(seen[0].authorization, "Bearer tool-1");
        });
    }

    /// The conflict the backend reports when it already knows the account from
    /// the time before WireCloud arrives as `WC-EC` and is understandable.
    #[test]
    fn an_existing_account_is_reported_as_wc_ec() {
        run(async {
            let (url, _) = server(vec![(409, "", r#"{"code":"WC-EC"}"#)]).await;
            let error = own_user(&api(&url), &mut jar())
                .await
                .expect_err("conflict");
            assert_eq!(error.code(), "WC-EC");
            assert!(error.to_string().contains("linked"), "{error}");
        });
    }

    #[test]
    fn linking_sends_the_password_and_the_tool_token() {
        run(async {
            let (url, seen) = server(vec![(200, "", r#"{"linked":true}"#)]).await;
            link_wirecloud(&api(&url), &mut jar(), "old-password")
                .await
                .expect("linked");
            let seen = seen.lock().unwrap();
            assert_eq!(seen[0].method, "POST");
            assert_eq!(seen[0].path, "/api/wirecloud/link");
            assert_eq!(seen[0].authorization, "Bearer tool-1");
            assert_eq!(
                serde_json::from_str::<Value>(&seen[0].body).unwrap(),
                json!({ "password": "old-password" })
            );
        });
    }

    #[test]
    fn linking_errors_have_understandable_texts() {
        run(async {
            for (status, code, wanted) in [
                (403, "WC-LD", "password is wrong"),
                (403, "WC-NV", "not been verified"),
                (404, "WC-NN", "no existing account"),
                (429, "WC-RL", "15 minutes"),
            ] {
                let body: &'static str =
                    Box::leak(format!(r#"{{"code":"{code}"}}"#).into_boxed_str());
                let (url, _) = server(vec![(status, "", body)]).await;
                let error = link_wirecloud(&api(&url), &mut jar(), "x")
                    .await
                    .expect_err("rejected");
                assert_eq!(error.code(), code);
                assert!(error.to_string().contains(wanted), "{code}: {error}");
            }
        });
    }

    /// Whether the stored session is valid, WireCloud says. The name comes from
    /// the tool token, the local ID from the session itself.
    #[test]
    fn the_session_is_valid_as_long_as_wirecloud_hands_out_a_tool_token() {
        run(async {
            // No backend needed: in WireCloud mode `session` only asks WireCloud.
            let user = session(&api("http://127.0.0.1:1"), &mut jar())
                .await
                .expect("valid")
                .expect("signed in");
            // The test token is no JWT: the name is missing, the ID is the local one.
            assert_eq!(user.id, "u1");
        });
    }

    #[test]
    fn signing_out_ends_the_session_for_copies_too() {
        run(async {
            let mut original = jar();
            let copy = original.clone();
            sign_out(&api("http://127.0.0.1:1"), &mut original)
                .await
                .expect("signs out");
            assert!(original.is_empty());
            assert!(copy.is_empty());
            // Afterwards it is no longer valid.
            let mut again = copy.clone();
            let answer = session(&api("http://127.0.0.1:1"), &mut again).await;
            assert!(matches!(answer, Ok(None)), "{answer:?}");
        });
    }
}
