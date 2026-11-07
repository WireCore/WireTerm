//! Organizations, teams, members and invitations.
//!
//! All of it is answered by better-auth under `/api/auth/organization/*`; the
//! backend has no routes of its own for it and only passes it through. That is
//! why it lives here and not in [`super::api`], and why the errors look
//! different — `{code, message}` instead of `{code, detail}`, see
//! [`super::http`].
//!
//! An organization **is** a workspace. There is no separate workspace model,
//! and "Personal" is just the one created at registration: it can be renamed
//! but not deleted — inviting is allowed, though, and that is exactly how it
//! becomes a team.

use rust_i18n::t;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::http::{Api, ApiError, Jar};
use super::model::Role;

type Answer<T> = Result<T, ApiError>;

fn parse<T: serde::de::DeserializeOwned>(value: Value) -> Answer<T> {
    serde_json::from_value(value).map_err(|e| ApiError::Api {
        status: 200,
        code: "I-IP".to_string(),
        detail: t!("cloud_sync.unexpected_response", error = e).into_owned(),
    })
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationRow {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub slug: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TeamRow {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub organization_id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MemberRow {
    /// The membership ID — what `update-member-role` expects.
    pub id: String,
    pub user_id: String,
    #[serde(default)]
    pub role: Role,
    #[serde(default)]
    pub user: Option<MemberUser>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MemberUser {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub email: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct InvitationRow {
    pub id: String,
    pub email: String,
    #[serde(default)]
    pub role: Option<String>,
    /// `pending`, `accepted`, `rejected`, `canceled`.
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub team_id: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub organization_id: Option<String>,
    /// Only for the invitations addressed to the signed-in user.
    #[serde(default)]
    pub organization_name: Option<String>,
}

/// An organization with everything its management needs.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FullOrganization {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub members: Vec<MemberRow>,
    #[serde(default)]
    pub invitations: Vec<InvitationRow>,
    #[serde(default)]
    pub teams: Vec<TeamRow>,
}

// ---- Organization ------------------------------------------------------------

pub async fn full(api: &Api, jar: &mut Jar, org: &str) -> Answer<FullOrganization> {
    parse(
        api.get(
            "/api/auth/organization/get-full-organization",
            &[("organizationId", org.to_string())],
            jar,
        )
        .await?,
    )
}

/// Creates an organization. The slug has to be unique; here it is formed from
/// the name and given a suffix if needed — asking for it would be asking about
/// something that appears nowhere in the UI.
pub async fn create(api: &Api, jar: &mut Jar, name: &str) -> Answer<OrganizationRow> {
    let base = slugify(name);
    let mut slug = base.clone();

    for attempt in 0..5u32 {
        if attempt > 0 {
            slug = format!("{base}-{}", suffix());
        }
        let answer = api
            .post(
                "/api/auth/organization/create",
                json!({
                    "name": name,
                    "slug": slug,
                    // The workspace currently being worked in should not switch
                    // just because a new one was created on the side.
                    "keepCurrentActiveOrganization": true,
                }),
                jar,
            )
            .await;

        match answer {
            Ok(value) => return parse(value),
            Err(ApiError::Api { ref code, .. }) if is_slug_taken(code) => continue,
            Err(error) => return Err(error),
        }
    }

    Err(ApiError::Api {
        status: 400,
        code: "SLUG_TAKEN".to_string(),
        detail: t!("cloud_sync.no_free_slug").into_owned(),
    })
}

fn is_slug_taken(code: &str) -> bool {
    code.contains("SLUG") || code.contains("ALREADY_EXISTS")
}

pub async fn rename(api: &Api, jar: &mut Jar, org: &str, name: &str) -> Answer<()> {
    api.post(
        "/api/auth/organization/update",
        json!({ "organizationId": org, "data": { "name": name } }),
        jar,
    )
    .await
    .map(|_| ())
}

/// The server rejects "Personal" (`PERSONAL_WORKSPACE_NOT_DELETABLE`).
/// Otherwise someone would be left without any workspace after one click, and
/// a second one would never come into being — the registration that creates
/// it is long over.
pub async fn delete(api: &Api, jar: &mut Jar, org: &str) -> Answer<()> {
    api.post(
        "/api/auth/organization/delete",
        json!({ "organizationId": org }),
        jar,
    )
    .await
    .map(|_| ())
}

/// Leaving instead of deleting — for everyone who does not own the organization.
pub async fn leave(api: &Api, jar: &mut Jar, org: &str) -> Answer<()> {
    api.post(
        "/api/auth/organization/leave",
        json!({ "organizationId": org }),
        jar,
    )
    .await
    .map(|_| ())
}

// ---- Members -----------------------------------------------------------------

pub async fn invite(
    api: &Api,
    jar: &mut Jar,
    org: &str,
    email: &str,
    role: Role,
    team: Option<&str>,
) -> Answer<InvitationRow> {
    let mut body = json!({
        "organizationId": org,
        "email": email,
        "role": role,
        // A second invitation to the same address should send the mail again
        // instead of refusing: "it never arrived" is the most common reason to
        // try again.
        "resend": true,
    });
    if let (Some(team), Some(object)) = (team, body.as_object_mut()) {
        object.insert("teamId".to_string(), json!(team));
    }
    parse(
        api.post("/api/auth/organization/invite-member", body, jar)
            .await?,
    )
}

pub async fn cancel_invitation(api: &Api, jar: &mut Jar, id: &str) -> Answer<()> {
    api.post(
        "/api/auth/organization/cancel-invitation",
        json!({ "invitationId": id }),
        jar,
    )
    .await
    .map(|_| ())
}

/// Whether a rejection is due to the email address not being verified.
///
/// better-auth requires that for everything that touches an invitation **by
/// its ID** — listing, accepting, rejecting — as soon as the IDs do not come
/// from its built-in, opaque generator. With the Prisma adapter that is exactly
/// the case.
///
/// For the UI this is not an error but information: the dialog then offers the
/// verification mail ([`send_verification_email`]), and an invitation can
/// still be accepted through the link in the mail.
pub fn needs_verified_email(error: &ApiError) -> bool {
    error.code().starts_with("EMAIL_VERIFICATION_REQUIRED")
}

/// The invitations addressed to the signed-in user.
pub async fn my_invitations(api: &Api, jar: &mut Jar) -> Answer<Vec<InvitationRow>> {
    parse(
        api.get("/api/auth/organization/list-user-invitations", &[], jar)
            .await?,
    )
}

/// Sends the link for verifying the email address again. It already goes out
/// at registration; this is for everyone whose mail did not arrive or whose
/// account is older than the verification.
///
/// An already verified address is not an error — then what this was about is
/// already done.
pub async fn send_verification_email(api: &Api, jar: &mut Jar, email: &str) -> Answer<()> {
    match api
        .post(
            "/api/auth/send-verification-email",
            json!({ "email": email }),
            jar,
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(error) if error.code() == "EMAIL_ALREADY_VERIFIED" => Ok(()),
        Err(error) => Err(error),
    }
}

pub async fn accept_invitation(api: &Api, jar: &mut Jar, id: &str) -> Answer<Value> {
    api.post(
        "/api/auth/organization/accept-invitation",
        json!({ "invitationId": id }),
        jar,
    )
    .await
}

pub async fn reject_invitation(api: &Api, jar: &mut Jar, id: &str) -> Answer<()> {
    api.post(
        "/api/auth/organization/reject-invitation",
        json!({ "invitationId": id }),
        jar,
    )
    .await
    .map(|_| ())
}

pub async fn remove_member(api: &Api, jar: &mut Jar, org: &str, member: &str) -> Answer<()> {
    api.post(
        "/api/auth/organization/remove-member",
        json!({ "organizationId": org, "memberIdOrEmail": member }),
        jar,
    )
    .await
    .map(|_| ())
}

pub async fn set_role(api: &Api, jar: &mut Jar, org: &str, member: &str, role: Role) -> Answer<()> {
    api.post(
        "/api/auth/organization/update-member-role",
        json!({ "organizationId": org, "memberId": member, "role": role }),
        jar,
    )
    .await
    .map(|_| ())
}

// ---- Teams -------------------------------------------------------------------

pub async fn teams(api: &Api, jar: &mut Jar, org: &str) -> Answer<Vec<TeamRow>> {
    parse(
        api.get(
            "/api/auth/organization/list-teams",
            &[("organizationId", org.to_string())],
            jar,
        )
        .await?,
    )
}

pub async fn create_team(api: &Api, jar: &mut Jar, org: &str, name: &str) -> Answer<TeamRow> {
    parse(
        api.post(
            "/api/auth/organization/create-team",
            json!({ "organizationId": org, "name": name }),
            jar,
        )
        .await?,
    )
}

pub async fn rename_team(api: &Api, jar: &mut Jar, team: &str, name: &str) -> Answer<()> {
    api.post(
        "/api/auth/organization/update-team",
        json!({ "teamId": team, "data": { "name": name } }),
        jar,
    )
    .await
    .map(|_| ())
}

pub async fn remove_team(api: &Api, jar: &mut Jar, org: &str, team: &str) -> Answer<()> {
    api.post(
        "/api/auth/organization/remove-team",
        json!({ "organizationId": org, "teamId": team }),
        jar,
    )
    .await
    .map(|_| ())
}

pub async fn team_members(api: &Api, jar: &mut Jar, team: &str) -> Answer<Vec<MemberRow>> {
    parse(
        api.get(
            "/api/auth/organization/list-team-members",
            &[("teamId", team.to_string())],
            jar,
        )
        .await?,
    )
}

pub async fn add_team_member(
    api: &Api,
    jar: &mut Jar,
    org: &str,
    team: &str,
    user: &str,
) -> Answer<()> {
    api.post(
        "/api/auth/organization/add-team-member",
        json!({ "organizationId": org, "teamId": team, "userId": user }),
        jar,
    )
    .await
    .map(|_| ())
}

pub async fn remove_team_member(
    api: &Api,
    jar: &mut Jar,
    org: &str,
    team: &str,
    user: &str,
) -> Answer<()> {
    api.post(
        "/api/auth/organization/remove-team-member",
        json!({ "organizationId": org, "teamId": team, "userId": user }),
        jar,
    )
    .await
    .map(|_| ())
}

// ---- The slug ----------------------------------------------------------------

/// Turns a name into an identifier: lower-case letters, digits, hyphens.
///
/// German umlauts are spelled out instead of dropped — "Bürogebäude" should
/// become `buerogebaeude` and not `brogebude`.
fn slugify(name: &str) -> String {
    let mut out = String::new();
    for character in name.trim().to_lowercase().chars() {
        match character {
            'ä' => out.push_str("ae"),
            'ö' => out.push_str("oe"),
            'ü' => out.push_str("ue"),
            'ß' => out.push_str("ss"),
            c if c.is_ascii_alphanumeric() => out.push(c),
            _ => {
                if !out.ends_with('-') && !out.is_empty() {
                    out.push('-');
                }
            }
        }
    }
    let slug = out.trim_matches('-').to_string();
    // better-auth requires at least one character; a name made only of special
    // characters is rare, but here it costs just one line.
    if slug.is_empty() {
        return format!("workspace-{}", suffix());
    }
    slug.chars().take(48).collect()
}

/// A short random suffix that frees up a taken slug.
fn suffix() -> String {
    uuid::Uuid::new_v4()
        .simple()
        .to_string()
        .chars()
        .take(6)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// "Bürogebäude" should become `buerogebaeude` and not `brogebude`.
    #[test]
    fn umlauts_are_spelled_out() {
        assert_eq!(slugify("Bürogebäude"), "buerogebaeude");
        assert_eq!(slugify("Straße 17"), "strasse-17");
    }

    #[test]
    fn a_name_becomes_an_identifier() {
        assert_eq!(slugify("  My  Company Inc "), "my-company-inc");
        assert_eq!(slugify("A/B–Test"), "a-b-test");
    }

    /// better-auth requires at least one character.
    #[test]
    fn a_name_of_special_characters_still_yields_an_identifier() {
        let slug = slugify("···");
        assert!(slug.starts_with("workspace-"));
        assert!(slug.len() > "workspace-".len());
    }
}
