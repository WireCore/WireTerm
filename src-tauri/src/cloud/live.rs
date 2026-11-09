//! The whole way, against a running backend.
//!
//! What can be checked without a server is in the modules next to this one:
//! the crypto against itself, the diff against a made-up copy, the error
//! shapes against a string. What **cannot** be checked there is the one thing
//! that matters in the end — whether a secret that goes in here comes back out
//! on another device and for another person.
//!
//! That needs the backend from `../backend`:
//!
//! ```text
//! docker compose up -d          # in the backend directory
//! cargo test --lib cloud::live -- --ignored --nocapture
//! ```
//!
//! `WIRETERM_BACKEND` points to an address other than `http://localhost:8080`.
//! Every run creates its own accounts — nothing is cleaned up; this is a
//! throwaway database.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

use super::account::Unlocked;
use super::cache::Cached;
use super::http::{Api, Jar, Server};
use super::model::{Role, ShareRole};
use super::{api, crypto, diff, org, sync};
use crate::storage::{
    Connection, ConnectionSettings, Project, SshAuth, SshSettings, StorageKind, Workspace,
};

const MASTER: &str = "a-very-long-master-password";
const SIGN_IN: &str = "a-different-sign-in-password";

fn backend() -> Server {
    let url =
        std::env::var("WIRETERM_BACKEND").unwrap_or_else(|_| "http://localhost:8080".to_string());
    Server::resolve(&url, true).expect("the backend's address")
}

fn run<F: std::future::Future<Output = ()>>(test: F) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(test);
}

fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// An address that does not exist yet. Every run starts from scratch.
fn fresh_email(role: &str) -> String {
    format!("wt-{role}-{}@example.test", uuid::Uuid::new_v4().simple())
}

/// A fresh account with its master password set up.
struct Person {
    api: Api,
    jar: Jar,
    user_id: String,
    unlocked: Unlocked,
    email: String,
}

async fn register(role: &str) -> Person {
    let api = Api::new(&backend()).expect("HTTP client");
    let mut jar = Jar::default();
    let email = fresh_email(role);

    let user = api::sign_up(&api, &mut jar, &email, SIGN_IN, "Test User")
        .await
        .expect("sign up");
    assert!(!jar.is_empty(), "signing up signs in right away");

    // Just like `cloud_setup_master`: create a pair, wrap it, upload it.
    let pair = crypto::new_key_pair().expect("key pair");
    let master = super::wrap_private(&pair.private, MASTER.as_bytes()).expect("wrap");
    let (_codes, rows) = super::new_recovery_set(&pair.private).expect("recovery codes");

    api::create_keys(
        &api,
        &mut jar,
        crypto::KEY_ALGORITHM,
        &BASE64.encode(pair.public),
        &master,
        &rows,
    )
    .await
    .expect("create key material");

    Person {
        api,
        jar,
        user_id: user.id,
        unlocked: Unlocked::new(pair.private, pair.public),
        email,
    }
}

/// The workspace that registration created on the side.
async fn personal(person: &mut Person) -> String {
    let rows = api::workspaces(&person.api, &mut person.jar)
        .await
        .expect("workspaces");
    let row = rows
        .iter()
        .find(|row| row.kind == super::WorkspaceKind::Personal)
        .expect("\"Personal\" is created at registration");
    row.id.clone()
}

/// Project and connection IDs come from the client — and on the server they
/// are unique **server-wide**, not per organization. That is why this uses the
/// same UUIDs as the app and no descriptive names: those would collide with
/// the first run's on the second run.
fn tree(org: &str, project: &str, connection: &str, secret: &str) -> Workspace {
    Workspace {
        id: org.to_string(),
        name: "Company".to_string(),
        storage: StorageKind::CustomBackend,
        one_password_account: String::new(),
        bitwarden: None,
        remote: None,
        projects: vec![Project {
            id: project.to_string(),
            name: "Production".to_string(),
            connections: vec![Connection {
                id: connection.to_string(),
                name: "web01".to_string(),
                settings: ConnectionSettings::Ssh(SshSettings {
                    host: "web01.example".to_string(),
                    port: 22,
                    user: "root".to_string(),
                    auth: SshAuth::InlineKey {
                        key: secret.to_string(),
                    },
                    start_path: String::new(),
                    jump: None,
                    agent_forwarding: false,
                    via: Vec::new(),
                    forwards: Vec::new(),
                    proxy: None,
                    startup_snippet: None,
                }),
                system: None,
                bookmarked: false,
                secret_unreadable: false,
            }],
        }],
        snippets: Vec::new(),
    }
}

/// What comes out of the copy as the one connection's secret — or nothing if
/// it cannot be opened.
fn secret_in(cached: &Cached, unlocked: Option<&Unlocked>) -> Option<String> {
    let (projects, _) = cached.tree(unlocked.map(|open| &*open.private));
    let settings = &projects.first()?.connections.first()?.settings;
    super::model::secret_of(settings).map(|value| value.to_string())
}

/// One pass: up, down, distribute keys.
async fn sync_once(person: &mut Person, cached: &mut Cached) {
    let outcome = sync::run(
        &person.api,
        &mut person.jar,
        cached,
        Some(&person.unlocked),
        &person.user_id,
    )
    .await;
    assert!(
        outcome.error.is_none(),
        "the sync should run through without complaint: {:?}",
        outcome.error
    );
    assert!(cached.pending.is_empty(), "the queue is empty");
}

/// The basic case, and the reason for this whole module: what goes up
/// encrypted here comes back out on **another device** — with nothing but the
/// master password.
///
/// "Another device" means here: fresh jar, fresh copy, `since=0`. Exactly what
/// a fresh install faces.
#[test]
#[ignore]
fn a_secret_survives_the_trip_to_the_server_and_back() {
    run(async {
        let mut me = register("solo").await;
        let workspace = personal(&mut me).await;

        let mut cached = Cached::new(
            workspace.clone(),
            "account".to_string(),
            "Company".to_string(),
        );
        sync_once(&mut me, &mut cached).await;

        let ops = diff::plan(
            &mut cached,
            &tree(&workspace, &new_id(), &new_id(), "PRIVATE KEY"),
            &me.user_id,
            Some(&me.unlocked),
        )
        .expect("plan");
        assert!(!ops.is_empty(), "a new tree yields something to do");
        cached.pending.extend(ops);

        sync_once(&mut me, &mut cached).await;
        assert_eq!(
            secret_in(&cached, Some(&me.unlocked)).as_deref(),
            Some("PRIVATE KEY")
        );

        // ---- The second device ----------------------------------------------
        let api = Api::new(&backend()).expect("HTTP client");
        let mut jar = Jar::default();
        api::sign_in(&api, &mut jar, &me.email, SIGN_IN)
            .await
            .expect("sign in");

        let material = api::keys(&api, &mut jar)
            .await
            .expect("key material")
            .expect("there is some");
        let private =
            super::open_private(&material.master, MASTER.as_bytes()).expect("master password");
        let public = crypto::public_key_of(&private);

        let mut elsewhere = Cached::new(workspace, "account2".to_string(), "Company".to_string());
        let delta = api::sync(&api, &mut jar, &elsewhere.id.clone(), "0")
            .await
            .expect("sync");
        elsewhere.apply(delta);

        let unlocked = Unlocked::new(private, public);
        assert_eq!(
            secret_in(&elsewhere, Some(&unlocked)).as_deref(),
            Some("PRIVATE KEY"),
            "the same secret, just via the server"
        );

        // And without the master password: the row is there, the secret is
        // not. That is exactly what the server itself sees.
        assert_eq!(secret_in(&elsewhere, None), None);
        let (projects, missing) = elsewhere.tree(None);
        assert_eq!(projects[0].connections[0].name, "web01");
        assert!(
            missing,
            "locked means: something is missing, and that is reported"
        );
    });
}

/// Two devices, the same connection, both change it. The second one loses —
/// but not silently: the sync reports it, and afterwards both have the version
/// that was up first.
#[test]
#[ignore]
fn a_concurrent_change_is_reported_instead_of_overwritten() {
    run(async {
        let mut me = register("conflict").await;
        let workspace = personal(&mut me).await;
        let tree_now = tree(&workspace, &new_id(), &new_id(), "PRIVATE KEY");

        let mut here = Cached::new(
            workspace.clone(),
            "account".to_string(),
            "Company".to_string(),
        );
        sync_once(&mut me, &mut here).await;
        let ops = diff::plan(&mut here, &tree_now, &me.user_id, Some(&me.unlocked)).expect("plan");
        here.enqueue(ops);
        sync_once(&mut me, &mut here).await;

        // The second device fetches the same state.
        let mut there = Cached::new(workspace, "account2".to_string(), "Company".to_string());
        sync_once(&mut me, &mut there).await;

        let mut from_here = tree_now.clone();
        from_here.projects[0].connections[0].name = "web01-here".to_string();
        let ops = diff::plan(&mut here, &from_here, &me.user_id, Some(&me.unlocked)).expect("plan");
        here.enqueue(ops);
        sync_once(&mut me, &mut here).await;

        // Over there they know nothing of it yet.
        let mut from_there = tree_now.clone();
        from_there.projects[0].connections[0].name = "web01-there".to_string();
        let ops =
            diff::plan(&mut there, &from_there, &me.user_id, Some(&me.unlocked)).expect("plan");
        there.enqueue(ops);
        let outcome = sync::run(
            &me.api,
            &mut me.jar,
            &mut there,
            Some(&me.unlocked),
            &me.user_id,
        )
        .await;

        assert!(
            outcome.error.is_none(),
            "a conflict is not an error: {:?}",
            outcome.error
        );
        assert_eq!(there.conflicts.len(), 1, "but it is reported");
        assert!(
            there.conflicts[0].contains("in the meantime"),
            "{:?}",
            there.conflicts
        );
        assert!(
            there.pending.is_empty(),
            "the discarded change does not get stuck"
        );
        let (projects, _) = there.tree(Some(&*me.unlocked.private));
        assert_eq!(
            projects[0].connections[0].name, "web01-here",
            "the version that was up first applies"
        );
    });
}

/// The sentence that matters: **the server can record a share, but not grant
/// one.**
///
/// Bert is invited and given a share. Afterwards he sees the connection — and
/// not its secret, because nobody has wrapped the project key for him. Only
/// when Anna's client syncs next does he get at it. That happens without any
/// intervention, because `sync::run` checks on every pass who is missing
/// something.
///
/// At the end the revocation, and what it cannot do: the wrapped copy is gone,
/// but what Bert has read until then he still knows. Only a new version of the
/// project key would help against that — see `TODO.md`.
#[test]
#[ignore]
fn a_new_member_gets_their_key_only_from_a_client() {
    run(async {
        let mut anna = register("anna").await;
        let mut bert = register("bert").await;

        // A separate organization — inviting would be allowed in "Personal"
        // too, but a company is the honest case.
        let created = org::create(&anna.api, &mut anna.jar, "Live Test")
            .await
            .expect("create organization");
        let workspace = created.id;

        let mut at_anna = Cached::new(
            workspace.clone(),
            "anna".to_string(),
            "Live Test".to_string(),
        );
        sync_once(&mut anna, &mut at_anna).await;

        let project = new_id();
        let ops = diff::plan(
            &mut at_anna,
            &tree(&workspace, &project, &new_id(), "SECRET"),
            &anna.user_id,
            Some(&anna.unlocked),
        )
        .expect("plan");
        at_anna.pending.extend(ops);
        sync_once(&mut anna, &mut at_anna).await;

        // ---- Invite and accept ----------------------------------------------
        //
        // The ID comes from the response to the invitation. Bert cannot fetch
        // it himself — see the test below — for him it is in the link in the
        // invitation mail.
        let invitation = org::invite(
            &anna.api,
            &mut anna.jar,
            &workspace,
            &bert.email,
            Role::Member,
            None,
        )
        .await
        .expect("invite");

        org::accept_invitation(&bert.api, &mut bert.jar, &invitation.id)
            .await
            .expect("accept");

        // ---- Share ---------------------------------------------------------
        //
        // With the whole organization, so that no team is in between: what is
        // checked here is the key, not the share.
        api::put_shares(
            &anna.api,
            &mut anna.jar,
            &workspace,
            &project,
            &[(None, ShareRole::Viewer)],
        )
        .await
        .expect("share");

        // ---- Bert sees the row, not the secret -----------------------------
        let mut at_bert = Cached::new(
            workspace.clone(),
            "bert".to_string(),
            "Live Test".to_string(),
        );
        let delta = api::sync(&bert.api, &mut bert.jar, &workspace, "0")
            .await
            .expect("sync");
        at_bert.apply(delta);

        let (projects, missing) = at_bert.tree(Some(&bert.unlocked.private));
        assert_eq!(
            projects[0].connections[0].name, "web01",
            "the share grants access to the rows"
        );
        assert!(
            missing,
            "but not to the secret: the server cannot grant a key"
        );
        assert_eq!(secret_in(&at_bert, Some(&bert.unlocked)), None);

        // And the server also says that Bert is missing something.
        let pending = api::key_requests(&anna.api, &mut anna.jar, &workspace, &project)
            .await
            .expect("key-requests");
        let bert_row = pending
            .iter()
            .find(|row| row.user_id != anna.user_id)
            .expect("Bert is in the list");
        assert!(
            bert_row.key.is_some(),
            "Bert has set up a master password, so it can be wrapped for him"
        );
        assert!(bert_row.key_ids.is_empty(), "but nobody has wrapped it yet");
        let bert_id = bert_row.user_id.clone();

        // ---- Anna's client hands it out -------------------------------------
        sync_once(&mut anna, &mut at_anna).await;

        let mut at_bert = Cached::new(
            workspace.clone(),
            "bert".to_string(),
            "Live Test".to_string(),
        );
        let delta = api::sync(&bert.api, &mut bert.jar, &workspace, "0")
            .await
            .expect("sync");
        at_bert.apply(delta);

        assert_eq!(
            secret_in(&at_bert, Some(&bert.unlocked)).as_deref(),
            Some("SECRET"),
            "after a pass of Anna's client, Bert gets at it"
        );

        // ---- Revocation -----------------------------------------------------
        api::revoke_key(&anna.api, &mut anna.jar, &workspace, &project, &bert_id)
            .await
            .expect("revoke");

        let mut at_bert = Cached::new(
            workspace.clone(),
            "bert".to_string(),
            "Live Test".to_string(),
        );
        let delta = api::sync(&bert.api, &mut bert.jar, &workspace, "0")
            .await
            .expect("sync");
        at_bert.apply(delta);
        assert_eq!(
            secret_in(&at_bert, Some(&bert.unlocked)),
            None,
            "without a wrapped copy the ciphertext is just bytes for him again"
        );
    });
}

/// Moving between two projects: on the server the connection is in the new
/// project afterwards, and its secret lies under that project's key —
/// readable for everyone with access to the new project.
#[test]
#[ignore]
fn a_connection_moves_along_with_its_secret() {
    run(async {
        let mut me = register("move").await;
        let workspace = personal(&mut me).await;
        let (old, new, connection) = (new_id(), new_id(), new_id());

        let mut tree_now = tree(&workspace, &old, &connection, "PRIVATE KEY");
        tree_now.projects.push(Project {
            id: new.clone(),
            name: "New".to_string(),
            connections: Vec::new(),
        });
        let mut here = Cached::new(
            workspace.clone(),
            "account".to_string(),
            "Company".to_string(),
        );
        sync_once(&mut me, &mut here).await;
        let ops = diff::plan(&mut here, &tree_now, &me.user_id, Some(&me.unlocked)).expect("plan");
        here.enqueue(ops);
        sync_once(&mut me, &mut here).await;

        let moving = tree_now.projects[0].connections.remove(0);
        tree_now.projects[1].connections.push(moving);
        let ops = diff::plan(&mut here, &tree_now, &me.user_id, Some(&me.unlocked)).expect("plan");
        here.enqueue(ops);
        sync_once(&mut me, &mut here).await;

        // Fresh from the server, as another device would see it.
        let mut elsewhere = Cached::new(workspace, "account2".to_string(), "Company".to_string());
        elsewhere.apply(
            api::sync(&me.api, &mut me.jar, &elsewhere.id.clone(), "0")
                .await
                .expect("sync"),
        );
        let row = elsewhere.connection(&connection).expect("the connection");
        assert_eq!(row.project_id, new, "it is in the new project");
        let secret = elsewhere.secret(&connection).expect("the secret");
        assert_eq!(
            Some(secret.key_id.clone()),
            elsewhere.current_key_id(&new),
            "under the new project's key"
        );
        let (projects, _) = elsewhere.tree(Some(&me.unlocked.private));
        let read = projects
            .iter()
            .find(|project| project.id == new)
            .and_then(|project| project.connections.first())
            .and_then(|connection| {
                super::model::secret_of(&connection.settings).map(str::to_string)
            });
        assert_eq!(read.as_deref(), Some("PRIVATE KEY"));
    });
}

/// The reason for rotation: whoever is thrown out of a project may still know
/// the old key. After a new version that is of no use to them anymore — and
/// for those who stay, nothing changes.
#[test]
#[ignore]
fn a_revocation_is_sealed_with_a_new_version() {
    run(async {
        let mut anna = register("anna").await;
        let mut bert = register("bert").await;
        let workspace = org::create(&anna.api, &mut anna.jar, "Live Test")
            .await
            .expect("create organization")
            .id;

        let mut at_anna = Cached::new(
            workspace.clone(),
            "anna".to_string(),
            "Live Test".to_string(),
        );
        sync_once(&mut anna, &mut at_anna).await;
        let project = new_id();
        let connection = new_id();
        let ops = diff::plan(
            &mut at_anna,
            &tree(&workspace, &project, &connection, "SECRET"),
            &anna.user_id,
            Some(&anna.unlocked),
        )
        .expect("plan");
        at_anna.enqueue(ops);
        sync_once(&mut anna, &mut at_anna).await;
        let old_version = at_anna.current_key_id(&project).expect("a version");

        // Bert joins, gets the key and remembers it.
        let invitation = org::invite(
            &anna.api,
            &mut anna.jar,
            &workspace,
            &bert.email,
            Role::Member,
            None,
        )
        .await
        .expect("invite");
        org::accept_invitation(&bert.api, &mut bert.jar, &invitation.id)
            .await
            .expect("accept");
        api::put_shares(
            &anna.api,
            &mut anna.jar,
            &workspace,
            &project,
            &[(None, ShareRole::Viewer)],
        )
        .await
        .expect("share");
        sync_once(&mut anna, &mut at_anna).await;

        let mut at_bert = Cached::new(
            workspace.clone(),
            "bert".to_string(),
            "Live Test".to_string(),
        );
        at_bert.apply(
            api::sync(&bert.api, &mut bert.jar, &workspace, "0")
                .await
                .expect("sync"),
        );
        let remembered = at_bert
            .unwrap_key(&bert.unlocked.private, &project, &old_version)
            .expect("Bert has the old key");

        // ---- Bert is thrown out, Anna renews --------------------------------
        api::put_shares(&anna.api, &mut anna.jar, &workspace, &project, &[])
            .await
            .expect("revoke share");
        let renewed = super::rotate::rotate(
            &anna.api,
            &mut anna.jar,
            &at_anna,
            &anna.unlocked,
            &anna.user_id,
            &project,
        )
        .await
        .expect("renew");
        assert_eq!(renewed.secrets, 1, "{renewed:?}");
        assert_eq!(renewed.skipped, 0, "{renewed:?}");
        assert_eq!(
            renewed.granted, 1,
            "only Anna is still entitled: {renewed:?}"
        );
        assert_ne!(renewed.key_id, old_version);

        sync_once(&mut anna, &mut at_anna).await;
        assert_eq!(
            at_anna.current_key_id(&project).as_deref(),
            Some(renewed.key_id.as_str()),
            "new secrets go under the new version from now on"
        );
        assert_eq!(
            secret_in(&at_anna, Some(&anna.unlocked)).as_deref(),
            Some("SECRET"),
            "nothing changes for Anna"
        );

        // What Bert remembered does not open the new ciphertext.
        let new = at_anna.secret(&connection).expect("the secret");
        assert_eq!(new.key_id, renewed.key_id);
        let nonce = BASE64.decode(&new.nonce).expect("nonce");
        let ciphertext = BASE64.decode(&new.ciphertext).expect("ciphertext");
        assert!(
            crypto::open(&remembered, &nonce, &ciphertext, connection.as_bytes()).is_err(),
            "the old key is worthless for the new ciphertext"
        );
    });
}

/// Nobody can fetch their own open invitations as long as their email address
/// is not verified.
///
/// That is not a property of the client but an unconditional check in
/// `list-user-invitations`. **Accepting** works anyway — a different rule
/// applies to that, one that does not kick in here. The way in the app is
/// therefore: verify the address via the mail from registration, or use the
/// ID or the link from the invitation mail.
///
/// The test pins down both, so that it is noticed when either of them changes.
#[test]
#[ignore]
fn own_invitations_stay_invisible_without_a_verified_address() {
    run(async {
        let mut anna = register("anna").await;
        let mut bert = register("bert").await;

        let created = org::create(&anna.api, &mut anna.jar, "Live Test")
            .await
            .expect("create organization");

        let invitation = org::invite(
            &anna.api,
            &mut anna.jar,
            &created.id,
            &bert.email,
            Role::Member,
            None,
        )
        .await
        .expect("invite");

        // For the sender it shows up in member management.
        let full = org::full(&anna.api, &mut anna.jar, &created.id)
            .await
            .expect("organization");
        assert!(
            full.invitations
                .iter()
                .any(|row| row.email == bert.email && row.status == "pending"),
            "the open invitation shows up for the sender"
        );

        // Not for the recipient.
        let error = org::my_invitations(&bert.api, &mut bert.jar)
            .await
            .expect_err("without a verified address the backend does not hand them out");
        assert!(
            org::needs_verified_email(&error),
            "and for exactly this reason: {error:?}"
        );

        // Accepting, on the other hand, works.
        org::accept_invitation(&bert.api, &mut bert.jar, &invitation.id)
            .await
            .expect("accepting works without a verified address too");

        let his = api::workspaces(&bert.api, &mut bert.jar)
            .await
            .expect("workspaces");
        assert!(
            his.iter().any(|row| row.id == created.id),
            "afterwards the workspace is in his list"
        );
    });
}

/// The server says who is missing the project key — a client has to wrap it.
///
/// A look at `…/key-requests` alone, without a second member: that one's own
/// version already counts as present there. Otherwise the sync would wrap it
/// again on every pass.
#[test]
#[ignore]
fn the_server_says_who_is_missing_the_key() {
    run(async {
        let mut me = register("keyreq").await;
        let workspace = personal(&mut me).await;

        let mut cached = Cached::new(
            workspace.clone(),
            "account".to_string(),
            "Company".to_string(),
        );
        sync_once(&mut me, &mut cached).await;

        let project = new_id();
        let ops = diff::plan(
            &mut cached,
            &tree(&workspace, &project, &new_id(), "SECRET"),
            &me.user_id,
            Some(&me.unlocked),
        )
        .expect("plan");
        cached.pending.extend(ops);
        sync_once(&mut me, &mut cached).await;

        let pending = api::key_requests(&me.api, &mut me.jar, &workspace, &project)
            .await
            .expect("key-requests");

        let myself = pending
            .iter()
            .find(|row| row.user_id == me.user_id)
            .expect("whoever may see the project is in the list");
        assert!(
            myself.key.is_some(),
            "the master password is set up, so there is a public key"
        );
        let version = cached
            .current_key_id(&project)
            .expect("there is a version of the project key");
        assert!(
            myself.key_ids.contains(&version),
            "and it is already wrapped for me"
        );
    });
}

/// A recovery code opens the same door as the master password — and
/// afterwards the new one applies, the old codes no longer do.
///
/// The key pair stays the same; that is why everything that was readable
/// before stays readable. That is exactly what is checked here.
#[test]
#[ignore]
fn a_recovery_code_opens_the_same_door() {
    run(async {
        let api = Api::new(&backend()).expect("HTTP client");
        let mut jar = Jar::default();
        let email = fresh_email("code");

        api::sign_up(&api, &mut jar, &email, SIGN_IN, "Test User")
            .await
            .expect("sign up");

        let pair = crypto::new_key_pair().expect("key pair");
        let master = super::wrap_private(&pair.private, MASTER.as_bytes()).expect("wrap");
        let (codes, rows) = super::new_recovery_set(&pair.private).expect("recovery codes");
        api::create_keys(
            &api,
            &mut jar,
            crypto::KEY_ALGORITHM,
            &BASE64.encode(pair.public),
            &master,
            &rows,
        )
        .await
        .expect("create key material");

        // A code, typed in as if from a slip of paper.
        let typed = codes[3].to_lowercase().replace('-', " ");
        let normalized = crypto::normalize_recovery_code(&typed);
        let label = crypto::recovery_label(&typed);

        let material = api::keys(&api, &mut jar)
            .await
            .expect("key material")
            .expect("there is some");
        let row = material
            .recovery_keys
            .iter()
            .find(|row| row.label.eq_ignore_ascii_case(&label))
            .expect("the label finds the row");

        let private =
            super::open_private(&row.wrapped, normalized.as_bytes()).expect("the code opens it");
        assert_eq!(
            private.as_ref(),
            pair.private.as_ref(),
            "the same private key, just wrapped differently"
        );

        // Rewrap, new set of codes — the old one opened the same door.
        const NEW: &str = "a-brand-new-master-password";
        let master = super::wrap_private(&private, NEW.as_bytes()).expect("wrap");
        let (new_codes, new_rows) = super::new_recovery_set(&private).expect("recovery codes");
        api::rewrap(&api, &mut jar, &master, Some(&new_rows))
            .await
            .expect("rewrap");

        let material = api::keys(&api, &mut jar)
            .await
            .expect("key material")
            .expect("there is some");

        assert!(
            super::open_private(&material.master, MASTER.as_bytes()).is_err(),
            "the old master password no longer applies"
        );
        let private =
            super::open_private(&material.master, NEW.as_bytes()).expect("the new one applies");
        assert_eq!(private.as_ref(), pair.private.as_ref());

        let old_labels: Vec<String> = codes
            .iter()
            .map(|code| crypto::recovery_label(code))
            .collect();
        let new_labels: Vec<String> = material
            .recovery_keys
            .iter()
            .map(|row| row.label.clone())
            .collect();
        assert_eq!(new_labels.len(), new_codes.len());
        assert!(
            !new_labels.iter().any(|label| old_labels.contains(label)),
            "the old set is completely replaced"
        );
    });
}

/// A second `POST /api/keys/me` would not be a fresh start but a loss: every
/// project key of this user is wrapped for the old public key. The server
/// rejects it, and the client says why.
#[test]
#[ignore]
fn the_server_rejects_a_second_key_pair() {
    run(async {
        let mut me = register("twice").await;

        let pair = crypto::new_key_pair().expect("key pair");
        let master = super::wrap_private(&pair.private, MASTER.as_bytes()).expect("wrap");
        let (_codes, rows) = super::new_recovery_set(&pair.private).expect("recovery codes");

        let error = api::create_keys(
            &me.api,
            &mut me.jar,
            crypto::KEY_ALGORITHM,
            &BASE64.encode(pair.public),
            &master,
            &rows,
        )
        .await
        .expect_err("a second time does not work");

        assert_eq!(error.code(), "K-EX");
    });
}

/// Snippets, a startup command and a proxy reach the colleague. As a viewer
/// of the project he may not create snippets — and after he was removed, the server names
/// exactly the project whose key he still knows.
#[test]
#[ignore]
fn snippets_startup_command_proxy_and_stale_keys() {
    run(async {
        let mut anna = register("anna").await;
        let mut bert = register("bert").await;
        let workspace = org::create(&anna.api, &mut anna.jar, "Live Snippets")
            .await
            .expect("create organization")
            .id;
        let mut at_anna = Cached::new(workspace.clone(), "anna".into(), "Live Snippets".into());
        sync_once(&mut anna, &mut at_anna).await;

        let (project, connection, snippet) = (new_id(), new_id(), new_id());
        let mut tree_now = tree(&workspace, &project, &connection, "SECRET");
        tree_now.snippets = vec![crate::storage::Snippet {
            id: snippet.clone(),
            project_id: project.clone(),
            connection_id: None,
            locked: true,
            name: "Space".into(),
            folder: "Maintenance/Linux".into(),
            command: "df -h # {{connection.host}}".into(),
        }];
        if let ConnectionSettings::Ssh(ssh) = &mut tree_now.projects[0].connections[0].settings {
            ssh.startup_snippet = Some(snippet.clone());
            ssh.proxy = Some(crate::proxy::ProxySetting::Custom(crate::proxy::Proxy {
                kind: crate::proxy::ProxyKind::Socks5,
                host: "proxy.intern".into(),
                port: 1080,
            }));
        }
        let ops =
            diff::plan(&mut at_anna, &tree_now, &anna.user_id, Some(&anna.unlocked)).expect("plan");
        at_anna.enqueue(ops);
        sync_once(&mut anna, &mut at_anna).await;

        let invitation = org::invite(
            &anna.api,
            &mut anna.jar,
            &workspace,
            &bert.email,
            Role::Member,
            None,
        )
        .await
        .expect("invite");
        org::accept_invitation(&bert.api, &mut bert.jar, &invitation.id)
            .await
            .expect("accept");
        api::put_shares(
            &anna.api,
            &mut anna.jar,
            &workspace,
            &project,
            &[(None, ShareRole::Viewer)],
        )
        .await
        .expect("share");
        sync_once(&mut anna, &mut at_anna).await;

        let mut at_bert = Cached::new(workspace.clone(), "bert".into(), "Live Snippets".into());
        sync_once(&mut bert, &mut at_bert).await;
        assert_eq!(
            at_bert.snippet_list(),
            tree_now.snippets,
            "the snippet reaches the colleague"
        );
        let (projects, _) = at_bert.tree(Some(&bert.unlocked.private));
        let ConnectionSettings::Ssh(ssh) = &projects[0].connections[0].settings else {
            panic!("an SSH connection");
        };
        assert_eq!(ssh.startup_snippet.as_deref(), Some(snippet.as_str()));
        assert!(
            matches!(&ssh.proxy, Some(crate::proxy::ProxySetting::Custom(p)) if p.host == "proxy.intern")
        );

        // Bert only views the project: the server rejects his snippet.
        let mut at_bert_new = tree_now.clone();
        at_bert_new.snippets.push(crate::storage::Snippet {
            id: new_id(),
            project_id: project.clone(),
            connection_id: None,
            locked: false,
            name: "foreign".into(),
            folder: String::new(),
            command: "rm -rf ~".into(),
        });
        let ops = diff::plan(
            &mut at_bert,
            &at_bert_new,
            &bert.user_id,
            Some(&bert.unlocked),
        )
        .expect("plan");
        at_bert.enqueue(ops);
        let outcome = sync::run(
            &bert.api,
            &mut bert.jar,
            &mut at_bert,
            Some(&bert.unlocked),
            &bert.user_id,
        )
        .await;
        assert!(
            outcome
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("snippet"),
            "{:?}",
            outcome.error
        );

        // Bert is thrown out: the shared project is due, nothing else.
        let member = org::full(&anna.api, &mut anna.jar, &workspace)
            .await
            .expect("members")
            .members
            .into_iter()
            .find(|m| m.user_id == bert.user_id)
            .expect("Bert is a member")
            .id;
        org::remove_member(&anna.api, &mut anna.jar, &workspace, &member)
            .await
            .expect("remove");
        let due = api::stale_keys(&anna.api, &mut anna.jar, &workspace, &bert.user_id)
            .await
            .expect("ask");
        assert_eq!(due, std::slice::from_ref(&project));

        // After renewing, nothing is due anymore.
        super::rotate::rotate(
            &anna.api,
            &mut anna.jar,
            &at_anna,
            &anna.unlocked,
            &anna.user_id,
            &project,
        )
        .await
        .expect("renew");
        let due = api::stale_keys(&anna.api, &mut anna.jar, &workspace, &bert.user_id)
            .await
            .expect("ask");
        assert!(due.is_empty(), "{due:?}");
    });
}
