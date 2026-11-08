mod bitwarden;
mod certificates;
mod cloud;
mod edit;
mod export;
mod files;
mod forward;
mod ftp;
mod import;
mod keys;
mod known_hosts;
mod local;
mod local_secrets;
mod locale;
mod mcp;
mod op;
mod paths;
mod proxy;
mod resume;
mod s3;
mod secret;
mod sftp;
mod ssh;
mod ssh_config;
mod storage;
mod tls;
mod transfer;
mod vault;

// Translations from locales/*.yml; a key without a translation falls back to English.
rust_i18n::i18n!("locales", fallback = "en");

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .manage(op::OpState::default())
        .manage(bitwarden::BwState::default())
        .manage(cloud::CloudState::default())
        .manage(local_secrets::LocalVault::default())
        .manage(ssh::SshState::default())
        .manage(ssh::Transports::default())
        .manage(forward::Forwards::default())
        .manage(ssh::HostKeyPrompts::default())
        .manage(sftp::SftpState::default())
        .manage(ftp::FtpState::default())
        .manage(s3::S3State::default())
        // Shared by every protocol: a transfer, an edit and a secret that has
        // to be asked for look the same from the outside whichever one carries
        // them.
        .manage(secret::Cache::default())
        .manage(secret::Prompts::default())
        .manage(transfer::Transfers::default())
        .manage(resume::Partials::default())
        .manage(edit::EditWatchers::default())
        .manage(local::LocalTerminals::default())
        .manage(mcp::Mcp::default())
        .setup(|app| {
            resume::sweep_on_start(app.handle());
            mcp::start_on_launch(app.handle());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            vault::vault_configure,
            vault::vault_vaults,
            vault::vault_items,
            vault::vault_fields,
            vault::vault_resolve,
            bitwarden::bw_unlock,
            bitwarden::bw_lock,
            bitwarden::bw_unlocked,
            ssh::ssh_connect,
            ssh::ssh_probe,
            ssh::ssh_send,
            ssh::ssh_resize,
            ssh::ssh_disconnect,
            ssh::ssh_host_key_answer,
            ssh::session_close,
            sftp::sftp_connect,
            sftp::sftp_disconnect,
            sftp::sftp_list,
            sftp::sftp_mkdir,
            sftp::sftp_create_file,
            sftp::sftp_exists,
            sftp::sftp_space,
            sftp::sftp_rename,
            sftp::sftp_chmod,
            sftp::sftp_remove,
            sftp::sftp_download,
            sftp::sftp_upload,
            sftp::sftp_discard,
            sftp::sftp_edit_open,
            ftp::ftp_connect,
            ftp::ftp_disconnect,
            ftp::ftp_probe,
            ftp::ftp_list,
            ftp::ftp_mkdir,
            ftp::ftp_create_file,
            ftp::ftp_exists,
            ftp::ftp_rename,
            ftp::ftp_chmod,
            ftp::ftp_remove,
            ftp::ftp_download,
            ftp::ftp_upload,
            ftp::ftp_discard,
            ftp::ftp_edit_open,
            s3::s3_connect,
            s3::s3_disconnect,
            s3::s3_probe,
            s3::s3_list,
            s3::s3_mkdir,
            s3::s3_create_file,
            s3::s3_exists,
            s3::s3_rename,
            s3::s3_chmod,
            s3::s3_remove,
            s3::s3_download,
            s3::s3_upload,
            s3::s3_discard,
            s3::s3_edit_open,
            s3::s3_link,
            s3::s3_stale_uploads,
            s3::s3_abort_stale_uploads,
            secret::secret_answer,
            transfer::transfer_cancel,
            edit::edit_close,
            files::local_home,
            files::local_roots,
            files::local_list,
            files::local_stat,
            files::local_exists,
            files::local_mkdir,
            files::local_create_file,
            files::local_remove,
            files::local_rename,
            storage::workspaces_load,
            storage::workspaces_save,
            storage::workspaces_location,
            // Cloud and a custom backend. The same commands for both: the
            // only difference is where the address comes from — see
            // `cloud`.
            cloud::cloud_url,
            cloud::cloud_accounts,
            cloud::cloud_account_image,
            cloud::cloud_workspace_images,
            cloud::cloud_check_sessions,
            cloud::cloud_sign_in,
            cloud::cloud_wirecloud_detect,
            cloud::cloud_wirecloud_sign_in,
            cloud::cloud_wirecloud_link,
            cloud::cloud_wirecloud_cancel,
            cloud::cloud_sign_up,
            cloud::cloud_push_locale,
            locale::set_locale,
            cloud::cloud_sign_out,
            cloud::cloud_forget_account,
            cloud::cloud_request_password_reset,
            cloud::cloud_key_status,
            cloud::cloud_setup_master,
            cloud::cloud_unlock,
            cloud::cloud_recover_master,
            cloud::cloud_change_master,
            cloud::cloud_lock,
            cloud::cloud_unlocked,
            cloud::cloud_available_workspaces,
            cloud::cloud_add_workspace,
            cloud::cloud_create_workspace,
            cloud::cloud_delete_workspace,
            cloud::cloud_hide_workspace,
            cloud::cloud_sync,
            cloud::cloud_members,
            cloud::cloud_invite,
            cloud::cloud_cancel_invitation,
            cloud::cloud_remove_member,
            cloud::cloud_set_member_role,
            cloud::cloud_create_team,
            cloud::cloud_rename_team,
            cloud::cloud_remove_team,
            cloud::cloud_team_members,
            cloud::cloud_add_team_member,
            cloud::cloud_remove_team_member,
            cloud::cloud_shares,
            cloud::cloud_set_shares,
            cloud::cloud_revoke_key,
            cloud::cloud_stale_keys,
            proxy::proxy_default_get,
            proxy::proxy_default_set,
            cloud::cloud_rotate_project_key,
            cloud::cloud_trust_host,
            cloud::cloud_known_hosts,
            cloud::cloud_forget_host,
            cloud::cloud_dismiss_conflicts,
            known_hosts::known_hosts_list,
            known_hosts::known_hosts_forget,
            known_hosts::host_key_fingerprint,
            certificates::certificates_list,
            certificates::certificates_forget,
            cloud::cloud_my_invitations,
            cloud::cloud_send_verification_email,
            cloud::cloud_accept_invitation,
            cloud::cloud_reject_invitation,
            ssh_config::ssh_config_hosts,
            import::import_putty,
            import::import_file,
            keys::key_generate,
            keys::key_import,
            keys::key_describe,
            ssh::ssh_install_key,
            local_secrets::local_vault_status,
            local_secrets::local_vault_retry,
            local_secrets::local_vault_unlock,
            local_secrets::local_vault_setup,
            local_secrets::local_vault_change_password,
            export::workspaces_export,
            export::workspaces_import,
            forward::ssh_forwards_start,
            forward::ssh_forwards_status,
            local::local_shells,
            local::local_custom_shell,
            local::local_open,
            local::local_send,
            local::local_resize,
            local::local_close,
            ssh::ssh_exec,
            mcp::mcp_status,
            mcp::mcp_configure,
            mcp::mcp_token,
            mcp::mcp_renew_token,
            mcp::mcp_answer
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
