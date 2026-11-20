// Copyright (C) 2026 The pgmoneta community
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use pgmoneta_mcp::configuration::{self, UserConf};
use pgmoneta_mcp::security::SecurityUtil;
use rpassword::prompt_password;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const DEFAULT_PASSWORD_LENGTH: usize = 64;
const MIN_PASSWORD_LENGTH: usize = 8;
const MAX_PASSWORD_LENGTH: usize = 1024;
const PASSWORD_CHARSET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+";

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Parser, Debug)]
#[command(
    name = "pgmoneta-mcp-admin",
    about = "Administration utility for pgmoneta-mcp",
    version
)]
struct Args {
    /// The user configuration file
    #[arg(short = 'f', long)]
    file: Option<String>,

    /// The user name
    #[arg(short = 'U', long)]
    user: Option<String>,

    /// The password for the user
    #[arg(short = 'P', long)]
    password: Option<String>,

    /// Generate a password
    #[arg(short = 'g', long, conflicts_with = "password")]
    generate: bool,

    /// Password length
    #[arg(short = 'l', long, default_value_t = DEFAULT_PASSWORD_LENGTH)]
    length: usize,

    /// Output format
    #[arg(short = 'F', long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Manage a specific user
    User {
        #[command(subcommand)]
        action: UserAction,
    },
}

#[derive(Subcommand, Debug)]
enum UserAction {
    /// Add a new user to configuration file
    Add,
    /// Remove an existing user
    Del,
    /// Change the password for an existing user
    Edit,
    /// List all available users
    Ls,
}

#[derive(Debug, Serialize, Deserialize)]
struct AdminResponse {
    command: String,
    outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    users: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generated_password: Option<String>,
}
fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Commands::User { action } => {
            let file = args
                .file
                .as_ref()
                .ok_or_else(|| anyhow!("Missing required argument: -f, --file <FILE>"))?;

            let response =
                match action {
                    UserAction::Add => {
                        let user = args.user.as_ref().ok_or_else(|| {
                            anyhow!("Missing required argument: -U, --user <USER>")
                        })?;
                        let (password, generated) = User::get_or_generate_password(
                            args.password.as_deref(),
                            args.generate,
                            args.length,
                        )?;
                        let mut response = User::add_user(file, user, &password)?;
                        response.generated_password = generated;
                        response
                    }
                    UserAction::Del => {
                        let user = args.user.as_ref().ok_or_else(|| {
                            anyhow!("Missing required argument: -U, --user <USER>")
                        })?;
                        User::remove_user(file, user)?
                    }
                    UserAction::Edit => {
                        let user = args.user.as_ref().ok_or_else(|| {
                            anyhow!("Missing required argument: -U, --user <USER>")
                        })?;
                        let (password, generated) = User::get_or_generate_password(
                            args.password.as_deref(),
                            args.generate,
                            args.length,
                        )?;
                        let mut response = User::edit_user(file, user, &password)?;
                        response.generated_password = generated;
                        response
                    }
                    UserAction::Ls => User::list_users(file)?,
                };

            User::print_response(&response, args.format)?;
        }
    }

    Ok(())
}

struct User;
impl User {
    pub fn add_user(file: &str, user: &str, password: &str) -> Result<AdminResponse> {
        let path = Path::new(file);
        let sutil = SecurityUtil::new();
        let mut conf: UserConf;
        let (master_password, master_salt) = sutil.load_master_key().map_err(|e| {
            anyhow!(
                "Unable to load the master key, needed for adding user: {:?}",
                e
            )
        })?;
        let password_str =
            sutil.encrypt_to_base64_string(password.as_bytes(), &master_password, &master_salt)?;

        if !path.exists() || path.is_dir() {
            conf = HashMap::new();
            let mut user_conf: HashMap<String, String> = HashMap::new();
            user_conf.insert(user.to_string(), password_str);
            conf.insert(configuration::DEFAULT_USER_SECTION.to_string(), user_conf);
        } else {
            conf = configuration::load_user_configuration(file)?;
            let section = configuration::get_user_section_name(&conf)
                .unwrap_or(configuration::DEFAULT_USER_SECTION)
                .to_string();
            let user_conf = conf.entry(section).or_default();
            if user_conf.contains_key(user) {
                return Err(anyhow!("User '{}' already exists", user));
            }
            user_conf.insert(user.to_string(), password_str);
        }

        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }

        let conf_str = serde_ini::to_string(&conf)?;
        Self::write_user_configuration(file, &conf_str)?;

        Ok(AdminResponse {
            command: "user add".to_string(),
            outcome: "success".to_string(),
            users: Some(vec![user.to_string()]),
            generated_password: None,
        })
    }

    pub fn remove_user(file: &str, user: &str) -> Result<AdminResponse> {
        let path = Path::new(file);

        if !path.exists() {
            return Err(anyhow!("User file '{}' does not exist", file));
        }

        let mut conf = configuration::load_user_configuration(file)?;

        if let Some(user_conf) = configuration::get_users_mut(&mut conf) {
            if user_conf.remove(user).is_none() {
                return Err(anyhow!("User '{}' not found", user));
            }
        } else {
            return Err(anyhow!(
                "Unable to find users section in user configuration"
            ));
        }

        let conf_str = serde_ini::to_string(&conf)?;
        Self::write_user_configuration(file, &conf_str)?;

        Ok(AdminResponse {
            command: "user del".to_string(),
            outcome: "success".to_string(),
            users: Some(vec![user.to_string()]),
            generated_password: None,
        })
    }

    pub fn edit_user(file: &str, user: &str, password: &str) -> Result<AdminResponse> {
        let path = Path::new(file);
        let sutil = SecurityUtil::new();

        if !path.exists() {
            return Err(anyhow!("User file '{}' does not exist", file));
        }

        let (master_password, master_salt) = sutil.load_master_key().map_err(|e| {
            anyhow!(
                "Unable to load the master key, needed for editing user: {:?}",
                e
            )
        })?;

        let password_str =
            sutil.encrypt_to_base64_string(password.as_bytes(), &master_password, &master_salt)?;

        let mut conf = configuration::load_user_configuration(file)?;

        if let Some(user_conf) = configuration::get_users_mut(&mut conf) {
            if user_conf.get(user).is_none() {
                return Err(anyhow!("User '{}' not found", user));
            }
            user_conf.insert(user.to_string(), password_str);
        } else {
            return Err(anyhow!(
                "Unable to find users section in user configuration"
            ));
        }

        let conf_str = serde_ini::to_string(&conf)?;
        Self::write_user_configuration(file, &conf_str)?;

        Ok(AdminResponse {
            command: "user edit".to_string(),
            outcome: "success".to_string(),
            users: Some(vec![user.to_string()]),
            generated_password: None,
        })
    }

    pub fn list_users(file: &str) -> Result<AdminResponse> {
        let path = Path::new(file);

        if !path.exists() {
            return Ok(AdminResponse {
                command: "user ls".to_string(),
                outcome: "success".to_string(),
                users: Some(vec![]),
                generated_password: None,
            });
        }

        let conf = configuration::load_user_configuration(file)?;
        let mut users: Vec<String> = configuration::get_users(&conf)
            .map(|user_conf| user_conf.keys().cloned().collect())
            .unwrap_or_default();
        users.sort_unstable();

        Ok(AdminResponse {
            command: "user ls".to_string(),
            outcome: "success".to_string(),
            users: Some(users),
            generated_password: None,
        })
    }

    fn write_user_configuration(file: &str, content: &str) -> Result<()> {
        let path = Path::new(file);

        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }

        #[cfg(unix)]
        {
            use std::io::{Seek, Write};
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

            let mut file_handle = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(path)?;

            file_handle.set_permissions(fs::Permissions::from_mode(0o600))?;
            file_handle.set_len(0)?;
            file_handle.rewind()?;
            file_handle.write_all(content.as_bytes())?;
            file_handle.flush()?;
            Ok(())
        }

        #[cfg(not(unix))]
        {
            fs::write(path, content)?;
            Ok(())
        }
    }

    fn generate_password(length: usize) -> Result<String> {
        if !(MIN_PASSWORD_LENGTH..=MAX_PASSWORD_LENGTH).contains(&length) {
            return Err(anyhow!(
                "Password length must be between {} and {}",
                MIN_PASSWORD_LENGTH,
                MAX_PASSWORD_LENGTH
            ));
        }
        Ok((0..length)
            .map(|_| PASSWORD_CHARSET[rand::random_range(0..PASSWORD_CHARSET.len())] as char)
            .collect())
    }

    fn get_or_generate_password(
        password: Option<&str>,
        generate: bool,
        length: usize,
    ) -> Result<(String, Option<String>)> {
        if generate {
            let pwd = Self::generate_password(length)?;
            return Ok((pwd.clone(), Some(pwd)));
        }

        if let Some(pwd) = password {
            return Ok((pwd.to_string(), None));
        }

        let pwd = prompt_password("Password: ")?;
        let verify = prompt_password("Verify password: ")?;

        if pwd != verify {
            return Err(anyhow!("Passwords do not match"));
        }

        Ok((pwd, None))
    }

    fn print_response(response: &AdminResponse, format: OutputFormat) -> Result<()> {
        match format {
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(response)?),
            OutputFormat::Text => {
                println!("Command: {}", response.command);
                println!("Outcome: {}", response.outcome);
                if let Some(users) = &response.users
                    && !users.is_empty()
                {
                    println!("Users:");
                    for user in users {
                        println!("  - {}", user);
                    }
                }
                if let Some(pwd) = &response.generated_password {
                    println!("Generated password: {}", pwd);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgmoneta_mcp::configuration::UserConf;
    use std::fs;

    fn ensure_master_key_exists() {
        let sutil = SecurityUtil::new();
        if sutil.load_master_key().is_err() {
            sutil
                .write_master_key("test_master_pass", &[0u8; 16])
                .unwrap();
        }
    }

    #[test]
    fn test_generate_password_length_and_charset() {
        let pwd = User::generate_password(64).unwrap();
        assert_eq!(pwd.len(), 64);
        assert!(pwd.bytes().all(|b| PASSWORD_CHARSET.contains(&b)));
    }

    #[test]
    fn test_generate_password_rejects_invalid_length() {
        assert!(User::generate_password(MIN_PASSWORD_LENGTH - 1).is_err());
        assert!(User::generate_password(MAX_PASSWORD_LENGTH + 1).is_err());
    }

    #[test]
    fn test_get_or_generate_password_generates() {
        let (pwd, generated) = User::get_or_generate_password(None, true, 32).unwrap();
        assert_eq!(pwd.len(), 32);
        assert_eq!(generated.as_deref(), Some(pwd.as_str()));
    }

    #[test]
    fn test_generate_conflicts_with_password() {
        let res = Args::try_parse_from(["pgmoneta-mcp-admin", "-g", "-P", "x", "user", "add"]);
        assert!(res.is_err());
    }

    #[test]
    fn test_add_edit_remove_user() {
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_file = temp_dir.path().join("pgmoneta_mcp_test_users.conf");
        let temp_file_str = temp_file.to_str().unwrap();

        ensure_master_key_exists();

        // Add a user
        User::add_user(temp_file_str, "test_user", "test_pass").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&temp_file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        // Verify user was added
        let content_added = fs::read_to_string(&temp_file).unwrap();
        let users_added: UserConf = serde_ini::from_str(&content_added).unwrap();
        assert!(users_added.contains_key(configuration::DEFAULT_USER_SECTION));
        assert!(users_added[configuration::DEFAULT_USER_SECTION].contains_key("test_user"));
        assert!(!users_added[configuration::DEFAULT_USER_SECTION]["test_user"].is_empty());

        // Edit the user
        User::edit_user(temp_file_str, "test_user", "new_pass").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&temp_file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        // Verify user was edited
        let content_edited = fs::read_to_string(&temp_file).unwrap();
        let users_edited: UserConf = serde_ini::from_str(&content_edited).unwrap();
        assert_ne!(
            users_added[configuration::DEFAULT_USER_SECTION]["test_user"],
            users_edited[configuration::DEFAULT_USER_SECTION]["test_user"]
        );

        // Remove the user
        User::remove_user(temp_file_str, "test_user").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&temp_file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        // Verify user was removed
        let content_removed = fs::read_to_string(&temp_file).unwrap();
        let users_removed: UserConf = serde_ini::from_str(&content_removed).unwrap();
        assert!(
            !users_removed
                .get(configuration::DEFAULT_USER_SECTION)
                .is_some_and(|a| a.contains_key("test_user"))
        );
    }

    #[test]
    fn test_list_users() {
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_file = temp_dir.path().join("pgmoneta_mcp_test_users_list.conf");
        let temp_file_str = temp_file.to_str().unwrap();

        ensure_master_key_exists();

        User::add_user(temp_file_str, "user1", "pass1").unwrap();
        User::add_user(temp_file_str, "user2", "pass2").unwrap();

        // We can't easily capture stdout here, but we can ensure the function runs without error
        User::list_users(temp_file_str).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn test_user_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::tempdir().unwrap();
        let temp_file = temp_dir.path().join("pgmoneta_mcp_test_permissions.conf");
        let temp_file_str = temp_file.to_str().unwrap();

        ensure_master_key_exists();

        // 1. Fresh file creation should have 0o600 mode
        User::add_user(temp_file_str, "perm_user", "perm_pass").unwrap();
        assert_eq!(
            fs::metadata(&temp_file).unwrap().permissions().mode() & 0o777,
            0o600
        );

        // 2. Pre-existing file with relaxed permissions (0o644) should be tightened to 0o600 on edit
        fs::set_permissions(&temp_file, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            fs::metadata(&temp_file).unwrap().permissions().mode() & 0o777,
            0o644
        );
        User::edit_user(temp_file_str, "perm_user", "new_perm_pass").unwrap();
        assert_eq!(
            fs::metadata(&temp_file).unwrap().permissions().mode() & 0o777,
            0o600
        );

        // 3. Deleting a user should also enforce 0o600 permissions even if pre-existing permissions were 0o666
        User::add_user(temp_file_str, "perm_user2", "perm_pass2").unwrap();
        fs::set_permissions(&temp_file, fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            fs::metadata(&temp_file).unwrap().permissions().mode() & 0o777,
            0o666
        );
        User::remove_user(temp_file_str, "perm_user").unwrap();
        assert_eq!(
            fs::metadata(&temp_file).unwrap().permissions().mode() & 0o777,
            0o600
        );

        // 4. Test write_user_configuration directly on pre-existing 0o644 and 0o666 files
        // to verify permissions are restricted through the open file handle before content is rewritten
        let direct_file = temp_dir.path().join("pgmoneta_mcp_direct_permissions.conf");
        let direct_file_str = direct_file.to_str().unwrap();

        // Direct test with 0o644 pre-existing file
        fs::write(&direct_file, "initial_data_644").unwrap();
        fs::set_permissions(&direct_file, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            fs::metadata(&direct_file).unwrap().permissions().mode() & 0o777,
            0o644
        );
        User::write_user_configuration(direct_file_str, "hardened_content_644").unwrap();
        assert_eq!(
            fs::metadata(&direct_file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::read_to_string(&direct_file).unwrap(),
            "hardened_content_644"
        );

        // Direct test with 0o666 pre-existing file
        fs::set_permissions(&direct_file, fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            fs::metadata(&direct_file).unwrap().permissions().mode() & 0o777,
            0o666
        );
        User::write_user_configuration(direct_file_str, "hardened_content_666").unwrap();
        assert_eq!(
            fs::metadata(&direct_file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::read_to_string(&direct_file).unwrap(),
            "hardened_content_666"
        );
    }

    #[test]
    fn test_write_user_configuration_relative_path() {
        struct CleanupFile<'a>(&'a str);
        impl Drop for CleanupFile<'_> {
            fn drop(&mut self) {
                let _ = fs::remove_file(self.0);
            }
        }

        let file = "users.conf";
        let _guard = CleanupFile(file);
        let _ = fs::remove_file(file);

        // 1. Successfully create a relative path file with no directory component
        User::write_user_configuration(file, "initial_relative_content").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        assert_eq!(
            fs::read_to_string(file).unwrap(),
            "initial_relative_content"
        );

        // 2. Successfully update the existing relative path file
        User::write_user_configuration(file, "updated_relative_content").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        assert_eq!(
            fs::read_to_string(file).unwrap(),
            "updated_relative_content"
        );
    }
}
