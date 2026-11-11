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
use clap::{Parser, Subcommand};
use pgmoneta_mcp::configuration::{self, UserConf};
use pgmoneta_mcp::security::SecurityUtil;
use rpassword::prompt_password;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

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

            match action {
                UserAction::Add => {
                    let user = args
                        .user
                        .as_ref()
                        .ok_or_else(|| anyhow!("Missing required argument: -U, --user <USER>"))?;
                    let password = User::get_or_generate_password(args.password.as_deref())?;
                    User::add_user(file, user, &password)?;
                }
                UserAction::Del => {
                    let user = args
                        .user
                        .as_ref()
                        .ok_or_else(|| anyhow!("Missing required argument: -U, --user <USER>"))?;
                    User::remove_user(file, user)?;
                }
                UserAction::Edit => {
                    let user = args
                        .user
                        .as_ref()
                        .ok_or_else(|| anyhow!("Missing required argument: -U, --user <USER>"))?;
                    let password = User::get_or_generate_password(args.password.as_deref())?;
                    User::edit_user(file, user, &password)?;
                }
                UserAction::Ls => {
                    User::list_users(file)?;
                }
            }
        }
    }

    Ok(())
}

struct User;
impl User {
    pub fn add_user(file: &str, user: &str, password: &str) -> Result<()> {
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

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let conf_str = serde_ini::to_string(&conf)?;
        fs::write(file, &conf_str)?;

        Self::print_response(AdminResponse {
            command: "user add".to_string(),
            outcome: "success".to_string(),
            users: Some(vec![user.to_string()]),
            generated_password: None,
        });

        Ok(())
    }

    pub fn remove_user(file: &str, user: &str) -> Result<()> {
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
        fs::write(file, &conf_str)?;

        Self::print_response(AdminResponse {
            command: "user del".to_string(),
            outcome: "success".to_string(),
            users: Some(vec![user.to_string()]),
            generated_password: None,
        });

        Ok(())
    }

    pub fn edit_user(file: &str, user: &str, password: &str) -> Result<()> {
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
        fs::write(file, &conf_str)?;

        Self::print_response(AdminResponse {
            command: "user edit".to_string(),
            outcome: "success".to_string(),
            users: Some(vec![user.to_string()]),
            generated_password: None,
        });

        Ok(())
    }

    pub fn list_users(file: &str) -> Result<()> {
        let path = Path::new(file);

        if !path.exists() {
            Self::print_response(AdminResponse {
                command: "user ls".to_string(),
                outcome: "success".to_string(),
                users: Some(vec![]),
                generated_password: None,
            });
            return Ok(());
        }

        let conf = configuration::load_user_configuration(file)?;
        let mut users: Vec<String> = configuration::get_users(&conf)
            .map(|user_conf| user_conf.keys().cloned().collect())
            .unwrap_or_default();
        users.sort_unstable();

        Self::print_response(AdminResponse {
            command: "user ls".to_string(),
            outcome: "success".to_string(),
            users: Some(users),
            generated_password: None,
        });

        Ok(())
    }

    fn get_or_generate_password(password: Option<&str>) -> Result<String> {
        if let Some(pwd) = password {
            return Ok(pwd.to_string());
        }

        let pwd = prompt_password("Password: ")?;
        let verify = prompt_password("Verify password: ")?;

        if pwd != verify {
            return Err(anyhow!("Passwords do not match"));
        }

        Ok(pwd)
    }

    fn print_response(response: AdminResponse) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use pgmoneta_mcp::configuration::UserConf;
    use std::fs;
    use std::path::PathBuf;

    fn get_temp_file(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(name);
        path
    }

    fn ensure_master_key_exists() {
        let sutil = SecurityUtil::new();
        if sutil.load_master_key().is_err() {
            sutil
                .write_master_key("test_master_pass", &[0u8; 16])
                .unwrap();
        }
    }

    #[test]
    fn test_add_edit_remove_user() {
        let temp_file = get_temp_file("pgmoneta_mcp_test_users.conf");
        let temp_file_str = temp_file.to_str().unwrap();

        ensure_master_key_exists();

        // Clean up before test
        if temp_file.exists() {
            fs::remove_file(&temp_file).unwrap();
        }

        // Add a user
        User::add_user(temp_file_str, "test_user", "test_pass").unwrap();

        // Verify user was added
        let content_added = fs::read_to_string(&temp_file).unwrap();
        let users_added: UserConf = serde_ini::from_str(&content_added).unwrap();
        assert!(users_added.contains_key(configuration::DEFAULT_USER_SECTION));
        assert!(users_added[configuration::DEFAULT_USER_SECTION].contains_key("test_user"));
        assert!(!users_added[configuration::DEFAULT_USER_SECTION]["test_user"].is_empty());

        // Edit the user
        User::edit_user(temp_file_str, "test_user", "new_pass").unwrap();

        // Verify user was edited
        let content_edited = fs::read_to_string(&temp_file).unwrap();
        let users_edited: UserConf = serde_ini::from_str(&content_edited).unwrap();
        assert_ne!(
            users_added[configuration::DEFAULT_USER_SECTION]["test_user"],
            users_edited[configuration::DEFAULT_USER_SECTION]["test_user"]
        );

        // Remove the user
        User::remove_user(temp_file_str, "test_user").unwrap();

        // Verify user was removed
        let content_removed = fs::read_to_string(&temp_file).unwrap();
        let users_removed: UserConf = serde_ini::from_str(&content_removed).unwrap();
        assert!(
            !users_removed
                .get(configuration::DEFAULT_USER_SECTION)
                .is_some_and(|a| a.contains_key("test_user"))
        );

        // Clean up after test
        if temp_file.exists() {
            fs::remove_file(&temp_file).unwrap();
        }
    }

    #[test]
    fn test_list_users() {
        let temp_file = get_temp_file("pgmoneta_mcp_test_users_list.conf");
        let temp_file_str = temp_file.to_str().unwrap();

        ensure_master_key_exists();

        // Clean up before test
        if temp_file.exists() {
            fs::remove_file(&temp_file).unwrap();
        }

        User::add_user(temp_file_str, "user1", "pass1").unwrap();
        User::add_user(temp_file_str, "user2", "pass2").unwrap();

        // We can't easily capture stdout here, but we can ensure the function runs without error
        User::list_users(temp_file_str).unwrap();

        // Clean up after test
        if temp_file.exists() {
            fs::remove_file(&temp_file).unwrap();
        }
    }
}
