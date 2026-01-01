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
use configuration::UserConf;
use pgmoneta_mcp::configuration;
use pgmoneta_mcp::security::SecurityUtil;
use rpassword::prompt_password;
use serde_ini;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Parser, Debug)]
#[command(name = "pgmoneta-mcp-admin", about = "Pgmoneta-mcp admin tool")]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// User related operations
    User {
        #[command(subcommand)]
        action: UserAction,
        /// The admin user
        #[arg(short = 'U', long)]
        user: String,
        /// The user configuration file
        #[arg(short = 'f', long)]
        file: String,
    },
    MasterKey,
}

#[derive(Subcommand, Debug)]
enum UserAction {
    /// Add a new user to configuration file, the file will be automatically created if not exist.
    /// If the user exists, new password will be set to the existing user.
    Add {
        /// The admin user password
        #[arg(short = 'P', long)]
        password: String,
    },
}
fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Commands::User {
            action,
            user,
            file,
        } => match action {
            UserAction::Add {password} => User::set_user(&file, &user, &password)?,
        },
        Commands::MasterKey => {
            MasterKey::set_master_key()?;
        }
    }
    Ok(())
}

struct User;
impl User {
    pub fn set_user(file: &str, user: &str, password: &str) -> Result<()> {
        let path = Path::new(file);
        let sutil = SecurityUtil::new();
        let mut conf: UserConf;
        let master_key = sutil.load_master_key().map_err(|e| {
            anyhow!(
                "Unable to load the master key, needed for adding user: {:?}",
                e
            )
        })?;
        let password_str = sutil.encrypt_to_base64_string(password.as_bytes(), &master_key[..])?;

        if !path.exists() || path.is_dir() {
            conf = HashMap::new();
            let mut user_conf: HashMap<String, String> = HashMap::new();
            user_conf.insert(user.to_string(), password_str);
            conf.insert("admins".to_string(), user_conf);
        } else {
            conf = configuration::load_user_configuration(file)?;
            if let Some(user_conf) = conf.get_mut("admins") {
                user_conf.insert(user.to_string(), password_str);
            } else {
                return Err(anyhow!("Unable to find admins in user configuration"));
            }
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let conf_str = serde_ini::to_string(&conf)?;
        fs::write(file, &conf_str)?;

        Ok(())
    }
}

struct MasterKey;

impl MasterKey {
    pub fn set_master_key() -> Result<()> {
        let sutil = SecurityUtil::new();
        let master_key = prompt_password("Please enter your master key").unwrap();
        let m = prompt_password("Please enter your master key again").unwrap();

        if master_key != m {
            return Err(anyhow!("Passwords do not match"));
        }

        sutil.write_master_key(&master_key)
    }
}
