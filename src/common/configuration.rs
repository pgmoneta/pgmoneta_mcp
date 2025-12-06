// Copyright (C) 2025 The pgmoneta community
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list
// of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this
// list of conditions and the following disclaimer in the documentation and/or other
// materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may
// be used to endorse or promote products derived from this software without specific
// prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
// OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
// TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use anyhow::anyhow;
use std::collections::HashMap;
use config::Config;
use serde::Deserialize;
use once_cell::sync::OnceCell;

pub static CONFIG: OnceCell<Configuration> = OnceCell::new();


#[derive(Clone, Debug, Deserialize)]
pub struct Configuration {
    pub pgmoneta: Pgmoneta,
    #[serde(default = "default_port")]
    pub port: i32,
    pub admins: HashMap<String, String> //username -> password
}

#[derive(Clone, Debug, Deserialize)]
pub struct Pgmoneta {
    pub host: String,
    pub port: i32
}

pub fn load_configuration(config_path: &str, user_path: &str) -> anyhow::Result<Configuration> {
    let conf = Config::builder()
        .add_source(config::File::with_name(config_path))
        .add_source(config::File::with_name(user_path))
        .build()?;
    conf.try_deserialize::<Configuration>().map_err(|e| {
        anyhow!("Error deserializing configuration at path {}, user {}: {:?}", config_path, user_path, e)
    })
}

fn default_port() -> i32 {
    8000
}