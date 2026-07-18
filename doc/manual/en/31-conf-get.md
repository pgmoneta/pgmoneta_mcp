## Get

**Natural language description**

Read full runtime configuration.

**Example**

```text
Show the full pgmoneta runtime configuration
```

Example Output:
```
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  
{                                                                                                                                                                                     
    "Header": {                                                                                                                                        
        "ClientVersion": "0.21.0",
        "Command": "conf get",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718185806
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0013"
    },
    "Request": {},
    "Response": {
        "ServerVersion": "0.22.0",
        "admin_configuration_path": "pgmoneta_users.conf",
        "azure_base_dir": "",
        "azure_container": "",
        "azure_shared_key": "",
        "azure_storage_account": "",
        "backlog": 16,
        "base_dir": "~/pgmoneta/backup",
        "blocking_timeout": {
            "string_value": "30s",
            "value": 30
        },
        "compression": {
            "string_value": "zstd",
            "value": 18
        },
        "compression_level": 3,
        "console": 0,
        "create_slot": {
            "string_value": "undefined",
            "value": 0
        },
        "direct_io": {
            "string_value": "off",
            "value": 0
        },                                                      
        "encryption": {                                                                                                          
            "string_value": "aes-256-gcm",                      
            "value": 1                                                                                             
        },                                                      
        "host": "*",                                            
        "hugepage": {                                                      
            "string_value": "try",                                         
            "value": 1                                                     
        },                                                                 
        "keep_alive": true,                                                
        "libev": "",                                                       
        "log_level": {                                                     
            "string_value": "debug",                                       
            "value": 2                             
        },                 
        "log_line_prefix": "%Y-%m-%d %H:%M:%S",    
        "log_mode": {      
            "string_value": "append",
            "value": 1        
        },                        
        "log_path": "/home/ahmed-kamal/pgmoneta/pgmoneta.log",                                                                                           
        "log_rotation_age": {     
            "string_value": "0s",
            "value": 0             
        },                       
        "log_rotation_size": {                                              
            "string_value": "0B",                                           
            "value": 0                                                      
        },                                                                  
        "log_type": {                                                       
            "string_value": "file",                                         
            "value": 1
        },                                                                  
        "main_configuration_path": "pgmoneta.conf",
        "management": 5002,
        "manifest": "SHA512",
        "max_rate": 0,
        "metrics": 5001,
        "metrics_ca_file": "",
        "metrics_cache_max_age": {                                                                                                                       
            "string_value": "0s",                                                                                                                        
            "value": 0
        },
        "metrics_cache_max_size": {                                                                                                                      
            "string_value": "0B",                                                                                                                        
            "value": 0
        },
        "metrics_cert_file": "",
        "metrics_key_file": "",
        "nodelay": true,
        "non_blocking": true,
        "pidfile": "/tmp/pgmoneta.all.pid",
        "progress": false,
        "retention": "7,-,-,-",
        "s3_access_key_id": "",
        "s3_base_dir": "",
        "s3_bucket": "",
        "s3_endpoint": "",
        "s3_port": 0,                                      
        "s3_region": "",
        "s3_secret_access_key": "",
        "s3_storage_class": "",
        "s3_use_tls": 0,
        "server": {
            "primary": {
                "create_slot": 0,
                "extra": "",
                "follow": "",
                "host": "localhost",
                "hot_standby": "",
                "hot_standby_overrides": "",
                "hot_standby_tablespaces": "",
                "manifest": "SHA512",
                "max_rate": -1,
                "online": false,
                "port": 5432,
                "progress": true,
                "retention": "-,-,-,-",
                "tls_ca_file": "",
                "tls_cert_file": "",
                "tls_key_file": "",
                "user": "repl",
                "wal_shipping": "",
                "wal_slot": "repl",
                "workers": -1,
                "workspace": ""
            }
        },
        "ssh_base_dir": "",
        "ssh_ciphers": "",
        "ssh_hostname": "",
        "ssh_private_key_file": "",
        "ssh_public_key_file": "",
        "ssh_username": "",
        "storage_engine": {
            "string_value": "local",
            "value": 1
        },
        "tls": false,
        "tls_ca_file": "",
        "tls_cert_file": "",
        "tls_key_file": "",
        "unix_socket_dir": "/tmp/",
        "update_process_title": {
            "string_value": "verbose",
            "value": 3
        },
        "users_configuration_path": "pgmoneta_users.conf",
        "verification": {
            "string_value": "0s",
            "value": 0
        },
        "workers": 0,
        "workspace": ""
    }
}
```

## Tool: /conf_get

**Tool description**

Read full runtime configuration.

**Arguments**

- No tool-specific arguments beyond `username`.

**Behavior**

- Returns detailed configuration content rather than only configuration keys.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
conf_get {}
```

