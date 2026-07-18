## Set

**Natural language description**

Update a single runtime configuration value.

**Example**

```text
Set pgmoneta log_level to debug
```

Example Output:
```                                                                                     
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "conf set",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718185603
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0484"
    },
    "Request": {
        "ConfigKey": "log_level",
        "ConfigValue": "debug"
    },
    "Response": {
        "ServerVersion": "0.22.0",
        "config_key": "log_level",
        "message": "Configuration change applied successfully",
        "new_value": 2,
        "old_value": 2,
        "restart_required": false,
        "status": "success"
    }
}
```

## Tool: /conf_set

**Tool description**

Set a single configuration key/value.

**Arguments**

- `config_key`: Name of the configuration entry to update.
- `config_value`: New value to assign.

**Behavior**

- This updates one configuration value per call.
- A common workflow is `conf_ls` -> `conf_get` -> `conf_set` -> `conf_reload`.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
conf_set {"config_key":"retention_days","config_value":"7"}
conf_set {"config_key":"log_level","config_value":"debug"}
```

