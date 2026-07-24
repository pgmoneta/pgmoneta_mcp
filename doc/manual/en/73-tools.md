\newpage

# Tools

This developer reference collects the pgmoneta MCP tool definitions. The user-facing chapters describe workflows in natural language; this section keeps the direct tool names, arguments, behavior, and JSON-style examples in one place.

**Backup**

**Tool: /backup**

Create a full or incremental backup.

**Arguments**

- `server`: The pgmoneta server name.
- Optional `backup`: Base backup label for incremental backup.

**Behavior**

- Without `backup`, the tool creates a full backup.
- With `backup`, the tool creates an incremental backup based on that backup.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
backup {"server":"primary"}
backup {"server":"primary","backup":"latest"}
backup {"server":"primary","backup":"20260706113507"}
```

**Example Output:**

```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "backup",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260726034914
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:3.2639"
    },
    "Request": {
        "Backup": "",
        "Server": "primary"
    },
    "Response": {
        "Backup": 20260726034915,
        "BackupSize": "6.20 MB",
        "BiggestFileSize": "232.00 KB",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Incremental": false,
        "IncrementalParent": "",
        "MajorVersion": 18,
        "MinorVersion": 1,
        "RestoreSize": "6.20 MB",
        "Server": "primary",
        "ServerVersion": "0.22.0",
        "Valid": 1
    }
}
```

**Restore**

**Tool: /restore**

Restore a backup into a directory. Position defaults to `current` when omitted.

**Arguments**

- `server`: The pgmoneta server name.
- `backup_id`: Backup label or one of `newest`, `latest`, `oldest`.
- `directory`: Target restore directory.
- Optional position controls: `current`, `name`, `xid`, `time`, `lsn`, `inclusive`, `timeline`, `action`, `primary`, `replica`.

**Behavior**

- If no position controls are provided, pgmoneta_mcp uses `current`.
- `name`, `xid`, `time`, `lsn`, and `timeline` are different restore selection modes.
- `action` controls post-restore behavior such as `pause` or `shutdown`.
- `primary` and `replica` describe the resulting cluster role.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
restore {"server":"primary","backup_id":"latest","directory":"/tmp/restore"}
restore {"server":"primary","backup_id":"latest","directory":"/tmp/restore","name":"recovery-label"}
restore {"server":"primary","backup_id":"latest","directory":"/tmp/restore","xid":"734560"}
restore {"server":"primary","backup_id":"latest","directory":"/tmp/restore","time":"2026-07-06 11:30:00"}
restore {"server":"primary","backup_id":"latest","directory":"/tmp/restore","lsn":"0/5000000"}
restore {"server":"primary","backup_id":"latest","directory":"/tmp/restore","timeline":"2","inclusive":"true","action":"shutdown"}
restore {"server":"primary","backup_id":"latest","directory":"/tmp/restore","primary":true}
restore {"server":"primary","backup_id":"latest","directory":"/tmp/restore","replica":true}
```

**Example Output:**

```

{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "restore",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718173829
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:5.7377"
    },
    "Request": {
        "Backup": "latest",
        "Directory": "/tmp/restore",
        "Position": "primary",
        "Server": "primary"
    },
    "Response": {
        "Backup": 20260718173645,
        "BackupSize": "12.44 MB",
        "BiggestFileSize": "5.68 MB",
        "Comments": "",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Incremental": false,
        "IncrementalParent": "",
        "MajorVersion": 18,
        "MinorVersion": 1,
        "RestoreSize": "12.43 MB",
        "Server": "primary",
        "ServerVersion": "0.22.0"
    }
}
```

**List Backups**

**Tool: /list_backups**

List backups with sort control. Default sort is ascending.

**Arguments**

- `server`: The pgmoneta server name.
- Optional `sort`: `asc` or `desc`.

**Behavior**

- If `sort` is omitted, empty, or effectively null, pgmoneta_mcp uses `asc`.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
list_backups {"server":"primary"}
list_backups {"server":"primary","sort":"asc"}
list_backups {"server":"primary","sort":"desc"}
```

**Example Output:**

```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "list-backup",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260726035019
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0149"
    },
    "Request": {
        "Server": "primary",
        "Sort": "asc"
    },
    "Response": {
        "Backups": [
            {
                "Backup": 20260726004007,
                "BackupSize": "6.47 MB",
                "BiggestFileSize": "232.00 KB",
                "Comments": "",
                "Compression": "zstd",
                "Encryption": "aes_256_gcm",
                "Incremental": false,
                "IncrementalParent": "",
                "Keep": false,
                "RestoreSize": "6.20 MB",
                "Server": "primary",
                "Valid": 1,
                "WAL": 0
            },
            {
                "Backup": 20260726004442,
                "BackupSize": "3.77 MB",
                "BiggestFileSize": "232.00 KB",
                "Comments": "",
                "Compression": "zstd",
                "Encryption": "aes_256_gcm",
                "Incremental": false,
                "IncrementalParent": "",
                "Keep": false,
                "RestoreSize": "6.20 MB",
                "Server": "primary",
                "Valid": 1,
                "WAL": 33554432
            },
            {
                "Backup": 20260726005422,
                "BackupSize": "3.77 MB",
                "BiggestFileSize": "232.00 KB",
                "Comments": "",
                "Compression": "zstd",
                "Encryption": "aes_256_gcm",
                "Incremental": false,
                "IncrementalParent": "",
                "Keep": false,
                "RestoreSize": "6.20 MB",
                "Server": "primary",
                "Valid": 1,
                "WAL": 33554432
            },
            {
                "Backup": 20260726010308,
                "BackupSize": "3.77 MB",
                "BiggestFileSize": "232.00 KB",
                "Comments": "",
                "Compression": "zstd",
                "Encryption": "aes_256_gcm",
                "Incremental": false,
                "IncrementalParent": "",
                "Keep": false,
                "RestoreSize": "6.20 MB",                                   
                "Server": "primary",                                        
                "Valid": 1,                                                 
                "WAL": 33554432
            },                                                              
            {
                "Backup": 20260726011419,                                               
                "BackupSize": "3.77 MB",                                    
                "BiggestFileSize": "232.00 KB",
                "Comments": "",                                             
                "Compression": "zstd",
                "Encryption": "aes_256_gcm",                                            
                "Incremental": false,
                "IncrementalParent": "",
                "Keep": false,      
                "RestoreSize": "6.20 MB",                                   
                "Server": "primary",                                        
                "Valid": 1,                                                 
                "WAL": 33554432
            },                                                              
            {
                "Backup": 20260726011802,
                "BackupSize": "3.77 MB",
                "BiggestFileSize": "232.00 KB",
                "Comments": "",
                "Compression": "zstd",
                "Encryption": "aes_256_gcm",
                "Incremental": false,
                "IncrementalParent": "",
                "Keep": true,
                "RestoreSize": "6.20 MB",
                "Server": "primary",
                "Valid": 1,
                "WAL": 33554432
            },
            {
                "Backup": 20260726012918,
                "BackupSize": "3.78 MB",
                "BiggestFileSize": "3.35 MB",
                "Comments": "",
                "Compression": "zstd",
                "Encryption": "aes_256_gcm",
                "Incremental": true,
                "IncrementalParent": 20260726011802,
                "Keep": true,
                "RestoreSize": "25.37 MB",
                "Server": "primary",
                "Valid": 1,
                "WAL": 33554432
            },
            {
                "Backup": 20260726012935,
                "BackupSize": "3.78 MB",
                "BiggestFileSize": "3.35 MB",
                "Comments": "",
                "Compression": "zstd",
                "Encryption": "aes_256_gcm",
                "Incremental": true,
                "IncrementalParent": 20260726012918,
                "Keep": true,
                "RestoreSize": "25.37 MB",
                "Server": "primary",
                "Valid": 1,
                "WAL": 33554432
            },
            {
                "Backup": 20260726023426,
                "BackupSize": "3.78 MB",
                "BiggestFileSize": "3.35 MB",
                "Comments": "ticket|before release",
                "Compression": "zstd",
                "Encryption": "aes_256_gcm",
                "Incremental": true,
                "IncrementalParent": 20260726012935,
                "Keep": true,
                "RestoreSize": "25.37 MB",
                "Server": "primary",
                "Valid": 1,
                "WAL": 33554432
            },
            {
                "Backup": 20260726034915,
                "BackupSize": "6.20 MB",
                "BiggestFileSize": "232.00 KB",
                "Comments": "",
                "Compression": "zstd",
                "Encryption": "aes_256_gcm",
                "Incremental": false,
                "IncrementalParent": "",
                "Keep": false,
                "RestoreSize": "6.20 MB",
                "Server": "primary",
                "Valid": 1,
                "WAL": 33554432
            }
        ],
        "MajorVersion": 18,
        "MinorVersion": 1,
        "NumberOfBackups": 11,
        "Server": "primary",
        "ServerVersion": "0.22.0"
    }
}
```

**Verify**

**Tool: /verify**

Verify backup integrity, with optional output directory.

**Arguments**

- `server`: The pgmoneta server name.
- `backup_id`: Backup label or one of `newest`, `latest`, `oldest`.
- Optional `directory`: Verification target directory, default `/tmp`.

**Behavior**

- If `directory` is omitted, pgmoneta_mcp uses `/tmp`.
- Use an explicit directory when verification artifacts should be kept in a controlled location.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
verify {"server":"primary","backup_id":"latest"}
verify {"server":"primary","backup_id":"latest","directory":"/tmp/verify"}
```

**Example Output:**
```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "verify",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718175831
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:4.7336"
    },
    "Request": {
        "Backup": "latest",
        "Directory": "/tmp",
        "Server": "primary"
    },
    "Response": {
        "Backup": 20260718173645,
        "Files": {
            "All": {},
            "Failed": {}
        },
        "MajorVersion": 18,
        "MinorVersion": 1,
        "Server": "primary",
        "ServerVersion": "0.22.0"
    }
}
```

**Delete**

**Tool: /delete**

Delete a backup. `force` defaults to `false`.

**Arguments**

- `server`: The pgmoneta server name.
- `backup_id`: Backup label or one of `newest`, `latest`, `oldest`.
- Optional `force`: Force deletion, default `false`.

**Behavior**

- If `force` is omitted, pgmoneta_mcp sends `false`.
- Use `force` only when you want to override normal deletion safeguards.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
delete {"server":"primary","backup_id":"oldest"}
delete {"server":"primary","backup_id":"oldest","force":true}
```

**Example Output:** 
```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "delete",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718181152
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0225"
    },
    "Request": {
        "Backup": "oldest",
        "Force": false,
        "Server": "primary"
    },
    "Response": {
        "Backup": 20260718181132,
        "MajorVersion": 18,
        "MinorVersion": 1,
        "Server": "primary",
        "ServerVersion": "0.22.0"
    }
}

```

**Compress**

**Tool: /compress**

Compress a file using configured compression.

**Arguments**

- `file_path`: Path of the file to compress on the pgmoneta host.

**Behavior**

- The compression algorithm comes from the server-side pgmoneta configuration.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
compress {"file_path":"/tmp/base.tar"}
```

**Example Output:**

```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "compress",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718182311
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0005"
    },
    "Request": {
        "SourceFile": "/tmp/base.tar"
    },
    "Response": {
        "DestinationFile": "/tmp/base.tar.zstd",
        "ServerVersion": "0.22.0"
    }
}
```

**Decompress**

**Tool: /decompress**

Decompress a file.

**Arguments**

- `file_path`: Path of the file to decompress on the pgmoneta host.

**Behavior**

- The decompression method follows the file and configured server behavior.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
decompress {"file_path":"/tmp/base.tar.zstd"}
```

**Example Output:**
```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "decompress",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718182652
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0005"
    },
    "Request": {
        "SourceFile": "/tmp/base.tar.zstd"
    },
    "Response": {
        "DestinationFile": "/tmp/base.tar",
        "ServerVersion": "0.22.0"
    }
}

```

**Encrypt**

**Tool: /encrypt**

Encrypt a file.

**Arguments**

- `file_path`: Path of the file to encrypt on the pgmoneta host.

**Behavior**

- Encryption uses the configured pgmoneta encryption settings.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
encrypt {"file_path":"/tmp/base.tar"}
```

**Example Output:**
```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "encrypt",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718182743
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0021"
    },
    "Request": {
        "SourceFile": "/tmp/base.tar"
    },
    "Response": {
        "DestinationFile": "/tmp/base.tar.aes",
        "ServerVersion": "0.22.0"
    }
}
```

**Decrypt**

**Tool: /decrypt**

Decrypt a file.

**Arguments**

- `file_path`: Path of the file to decrypt on the pgmoneta host.

**Behavior**

- Decryption uses the encryption setup configured on the pgmoneta side.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
decrypt {"file_path":"/tmp/base.tar.aes"}
```

**Example Output:**
```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "decrypt",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718182908
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0018"
    },
    "Request": {
        "SourceFile": "/tmp/base.tar.aes"
    },
    "Response": {
        "DestinationFile": "/tmp/base.tar",
        "ServerVersion": "0.22.0"
    }
}
```

**Archive**

**Tool: /archive**

Archive a backup to a directory. Position defaults to `current` when not provided.

**Arguments**

- `server`: The pgmoneta server name.
- `backup_id`: Backup label or one of `newest`, `latest`, `oldest`.
- `directory`: Target archive directory.
- Optional position controls: `current`, `name`, `xid`, `time`, `lsn`, `inclusive`, `timeline`, `action`, `primary`, `replica`.

**Behavior**

- If no position controls are supplied, pgmoneta_mcp uses `current`.
- `action` controls what happens after archive processing, for example `pause`.
- `primary` and `replica` describe the target role.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
archive {"server":"primary","backup_id":"latest","directory":"/tmp/archive"}
archive {"server":"primary","backup_id":"latest","directory":"/tmp/archive","name":"recovery-label"}
archive {"server":"primary","backup_id":"latest","directory":"/tmp/archive","xid":"734560"}
archive {"server":"primary","backup_id":"latest","directory":"/tmp/archive","time":"2026-07-06 11:30:00"}
archive {"server":"primary","backup_id":"latest","directory":"/tmp/archive","lsn":"0/5000000"}
archive {"server":"primary","backup_id":"latest","directory":"/tmp/archive","timeline":"2","inclusive":"true","action":"pause"}
archive {"server":"primary","backup_id":"latest","directory":"/tmp/archive","primary":true}
archive {"server":"primary","backup_id":"latest","directory":"/tmp/archive","replica":true}
```

**Example Output:**
```         
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "archive",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718183231
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:5.1568"
    },
    "Request": {
        "Backup": "latest",
        "Directory": "/tmp/archive",
        "Position": "current",
        "Server": "primary"
    },
    "Response": {
        "Backup": "",
        "FileName": "/tmp/archive/archive-primary-20260718183113.tar.zstd.aes",
        "MajorVersion": 18,
        "MinorVersion": 1,
        "Server": "primary",
        "ServerVersion": "0.22.0"
    }
}
```

**Annotation**

**Tool: /annotate_backup**

Add, update, or remove a backup annotation.

**Arguments**

- `server`: The pgmoneta server name.
- `backup_id`: Backup label or one of `newest`, `latest`, `oldest`.
- `action`: One of `add`, `update`, `remove`.
- `key`: Annotation key.
- `comment`: Required for `add` and `update`; omitted for `remove`.

**Behavior**

- The tool normalizes the action name before execution.
- `add` and `update` fail if `comment` is missing or empty.
- `remove` ignores any comment value.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
annotate_backup {"server":"primary","backup_id":"latest","action":"add","key":"ticket","comment":"before release"}
annotate_backup {"server":"primary","backup_id":"latest","action":"update","key":"ticket","comment":"after validation"}
annotate_backup {"server":"primary","backup_id":"latest","action":"remove","key":"ticket"}
```

**Example Output:**
```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "annotate",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718183906
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0118"
    },
    "Request": {
        "Action": "add",
        "Backup": "latest",
        "Comment": "before release",
        "Key": "ticket",
        "Server": "primary"
    },
    "Response": {
        "Backup": 20260718183113,
        "BackupSize": "12.44 MB",
        "BiggestFileSize": "5.68 MB",
        "CheckpointHiLSN": "0x3",
        "CheckpointLoLSN": "0x50000080",
        "Comments": "ticket|before release",
        "Compression": "zstd",
        "Elapsed": 0.0,
        "Encryption": "aes_256_gcm",
        "EndHiLSN": "0x3",
        "EndLoLSN": "0x50000120",
        "EndTimeline": 1,
        "Keep": false,
        "MajorVersion": 18,
        "MinorVersion": 1,
        "NumberOfTablespaces": 0,
        "RestoreSize": "12.43 MB",
        "Server": "primary",
        "ServerVersion": "0.22.0",
        "StartHiLSN": "0x3",
        "StartLoLSN": "0x50000028",
        "StartTimeline": 1,
        "Tablespaces": {},
        "Valid": 1,
        "WAL": "000000010000000300000050"
    }
}
```

**Get Info**

**Tool: /get_info**

Retrieve detailed backup metadata.

**Arguments**

- `server`: The pgmoneta server name.
- `backup_id`: Backup label or one of `newest`, `latest`, `oldest`.

**Behavior**

- Returns translated fields such as human-readable sizes and decoded compression and encryption names.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
get_info {"server":"primary","backup_id":"latest"}
get_info {"server":"primary","backup_id":"oldest"}
get_info {"server":"primary","backup_id":"20260706113507"}
```

**Example Output:**
```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "info",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718184036
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0068"
    },
    "Request": {
        "Backup": "latest",
        "Server": "primary"
    },
    "Response": {
        "Backup": 20260718183113,
        "BackupSize": "12.44 MB",
        "BiggestFileSize": "5.68 MB",
        "CheckpointHiLSN": "0x3",
        "CheckpointLoLSN": "0x50000080",
        "Comments": "ticket|before release",
        "Compression": "zstd",
        "Elapsed": 0.0,
        "Encryption": "aes_256_gcm",
        "EndHiLSN": "0x3",
        "EndLoLSN": "0x50000120",
        "EndTimeline": 1,
        "Keep": false,
        "MajorVersion": 18,
        "MinorVersion": 1,
        "NumberOfTablespaces": 0,
        "RestoreSize": "12.43 MB",
        "Server": "primary",
        "ServerVersion": "0.22.0",
        "StartHiLSN": "0x3",
        "StartLoLSN": "0x50000028",
        "StartTimeline": 1,
        "Tablespaces": {},
        "Valid": 1,
        "WAL": "000000010000000300000050"
    }
}
```

**Retain**

**Tool: /retain**

Mark a backup as retained (protected).

**Arguments**

- `server`: The pgmoneta server name.
- `backup_id`: Backup label or one of `newest`, `latest`, `oldest`.
- Optional `cascade`: Whether dependent backups should also be retained.

**Behavior**

- If `cascade` is omitted, it defaults to `false`.
- `cascade=true` retains dependent backups as well.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
retain {"server":"primary","backup_id":"latest","cascade":false}
retain {"server":"primary","backup_id":"latest","cascade":true}
retain {"server":"primary","backup_id":"latest"}
```

**Example Output:**
```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "retain",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718184231
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0116"
    },
    "Request": {
        "Backup": "latest",
        "Cascade": true,
        "Server": "primary"
    },
    "Response": {
        "Backups": [
            20260718183113
        ],
        "Cascade": true,
        "Comments": "ticket|before release",
        "Keep": true,
        "MajorVersion": 18,
        "MinorVersion": 1,
        "Server": "primary",
        "ServerVersion": "0.22.0",
        "Valid": 1
    }
}
```

**Expunge**

**Tool: /expunge**

Remove retention protection from a backup.

**Arguments**

- `server`: The pgmoneta server name.
- `backup_id`: Backup label or one of `newest`, `latest`, `oldest`.
- Optional `cascade`: Whether dependent backups should also be expunged.

**Behavior**

- If `cascade` is omitted, it defaults to `false`.
- `cascade=true` applies expunge to dependent backups as well.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
expunge {"server":"primary","backup_id":"latest","cascade":false}
expunge {"server":"primary","backup_id":"latest","cascade":true}
expunge {"server":"primary","backup_id":"latest"}
```

**Example Output:**
```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "expunge",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718184752
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0119"
    },
    "Request": {
        "Backup": "latest",
        "Cascade": false,
        "Server": "primary"
    },
    "Response": {
        "Backups": [
            20260718183113
        ],
        "Cascade": false,
        "Comments": "ticket|before release",
        "Keep": false,
        "MajorVersion": 18,
        "MinorVersion": 1,
        "Server": "primary",
        "ServerVersion": "0.22.0",
        "Valid": 1
    }
}
```

**Ping**

**Tool: /ping**

Check server reachability.

**Arguments**

- No tool-specific arguments beyond `username`.

**Behavior**

- Use this as the simplest health check before backup or restore operations.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
ping {}
```

**Example Output:**

```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "ping",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718185013
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0000"
    },
    "Request": "",
    "Response": {
        "ServerVersion": "0.22.0"
    }
}
```

**Status**

**Tool: /status**
Get status in compact or detailed view.

**Arguments**

- `in_details`: `false` for summary output, `true` for detailed output.

**Behavior**

- Summary mode returns high-level information such as version and storage totals.
- Detailed mode adds operational data such as backup sizes, WAL, retention, hot standby size, and workers.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
status {"in_details":false}
status {"in_details":true}
```

**Example Output:**
```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "status details",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718185112
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0114"
    },
    "Request": {},
    "Response": {
        "FreeSpace": "15.63 GB",
        "NumberOfServers": 1,
        "PgmonetaFips": false,
        "ServerVersion": "0.22.0",
        "Servers": [
            {
                "ActiveArchive": false,
                "ActiveBackup": false,
                "ActiveDelete": false,
                "ActiveRestore": false,
                "ActiveRetention": false,
                "Backups": [
                    {
                        "Backup": 20260718183113,
                        "BackupSize": 13045760,
                        "BiggestFileSize": 5959680,
                        "Comments": "ticket|before release",
                        "Compression": 18,
                        "Delta": 0,
                        "Encryption": 1,
                        "Keep": false,
                        "RestoreSize": 13037568,
                        "Valid": 1,
                        "WAL": 33554432
                    }
                ],
                "Checksums": true,
                "Fips": false,
                "HotStandbySize": 0,
                "NumberOfBackups": 1,
                "Online": true,
                "Primary": true,
                "RetentionDays": 7,
                "RetentionMonths": -1,
                "RetentionWeeks": -1,
                "RetentionYears": -1,
                "Server": "primary",
                "ServerSize": 30121984,
                "Workers": 0,
                "WorkspaceFreeSpace": 0
            }
        ],
        "TotalSpace": "179.01 GB",
        "UsedSpace": "28.73 MB",
        "Workers": 0
    }
}
```

**Set Mode**

**Tool: /set_mode**

Set server mode.

**Arguments**

- `server`: The pgmoneta server name.
- `action`: Must be `online` or `offline`.

**Behavior**

- This switches the pgmoneta server mode for the named server.
- Invalid action names are rejected by pgmoneta.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
set_mode {"server":"primary","action":"online"}
set_mode {"server":"primary","action":"offline"}
```

**Example Output:**
```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "mode",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718185343
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0000"
    },
    "Request": {
        "Action": "offline",
        "Server": "primary"
    },
    "Response": {
        "MajorVersion": 18,
        "MinorVersion": 1,
        "Online": false,
        "Server": "primary",
        "ServerVersion": "0.22.0"
    }
}
```

**Shutdown**

**Tool: /shutdown**

Shutdown pgmoneta.

**Arguments**

- No tool-specific arguments beyond `username`.

**Behavior**

- Use this carefully, because subsequent backup-related operations fail until pgmoneta is started again.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
shutdown {}
```

**Conf - List**

**Tool: /conf_ls**

List available configuration entries.

**Arguments**

- No tool-specific arguments beyond `username`.

**Behavior**

- Use this when you want an overview of configuration entries before calling `conf_get` or `conf_set`.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
conf_ls {}
```

**Example Output:**
```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "conf ls",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718185510
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0001"
    },
    "Request": {},
    "Response": {
        "ServerVersion": "0.22.0",
        "admin_configuration_path": "pgmoneta_users.conf",
        "main_configuration_path": "pgmoneta.conf",
        "users_configuration_path": "pgmoneta_users.conf"
    }
}
```

**Conf - Set**

**Tool: /conf_set**

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

**Example Output:**
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

**Conf - Get**

**Tool: /conf_get**

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

**Example Output:**
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

**Conf - Reload**

**Tool: /conf_reload**

Reload configuration from server files.

**Arguments**

- No tool-specific arguments beyond `username`.

**Behavior**

- Reloads the active pgmoneta configuration without changing tool input.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
conf_reload {}
```

**Example Output:**
```

{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "conf reload",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718190236
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0521"
    },
    "Request": {},
    "Response": {
        "Restart": false,
        "ServerVersion": "0.22.0"
    }
}
```

**Get Metrics**

**Tool: /get_metrics**

Return all metrics.

**Arguments**

- No tool-specific arguments beyond `username`.

**Behavior**

- Returns the full Prometheus exposition from the configured pgmoneta metrics endpoint.
- Use `metric` instead when you only want one metric name or one filtered sample.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
get_metrics {}
```

**Metric**

**Tool: /metric**

Return one metric by name, optionally filtered by labels.

**Arguments**

- `name`: Prometheus metric name.
- Optional `attributes`: Exact label filters.
- Optional `labels`: Alias for `attributes`.

**Behavior**

- Use either `attributes` or `labels`, not both.
- Filter values may be strings, numbers, or booleans.
- If one sample matches, the tool returns that sample line.
- If multiple samples match, the tool returns all matching lines.
- If no metric name matches, the tool fails.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
metric {"name":"pgmoneta_version"}
metric {"name":"pgmoneta_retention_server","attributes":{"server":"primary"}}
metric {"name":"pgmoneta_retention_server","labels":{"server":"primary"}}
```

**Clear**

**Tool: /clear**

Clear Prometheus-related statistics.

**Arguments**

- No tool-specific arguments beyond `username`.

**Behavior**

- This tool resets the pgmoneta statistics exposed through the metrics endpoint.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
clear {}
```

**Example Output:**
```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "clear prometheus",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718174927
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0000"
    },
    "Request": {}
}
```

