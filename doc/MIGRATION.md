# Migration

## From 0.1.x to 0.2.x

### Two-Step Vault Encryption

The key derivation for vault file encryption has been upgraded to a **two-step PBKDF2-HMAC-SHA256** process:

1.  **Master Derivation**: Master Password + Master Salt -> Derived Master Key (600,000 iterations).
2.  **File Derivation**: Derived Master Key + File Salt -> Final Encryption Key (1 iteration).

This is a **breaking change**. The `master.key` file now requires a specific **two-line format**:

1.  **Line 1**: Base64-encoded master password.
2.  **Line 2**: Base64-encoded master salt (16 bytes).

**Action required:**

1. Stop pgmoneta-mcp
2. Delete the existing admin configuration file:
   - `pgmoneta_admins.conf` (or the file specified with `-f`)
3. Delete the existing master key:
   - On Linux/Unix: `rm ~/.pgmoneta-mcp/master.key`
4. Copy the pgmoneta master key into the MCP home directory (this file must use the new two-line format):
   ```
   mkdir -p ~/.pgmoneta-mcp
   cp ~/.pgmoneta/master.key ~/.pgmoneta-mcp/master.key
   chmod 600 ~/.pgmoneta-mcp/master.key
   ```
5. Re-add all users/admins:
   ```
   pgmoneta-mcp-admin user add -U <username> -P <password> -f <admins_file>
   ```
6. Restart pgmoneta-mcp

### AES-GCM Upgrade

The encryption system has been upgraded to exclusively use **AES-GCM** (Galois/Counter Mode). Support for legacy CBC and CTR modes has been removed.

**Changes:**
1.  **Strict Enforcement**: Legacy identifiers (`aes_256_cbc`, etc.) are no longer supported.
2.  **Unified Protocol**: All encrypted communication now strictly follows the AES-GCM bundle format.
3.  **Expanded Bit-Length**: Native support for 128, 192, and 256-bit GCM.

**Action Required:**
- Update `pgmoneta-mcp.conf` and set the `encryption` field to one of:
  - `aes_256_gcm` (Recommended)
  - `aes_192_gcm`
  - `aes_128_gcm`
  - `none`

> [!WARNING]
> This is a breaking change. If your configuration continues to use legacy identifiers (`aes_256_cbc`, etc.), the MCP server will now return an explicit error and fail to connect. You MUST update your configuration to a supported GCM mode.
