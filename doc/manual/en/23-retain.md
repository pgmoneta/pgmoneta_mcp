\newpage

# Retain

**Natural language description**

Protect a backup from retention cleanup.

**Example**

```text
Retain the latest backup for the primary server and include dependent backups
```

Example Output:

```
Retained the latest backup for the primary server and included all dependent backups.

### Retention Details

*   **Success**: True
*   **Execution Time**: Completed in about 0 seconds
*   **Server**: primary
*   **Server Version**: 0.22.0
*   **Major Version**: 18
*   **Minor Version**: 1
*   **Cascade Retention**: True (Dependent backups were included for retention)
*   **Comments**: ticket|before release

### Backups Retained

The following backup IDs were retained:
*   20260726023426
*   20260726012935
*   20260726012918
*   20260726011802
```
