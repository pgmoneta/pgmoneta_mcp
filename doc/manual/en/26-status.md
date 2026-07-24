\newpage

# Status

**Natural language description**

Get the current pgmoneta status.

**Example**

```text
Show detailed status for pgmoneta
```

Example Output:

```
Successfully retrieved the detailed status for pgmoneta, completing in about 1 second.

### Server Overview

*   **Server Name:** primary
*   **Server Version:** 0.22.0
*   **Server Status:** Online (Primary)
*   **Number of Servers:** 1
*   **Total Storage Capacity:** 179.01 GB
*   **Used Space:** 65.50 MB
*   **Available Free Space:** 11.62 GB
*   **Total Number of Backups:** 11

### Retention and Configuration

*   **Retention Policy:** The policy is set to retain for **7 days** (RetentionDays: 7).
*   **Hot Standby Size:** 0
*   **System Workers:** 0
*   **Checksum Verification:** Enabled (true)
*   **FIPS Mode:** Disabled (false)

### Backup History Details

The server currently has 11 backups recorded. The most recent backup is **20260726034915**.

Below are the details for all stored backups:

| Backup ID | Size | Biggest File | Retention | Comments |
| :--- | :--- | :--- | :--- | :--- |
| 20260726004007 | 6.79 MB | 237.57 KB | No | null |
| 20260726004442 | 3.96 MB | 237.57 KB | No | null |
| 20260726005422 | 3.96 MB | 237.57 KB | No | null |
| 20260726010308 | 3.96 MB | 237.57 KB | No | null |
| 20260726011419 | 3.96 MB | 237.57 KB | No | null |
| 20260726011743 | 3.96 MB | 237.57 KB | No | null |
| 20260726011802 | 3.96 MB | 237.57 KB | Yes | null |
| 20260726012918 | 3.96 MB | 3.51 MB | Yes | null |
| 20260726012935 | 3.96 MB | 3.51 MB | Yes | null |
| 20260726023426 | 3.96 MB | 3.51 MB | Yes | ticket\|before release |
| 20260726034915 | 6.50 MB | 237.57 KB | No | null |

**Key Details Per Backup:**

*   **Backup ID 20260726004007:**
    *   Backup Size: 6787072 bytes
    *   Restore Size: 6496256 bytes
    *   WAL Size: 369098752 bytes
    *   Delta: 0
    *   Encryption: Yes
    *   Keep: False
*   **Backup ID 20260726012918:**
    *   Backup Size: 3964928 bytes
    *   Restore Size: 26601320 bytes
    *   WAL Size: 134217728 bytes
    *   Delta: 33554432
    *   Encryption: Yes
    *   Keep: True
*   **Backup ID 20260726023426:**
    *   Backup Size: 3964928 bytes
    *   Restore Size: 26601320 bytes
    *   WAL Size: 67108864 bytes
    *   Delta: 33554432
    *   Encryption: Yes
    *   Keep: True
*   **Backup ID 20260726034915:**
    *   Backup Size: 6504448 bytes
    *   Restore Size: 6496256 bytes
    *   WAL Size: 33554432 bytes
    *   Delta: 33554432
    *   Encryption: Yes
    *   Keep: False

*(Note: The data provided for Backup Sizes, Restore Sizes, and WAL sizes are listed in bytes.)*
```
