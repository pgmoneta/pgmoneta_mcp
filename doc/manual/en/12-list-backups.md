\newpage

# List Backups

**Natural language description**

Show the backups available for a server.

**Example**

```text
List the backups for the primary server in descending order
```

Example Output:

```
Listed the backups for the primary server in descending order, which was completed in about 0 seconds.

### Server Backup Details
*   **Server Name:** primary
*   **Server Version:** 0.22.0
*   **Total Number of Backups:** 10
*   **Major Version:** 18
*   **Minor Version:** 1

### Backup History (Descending Order)

Here is the detailed list of the 10 backups found on the primary server.

| Backup ID | Backup Size | Biggest File Size | Incremental | Parent ID | Keep | Restore Size |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **20260726012935** | 3.78 MB | 3.35 MB | Yes | 20260726012918 | No | 25.37 MB |
| 20260726012918 | 3.78 MB | 3.35 MB | Yes | 20260726011802 | No | 25.37 MB |
| 20260726011802 | 3.77 MB | 232.00 KB | No | - | No | 6.20 MB |
| 20260726011743 | 3.77 MB | 232.00 KB | No | - | No | 6.20 MB |
| 20260726011419 | 3.77 MB | 232.00 KB | No | - | No | 6.20 MB |
| 20260726010308 | 3.77 MB | 232.00 KB | No | - | No | 6.20 MB |
| 20260726005422 | 3.77 MB | 232.00 KB | No | - | No | 6.20 MB |
| 20260726004442 | 3.77 MB | 232.00 KB | No | - | No | 6.20 MB |
| 20260726004007 | 3.77 MB | 232.00 KB | No | - | No | 6.20 MB |
| 20260726003033 | 6.20 MB | 232.00 KB | No | - | No | 6.20 MB |

***

**Common Backup Details:**
*   **Compression:** zstd
*   **Encryption:** aes\_256\_gcm
*   **Valid:** All backups are valid (1).
*   **WAL (Write Ahead Log):** 0 (All backups).

```
