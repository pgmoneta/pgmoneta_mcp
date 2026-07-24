\newpage

# Annotation

**Natural language description**

Annotate a backup with a comment key.

**Example**

```text
Add the ticket with annotation 'before release' to the latest backup of the primary server
```

Example Output:

```
Annotated the latest primary backup with the annotation 'before release'.

### Annotation Details
*   **Success:** True
*   **Time Taken:** Completed in about 0.02 seconds

### Affected Backup Details
*   **Backup ID:** 20260726023426
*   **Server:** primary
*   **Backup Size:** 3.78 MB
*   **Biggest File Size:** 3.35 MB
*   **Start LSN:** 0x82000028
*   **End LSN:** 0x82000120
*   **Comments:** ticket|before release
*   **Compression:** zstd
*   **Encryption:** aes_256_gcm
*   **Major Version:** 18
*   **Minor Version:** 1
*   **Restore Size:** 25.37 MB
```
