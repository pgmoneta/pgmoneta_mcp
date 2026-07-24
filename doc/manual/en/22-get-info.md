\newpage

# Get Info

**Natural language description**

Retrieve detailed metadata for a backup.

**Example**

```text
Get detailed information about the latest backup for the primary server
```

Example Output:

```
Retrieved detailed information for the latest backup on the primary server.

### **Backup Summary**

*   **Backup ID:** 20260726023426
*   **Server Name:** primary
*   **Server Version:** 0.22.0
*   **Comments:** ticket|before release
*   **Backup Status:** **Valid**
*   **Compression:** zstd
*   **Encryption:** aes\_256\_gcm
*   **Keep:** No

### **Size and Storage Details**

*   **Backup Size:** 3.78 MB
*   **Restore Size:** 25.37 MB
*   **Biggest File Size:** 3.35 MB
*   **WAL File:** 000000010000000300000082

### **Time and Versioning**

*   **Elapsed Time:** Completed in less than 1 second (0.0 seconds)
*   **Major Version:** 18
*   **Minor Version:** 1
*   **Tablespaces:** 0

### **LSN and Timeline Details**

**Start Details:**
*   **Start LSN:** 0x82000028
*   **Start HiLSN:** 0x3
*   **Start Timeline:** 1

**End Details:**
*   **End LSN:** 0x82000120
*   **End HiLSN:** 0x3
*   **End Timeline:** 1

**Checkpoint Details:**
*   **Checkpoint LoLSN:** 0x82000080
*   **Checkpoint HiLSN:** 0x3
```
