\newpage

# Backup

**Natural language description**

Take a backup of a pgmoneta server.

**Example**

```text
Take a full backup of the primary server
```

Example Output:

```
Successfully created a full backup on **primary**.

### Backup Summary

*   **Server:** primary
*   **Server Version:** 0.22.0
*   **Backup ID:** 20260726043310
*   **Backup Type:** Full (Incremental: No)
*   **Status:** Success

### Operation Details

*   **Operation Status:** True
*   **Overall Success:** True
*   **Time Taken:** Completed in about 2 seconds
*   **Compression:** zstd
*   **Encryption:** aes_256_gcm
*   **Major Version:** 18
*   **Minor Version:** 1
*   **Valid:** 1

### File Information

*   **Backup Size:** 3.77 MB
*   **Restore Size:** 6.20 MB
*   **Biggest File Size:** 232.00 KB
*   **Incremental Parent:** (None)
```

Or 

```
Took an incremental backup of the primary server successfully.

The backup process for the **primary** server, running version **0.22.0**, was completed in about **2.3 seconds**.

### **Backup Details**

*   **Status:** Successful
*   **Backup ID:** **20260726023426**
*   **Type:** Incremental
*   **Incremental Parent ID:** 20260726012935 (This backup was based on this ID)

### **Storage & Recovery Information**

*   **Backup Size:** 3.78 MB
*   **Biggest File Size:** 3.35 MB
*   **Restore Size:** 25.37 MB
*   **Compression:** zstd
*   **Encryption:** aes\_256\_gcm
*   **Server:** primary
*   **Server Version:** 0.22.0
*   **Major Version:** 18
*   **Minor Version:** 1
*   **Valid:** Yes (1)
```
