# Architecture Deep Dive: Zend Engine Memory Management & Bailout Mechanics

This document provides a technical analysis of the memory management internals of the PHP Zend Engine, the lifecycle of Server API (SAPI) requests, and the precise conditions that give rise to **CVE-2026-109618** and **CVE-2026-109619**.

---

## 1. Zend Memory Manager (Zend MM) Internals

The Zend Engine implements its own userland memory manager sitting on top of system allocators (`glibc malloc`).

```text
┌─────────────────────────────────────────────────────────────┐
│                    Zend Memory Manager                      │
│                                                             │
│  ┌──────────────────────┐        ┌──────────────────────┐  │
│  │ Small Bins (≤ 3 KB)  │        │ Large Bins (≤ 2 MB)  │  │
│  │ 30 fixed-size bins   │        │ Page-aligned runs    │  │
│  │ Chunk-local pages    │        │ Chunk-local pages    │  │
│  └──────────┬───────────┘        └──────────┬───────────┘  │
│             └────────────────┬──────────────┘              │
│                              ▼                              │
│                 [ 2 MB Aligned Chunks ]                     │
│                              │                              │
│  ┌───────────────────────────┴───────────────────────────┐  │
│  │ Huge Allocations (> 2 MB)                             │  │
│  │ Directly delegated to system mmap() / malloc()        │  │
│  └───────────────────────────────────────────────────────┘  │
└──────────────────────────────┬──────────────────────────────┘
                               ▼
               [ Host glibc / Kernel VMM ]
```

### Allocation Tiers:
1. **Small Allocations (≤ 3072 bytes):** Allocated from 30 fixed-size bins inside 2 MB Zend MM chunks.
2. **Large Allocations (3073 bytes to 2 MB):** Allocated as consecutive page runs from chunk heaps.
3. **Huge Allocations (> 2 MB):** Directly requested via `mmap()` from the underlying operating system.

### Request-Scoped vs Process-Scoped Memory:
* **`emalloc()` / `efree()` (Engine Allocations):** Request-scoped. Every block allocated with `emalloc()` is automatically freed when the HTTP request finishes (`php_request_shutdown()`).
* **`malloc()` / `free()` (Persistent Allocations):** Allocated from the system heap and survives across multiple requests inside the same persistent worker process.

---

## 2. Request Lifecycle: Pre-RINIT vs Post-RINIT

Understanding the timing of these vulnerabilities requires tracing PHP's request lifecycle:

```text
HTTP Request Arrives
       │
       ▼
1. SAPI Pre-RINIT Phase (main.c)
   - Reading raw HTTP input stream.
   - RFC 1867 Multipart Form Parser parses headers & fields (rfc1867.c).
   - Populates $_POST, $_FILES, and session upload progress structures.
   - [!] CVE-2026-109618 OOM occurs HERE.
   - [!] CVE-2026-109619 Stale pointer arming occurs HERE.
       │
       ▼
2. Module Request Initialization (RINIT)
   - zend_activate_modules() runs.
   - Extensions initialize per-request state.
       │
       ▼
3. Script Execution (Application Phase)
   - User PHP scripts (index.php, login.php) execute.
       │
       ▼
4. Module Request Teardown (RSHUTDOWN)
   - php_request_shutdown() runs.
   - [!] CVE-2026-109618 stale bucket dereference occurs HERE.
   - All emalloc() allocations are cleared.
       │
       ▼
5. SAPI Post-RSHUTDOWN Phase
   - Persistent worker process loops and waits for the next request.
   - [!] CVE-2026-109619 cross-request UAF occurs upon Request B arrival.
```

---

## 3. C-Level Breakdown of CVE-2026-109618

### The Allocate-Then-Publish Violation

In `Zend/zend_hash.c`, inserting a new element into a `HashTable` involves allocating memory for the bucket and publishing its index. 

In unpatched PHP:
```c
/* Unpatched implementation */
static zend_always_inline Bucket *zend_hash_add_or_update_i(HashTable *ht, zend_string *key, zval *pData) 
{
    /* 1. INCREMENT COUNTER BEFORE ALLOCATION */
    uint32_t idx = ht->nNumUsed++;
    ht->nNumOfElements++;

    /* 2. ATTEMPT ALLOCATION */
    Bucket *p = ht->arData + idx;
    p->key = key;
    
    /* If this emalloc trips memory_limit, zend_bailout() is called immediately! */
    p->val.value.str = zend_string_copy(key); 
    ...
}
```

### The Bailout Mechanism (`zend_bailout`)
When the memory manager detects that total allocated memory exceeds `memory_limit`:
```c
ZEND_API ZEND_COLD void zend_bailout(void) {
    ...
    longjmp(EG(bailout), 1); /* Non-local jump directly to shutdown handler */
}
```

### The Teardown Vulnerability
During shutdown, `zend_hash_destroy` iterates through `0` to `nNumUsed`:
```c
ZEND_API void ZEND_FASTCALL zend_hash_destroy(HashTable *ht) {
    Bucket *p = ht->arData;
    uint32_t idx = 0;
    while (idx < ht->nNumUsed) {
        /* If idx points to the slot that was never allocated before bailout: */
        zval_ptr_dtor(&p->val); /* DEREFERENCES UNINITIALIZED MEMORY! */
        p++;
        idx++;
    }
}
```

---

## 4. C-Level Breakdown of CVE-2026-109619

### Persistent Worker Global Pointer Retention

When PHP runs under Apache MPM Prefork or PHP-FPM, persistent worker threads process multiple requests sequentially.

Global session state is stored in the persistent structure `php_ps_globals` (`PS(...)`):
* `PS(id)`: Points to the current session ID string (`zend_string *`).
* `PS(send_cookie)`: Flag determining whether to issue a `Set-Cookie` header.

### The Failure Sequence:
1. **Request A** triggers session initialization during pre-RINIT. `PS(id)` is allocated using request-scoped memory (`emalloc`).
2. An OOM or failure occurs during request preparation.
3. `php_request_shutdown()` frees all request memory, destroying the underlying string that `PS(id)` points to.
4. **The Bug:** `PS(id)` was not cleared to `NULL` upon bailout!
5. **Request B** arrives at the same worker process. Before Request B's `RINIT` runs, the engine reads `PS(id)`, causing a **Use-After-Free (UAF)** on the freed memory address.

---

## 5. Memory Layout Comparison: Patched vs Unpatched

| Behavior | Unpatched (PHP 8.4.26 / 8.5.11) | Patched (PHP 8.4.27 / 8.5.12) |
|---|---|---|
| **HashTable Insertion** | Counters incremented *before* allocation | Counters incremented *after* allocation returns `SUCCESS` |
| **Allocation Failure** | Unhandled `longjmp` bailout | Returns `HASH_NOMEM`; cleanly aborts stream |
| **Shutdown OOM State** | Iterates through unallocated buckets | Checks `ZEND_HAS_OOM()` and skips unfinalized structures |
| **Worker Session Globals** | Global pointers retain stale addresses on abort | Global pointers (`PS(id)`) strictly cleared to `NULL` |
| **Pre-RINIT Classes** | Userland classes could instantiate | `PS(in_rfc1867_update)` forces `incomplete_classes_only` |
