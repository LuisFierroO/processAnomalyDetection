/**
 * @file processAgent.c
 * @brief Implementation of the Linux process anomaly detection agent.
 *
 * @author Luis Fierro <luisfierroor@gmail.com>
 * @date 2026
 *
 * @note Development assisted by Claude (Anthropic) — claude.ai/code
 */

#include "processAgent.h"
#include <openssl/evp.h>


/* ── Static caches (zero-initialized, persistent across cycles) ─────────── */

/*
 * Exe hash cache: keyed by (pid, startTime). Avoids re-reading and hashing
 * stable binaries on every cycle — by far the costliest per-process operation.
 * Slot = Knuth multiplicative hash of pid mod EXE_CACHE_SLOTS (power of 2).
 * Collisions evict the old entry; correctness relies on the startTime guard.
 */
#define EXE_CACHE_SLOTS 8192u

typedef struct {
    pid_t         pid;
    unsigned long start_time;
    char          hash[65];
} ExeCacheEntry;

static ExeCacheEntry s_exe_cache[EXE_CACHE_SLOTS];

/*
 * Network inode table: populated once per cycle by build_net_table().
 * Replaces reading /proc/net/{tcp,tcp6,udp,udp6} once per process (O(N×M)→O(M)).
 * Open-addressing hash table keyed by socket inode number.
 */
#define NET_TABLE_SLOTS 16384u

typedef struct {
    unsigned long inode;
    unsigned int  local_port;
    unsigned int  remote_ip;
    unsigned int  remote_port;
    int           state;
    int           is_tcp;
} NetTableEntry;

static NetTableEntry s_net_table[NET_TABLE_SLOTS];
static int           s_net_table_ready = 0;


/* ── PID management and snapshots ───────────────────────────────────────── */

int *getPids(int *count) {
    DIR *dir = opendir("/proc");
    if (!dir) { perror("opendir /proc"); *count = 0; return NULL; }

    int  capacity = 512;
    int *pids     = malloc(capacity * sizeof(int));
    if (!pids) { closedir(dir); *count = 0; return NULL; }

    int n = 0;
    struct dirent *e;
    while ((e = readdir(dir)) != NULL) {
        if (!isDigitString(e->d_name)) continue;
        if (n == capacity) {
            capacity *= 2;
            int *tmp = realloc(pids, capacity * sizeof(int));
            if (!tmp) { free(pids); closedir(dir); *count = 0; return NULL; }
            pids = tmp;
        }
        pids[n++] = atoi(e->d_name);
    }
    closedir(dir);
    *count = n;
    return pids;
}

void takeSnapshot(PidSnapshot *snapshot, int *pids, int count) {
    if (snapshot->firstTime == 1) {
        snapshot->firstTime  = 0;
        snapshot->elapsed_ms = 0.0;
        gettimeofday(&snapshot->act_time, NULL);
        snapshot->actCount = count;
        memcpy(snapshot->actPids, pids, count * sizeof(int));
        for (int i = 0; i < count; i++) snapshot->act[pids[i]] = 1;
        free(pids);
    } else {
        snapshot->prev_time = snapshot->act_time;
        gettimeofday(&snapshot->act_time, NULL);
        snapshot->elapsed_ms =
            (snapshot->act_time.tv_sec  - snapshot->prev_time.tv_sec)  * 1000.0 +
            (snapshot->act_time.tv_usec - snapshot->prev_time.tv_usec) / 1000.0;

        snapshot->prevCount = snapshot->actCount;
        snapshot->actCount  = count;
        memcpy(snapshot->prevPids, snapshot->actPids, snapshot->prevCount * sizeof(int));
        memcpy(snapshot->actPids,  pids,              count * sizeof(int));
        memcpy(snapshot->prev, snapshot->act, sizeof(snapshot->act));
        memset(snapshot->act, 0, sizeof(snapshot->act));
        for (int i = 0; i < count; i++) snapshot->act[pids[i]] = 1;
        free(pids);
    }
}

void diffSnapshot(PidSnapshot *snapshot) {
    for (int i = 0; i < snapshot->actCount; i++)
        if (snapshot->act[snapshot->actPids[i]] != snapshot->prev[snapshot->actPids[i]])
            printf("New process: %d\n", snapshot->actPids[i]);

    for (int i = 0; i < snapshot->prevCount; i++)
        if (snapshot->act[snapshot->prevPids[i]] != snapshot->prev[snapshot->prevPids[i]])
            printf("Process gone: %d\n", snapshot->prevPids[i]);

    if (snapshot->actCount != snapshot->prevCount)
        printf("Process total count changed from %d to %d\n",
               snapshot->prevCount, snapshot->actCount);
}

PidSnapshot *initPidSnapshot(int size) {
    PidSnapshot *snapshot = malloc(sizeof(PidSnapshot));
    if (!snapshot) { perror("malloc initPidSnapshot"); return NULL; }

    snapshot->firstTime = 1;
    snapshot->actCount  = 0;
    snapshot->prevCount = 0;

    snapshot->actPids = malloc(size * sizeof(int));
    if (!snapshot->actPids) {
        perror("malloc initPidSnapshot actPids");
        free(snapshot);
        return NULL;
    }
    snapshot->prevPids = malloc(size * sizeof(int));
    if (!snapshot->prevPids) {
        perror("malloc initPidSnapshot prevPids");
        free(snapshot->actPids);
        free(snapshot);
        return NULL;
    }
    memset(snapshot->act,  0, sizeof(snapshot->act));
    memset(snapshot->prev, 0, sizeof(snapshot->prev));
    return snapshot;
}

void printPids(int *pids, int count) {
    printf("PIDs found:\n");
    for (int i = 0; i < count; i++) printf("|%d|,", pids[i]);
    printf("\n");
}


/* ── /proc data capture helpers ─────────────────────────────────────────── */

static void fillFromStat(ProcessInfo *info, int pid,
                          double elapsed_ms, const ProcessInfo *prev) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);

    int fd = open(path, O_RDONLY);
    if (fd == -1) return;

    char buf[512];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return;
    buf[n] = '\0';

    /* The name may contain parentheses; search for the last ')'. */
    char *end_name = strrchr(buf, ')');
    if (!end_name) return;

    char *start_name = strchr(buf, '(');
    if (start_name && start_name < end_name) {
        size_t len = (size_t)(end_name - start_name - 1);
        if (len >= sizeof(info->name)) len = sizeof(info->name) - 1;
        memcpy(info->name, start_name + 1, len);
        info->name[len] = '\0';
    }

    char *p = end_name + 2;
    char state;
    int ppid, num_threads;
    unsigned long utime, stime, starttime, vsize;
    long rss;

    int got = sscanf(p,
        "%c %d %*d %*d %*d %*d %*u %*u %*u %*u %*u "
        "%lu %lu %*d %*d %*d %*d %d %*d %lu %lu %ld",
        &state, &ppid, &utime, &stime, &num_threads, &starttime, &vsize, &rss);
    if (got < 8) return;

    info->state      = state;
    info->ppid       = ppid;
    info->numThreads = num_threads;
    info->startTime  = starttime;
    info->metrics.utime = utime;
    info->metrics.stime = stime;
    info->metrics.vsz   = (float)(vsize / 1024);
    info->metrics.rss   = (float)(rss * (sysconf(_SC_PAGE_SIZE) / 1024));

    if (prev) {
        info->metrics.prev_utime = prev->metrics.utime;
        info->metrics.prev_stime = prev->metrics.stime;
    }

    if (elapsed_ms > 0.0 && prev) {
        long clk_tck = sysconf(_SC_CLK_TCK);
        /* Guard against unsigned underflow on PID reuse or counter wrap. */
        if (utime >= info->metrics.prev_utime && stime >= info->metrics.prev_stime) {
            unsigned long delta = (utime - info->metrics.prev_utime) +
                                  (stime - info->metrics.prev_stime);
            info->metrics.cpuUsage =
                (float)delta / ((elapsed_ms / 1000.0) * clk_tck) * 100.0f;
        }
    }
}

static void fillFromStatus(ProcessInfo *info, int pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);

    FILE *f = fopen(path, "r");
    if (!f) return;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Uid:", 4) == 0) {
            sscanf(line + 4, " %u %u %u",
                   &info->identity.uid, &info->identity.euid, &info->identity.suid);
            struct passwd pw, *pw_result;
            char pw_buf[256];
            if (getpwuid_r(info->identity.uid, &pw, pw_buf, sizeof(pw_buf), &pw_result) == 0
                    && pw_result) {
                strncpy(info->identity.username, pw_result->pw_name,
                        sizeof(info->identity.username) - 1);
                info->identity.username[sizeof(info->identity.username) - 1] = '\0';
            }
        } else if (strncmp(line, "Gid:", 4) == 0)
            sscanf(line + 4, " %u %u", &info->identity.gid, &info->identity.egid);
        else if (strncmp(line, "TracerPid:", 10) == 0) {
            int tracer = 0;
            sscanf(line + 10, " %d", &tracer);
            info->identity.has_ptrace = (tracer != 0) ? 1 : 0;
        }
    }
    fclose(f);
}

static void fillCmdline(ProcessInfo *info, int pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);

    int fd = open(path, O_RDONLY);
    if (fd == -1) return;

    ssize_t n = read(fd, info->cmdline, sizeof(info->cmdline) - 1);
    close(fd);
    if (n <= 0) return;
    info->cmdline[n] = '\0';

    for (ssize_t i = 0; i < n - 1; i++)
        if (info->cmdline[i] == '\0') info->cmdline[i] = ' ';
}

static void computeExeHash(ProcessInfo *info) {
    int fd = open(info->identity.exe_path, O_RDONLY);
    if (fd == -1) { info->identity.exe_hash[0] = '\0'; return; }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { close(fd); info->identity.exe_hash[0] = '\0'; return; }

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

    unsigned char chunk[4096];
    ssize_t n;
    while ((n = read(fd, chunk, sizeof(chunk))) > 0)
        EVP_DigestUpdate(ctx, chunk, (size_t)n);
    close(fd);

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);

    for (unsigned int i = 0; i < hash_len; i++)
        sprintf(info->identity.exe_hash + i * 2, "%02x", hash[i]);
    info->identity.exe_hash[hash_len * 2] = '\0';
}

static void fillExePath(ProcessInfo *info, int pid) {
    char link[64];
    snprintf(link, sizeof(link), "/proc/%d/exe", pid);

    ssize_t len = readlink(link, info->identity.exe_path,
                           sizeof(info->identity.exe_path) - 1);
    if (len == -1) {
        info->identity.exe_path[0] = '\0';
        info->identity.exe_hash[0] = '\0';
        return;
    }
    info->identity.exe_path[len] = '\0';

    char *tag = strstr(info->identity.exe_path, " (deleted)");
    if (tag) { info->identity.is_deleted_exe = 1; *tag = '\0'; }

    /* Cache hit: reuse hash when pid+startTime match (process hasn't restarted). */
    unsigned int slot = ((unsigned int)info->pid * 2654435761u) >> (32u - 13u);
    ExeCacheEntry *ce = &s_exe_cache[slot];
    if (ce->pid == info->pid && ce->start_time == info->startTime && ce->hash[0] != '\0') {
        memcpy(info->identity.exe_hash, ce->hash, 65);
        return;
    }

    computeExeHash(info);

    ce->pid        = info->pid;
    ce->start_time = info->startTime;
    memcpy(ce->hash, info->identity.exe_hash, 65);
}

static const char *SUSPICIOUS_PREFIXES[] = {
    "/tmp/", "/dev/shm/", "/run/shm/", "/var/tmp/"
};

/* Single pass over /proc/<pid>/fd: collects fd stats, suspicious paths,
   and socket inodes without opening the directory twice. */
static void fillFdAndSockets(ProcessInfo *info, int pid,
                              unsigned long *sock_inodes, int *sock_count) {
    *sock_count = 0;
    char fd_dir[64];
    snprintf(fd_dir, sizeof(fd_dir), "/proc/%d/fd", pid);

    DIR *dir = opendir(fd_dir);
    if (!dir) return;

    struct dirent *entry;
    int susp = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        info->fd.open_fd_count++;

        char link[512], target[256];
        snprintf(link, sizeof(link), "/proc/%d/fd/%s", pid, entry->d_name);
        ssize_t len = readlink(link, target, sizeof(target) - 1);
        if (len <= 0) continue;
        target[len] = '\0';

        unsigned long ino;
        if (*sock_count < MAX_SOCK_INODES && sscanf(target, "socket:[%lu]", &ino) == 1) {
            sock_inodes[(*sock_count)++] = ino;
            continue;
        }

        if (target[0] != '/') continue;
        info->fd.open_files_count++;

        if (susp < 4) {
            for (int i = 0; i < 4; i++) {
                if (strncmp(target, SUSPICIOUS_PREFIXES[i],
                            strlen(SUSPICIOUS_PREFIXES[i])) == 0) {
                    strncpy(info->fd.suspicious_paths[susp], target, 255);
                    info->fd.suspicious_paths[susp][255] = '\0';
                    susp++;
                    break;
                }
            }
        }
    }
    closedir(dir);
}


/* ── Network inode table (built once per cycle) ──────────────────────────── */

static void net_table_insert(unsigned long inode, unsigned int lp,
                              unsigned int ri, unsigned int rp,
                              int state, int is_tcp) {
    if (!inode) return;
    unsigned int h = (unsigned int)(inode * 2654435761UL) & (NET_TABLE_SLOTS - 1);
    for (unsigned int i = 0; i < NET_TABLE_SLOTS; i++) {
        unsigned int s = (h + i) & (NET_TABLE_SLOTS - 1);
        if (!s_net_table[s].inode || s_net_table[s].inode == inode) {
            s_net_table[s].inode       = inode;
            s_net_table[s].local_port  = lp;
            s_net_table[s].remote_ip   = ri;
            s_net_table[s].remote_port = rp;
            s_net_table[s].state       = state;
            s_net_table[s].is_tcp      = is_tcp;
            return;
        }
    }
}

static const NetTableEntry *net_table_find(unsigned long inode) {
    if (!inode) return NULL;
    unsigned int h = (unsigned int)(inode * 2654435761UL) & (NET_TABLE_SLOTS - 1);
    for (unsigned int i = 0; i < NET_TABLE_SLOTS; i++) {
        unsigned int s = (h + i) & (NET_TABLE_SLOTS - 1);
        if (!s_net_table[s].inode) return NULL;
        if (s_net_table[s].inode == inode) return &s_net_table[s];
    }
    return NULL;
}

static void parse_net_file_global(const char *path, int is_tcp) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[256];
    fgets(line, sizeof(line), f); /* skip header */
    while (fgets(line, sizeof(line), f)) {
        unsigned int la, lp, ra, rp, st;
        unsigned long ino;
        char *colon = strchr(line, ':');
        if (!colon) continue;
        if (sscanf(colon + 1, " %X:%X %X:%X %X %*s %*s %*s %*s %*s %lu",
                   &la, &lp, &ra, &rp, &st, &ino) != 6) continue;
        net_table_insert(ino, lp, ra, rp, (int)st, is_tcp);
    }
    fclose(f);
}

static void build_net_table(void) {
    memset(s_net_table, 0, sizeof(s_net_table));
    parse_net_file_global("/proc/net/tcp",  1);
    parse_net_file_global("/proc/net/tcp6", 1);
    parse_net_file_global("/proc/net/udp",  0);
    parse_net_file_global("/proc/net/udp6", 0);
    s_net_table_ready = 1;
}

/* Fallback used only for single-process inspection (-i) when build_net_table()
   was not called: parses /proc/net files directly for a known inode set. */
static void parseNetFileDirect(ProcessInfo *info, const unsigned long *inodes,
                                int inode_count, const char *path, int is_tcp) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[256];
    fgets(line, sizeof(line), f);
    while (fgets(line, sizeof(line), f)) {
        unsigned int la, lp, ra, rp, st;
        unsigned long ino;
        char *colon = strchr(line, ':');
        if (!colon) continue;
        if (sscanf(colon + 1, " %X:%X %X:%X %X %*s %*s %*s %*s %*s %lu",
                   &la, &lp, &ra, &rp, &st, &ino) != 6) continue;
        int found = 0;
        for (int i = 0; i < inode_count; i++)
            if (inodes[i] == ino) { found = 1; break; }
        if (!found) continue;
        info->network.open_connections++;
        if (is_tcp && st == 0x0A && info->network.port_count < 32) {
            info->network.listen_ports[info->network.port_count++] = (int)lp;
        } else if (is_tcp && st == 0x01 && info->network.remote_ip_count < 8) {
            unsigned char *b = (unsigned char *)&ra;
            snprintf(info->network.remote_ips[info->network.remote_ip_count++], 46,
                     "%d.%d.%d.%d:%u", b[0], b[1], b[2], b[3], rp);
        }
    }
    fclose(f);
}

static void fillNetworkFromInodes(ProcessInfo *info,
                                   const unsigned long *inodes, int count) {
    if (s_net_table_ready) {
        for (int i = 0; i < count; i++) {
            const NetTableEntry *e = net_table_find(inodes[i]);
            if (!e) continue;
            info->network.open_connections++;
            if (e->is_tcp && e->state == 0x0A && info->network.port_count < 32) {
                info->network.listen_ports[info->network.port_count++] = (int)e->local_port;
            } else if (e->is_tcp && e->state == 0x01 && info->network.remote_ip_count < 8) {
                unsigned char *b = (unsigned char *)&e->remote_ip;
                snprintf(info->network.remote_ips[info->network.remote_ip_count++], 46,
                         "%d.%d.%d.%d:%u", b[0], b[1], b[2], b[3], e->remote_port);
            }
        }
    } else {
        parseNetFileDirect(info, inodes, count, "/proc/net/tcp",  1);
        parseNetFileDirect(info, inodes, count, "/proc/net/tcp6", 1);
        parseNetFileDirect(info, inodes, count, "/proc/net/udp",  0);
        parseNetFileDirect(info, inodes, count, "/proc/net/udp6", 0);
    }
}

static void fillIoInfo(ProcessInfo *info, int pid, const ProcessInfo *prev) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/io", pid);

    FILE *f = fopen(path, "r");
    if (!f) return;

    char line[128];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "read_bytes:", 11) == 0)
            sscanf(line + 11, " %lu", &info->metrics.io_read_bytes);
        else if (strncmp(line, "write_bytes:", 12) == 0)
            sscanf(line + 12, " %lu", &info->metrics.io_write_bytes);
    }
    fclose(f);

    if (prev && info->elapsed_ms > 0.0) {
        double secs = info->elapsed_ms / 1000.0;
        info->metrics.io_read_bps  =
            (double)(info->metrics.io_read_bytes  - prev->metrics.io_read_bytes)  / secs;
        info->metrics.io_write_bps =
            (double)(info->metrics.io_write_bytes - prev->metrics.io_write_bytes) / secs;
    }
}


/* ── Public API: process capture ─────────────────────────────────────────── */

ProcessInfo *getProcessInfo(int pid, double elapsed_ms, const ProcessInfo *prev) {
    ProcessInfo *info = calloc(1, sizeof(ProcessInfo));
    if (!info) return NULL;

    info->pid        = pid;
    info->elapsed_ms = elapsed_ms;
    gettimeofday(&info->capture_time, NULL);
    info->lastSeenTime = (unsigned long)info->capture_time.tv_sec;

    fillFromStat(info, pid, elapsed_ms, prev);
    fillFromStatus(info, pid);
    fillCmdline(info, pid);
    fillExePath(info, pid);

    unsigned long sock_inodes[MAX_SOCK_INODES];
    int           sock_count = 0;
    fillFdAndSockets(info, pid, sock_inodes, &sock_count);
    fillNetworkFromInodes(info, sock_inodes, sock_count);
    fillIoInfo(info, pid, prev);

    return info;
}

void printProcessInfo(const ProcessInfo *info) {
    if (!info) { printf("NULL\n"); return; }

    printf("=== Process %d ===\n", info->pid);
    printf("  name       : %s\n", info->name);
    printf("  cmdline    : %s\n", info->cmdline[0] ? info->cmdline : "(empty)");
    printf("  state      : %c\n", info->state);
    printf("  ppid       : %d\n", info->ppid);
    printf("  threads    : %d\n", info->numThreads);

    printf("  owner      : %s\n",
           info->identity.username[0] ? info->identity.username : "(unknown)");
    printf("  uid/euid   : %u / %u  gid/egid: %u / %u\n",
           info->identity.uid, info->identity.euid,
           info->identity.gid, info->identity.egid);
    printf("  exe        : %s%s\n",
           info->identity.exe_path[0] ? info->identity.exe_path : "(unknown)",
           info->identity.is_deleted_exe ? " [DELETED]" : "");
    printf("  sha256     : %s\n",
           info->identity.exe_hash[0] ? info->identity.exe_hash : "(none)");

    printf("  cpu        : %.2f%%  (utime=%lu stime=%lu)\n",
           info->metrics.cpuUsage, info->metrics.utime, info->metrics.stime);
    printf("  mem        : rss=%.0f KB  vsz=%.0f KB\n",
           info->metrics.rss, info->metrics.vsz);
    printf("  io         : read=%lu B  write=%lu B\n",
           info->metrics.io_read_bytes, info->metrics.io_write_bytes);
    printf("  io rate    : read=%.1f KB/s  write=%.1f KB/s\n",
           info->metrics.io_read_bps / 1024.0, info->metrics.io_write_bps / 1024.0);

    printf("  open fds   : %d  (files: %d)\n",
           info->fd.open_fd_count, info->fd.open_files_count);

    if (info->network.port_count > 0) {
        printf("  listening  :");
        for (int i = 0; i < info->network.port_count; i++)
            printf(" %d", info->network.listen_ports[i]);
        printf("\n");
    }
    if (info->network.remote_ip_count > 0) {
        printf("  remote IPs :");
        for (int i = 0; i < info->network.remote_ip_count; i++)
            printf(" %s", info->network.remote_ips[i]);
        printf("\n");
    }
    printf("  connections: %d\n", info->network.open_connections);

    for (int i = 0; i < 4; i++)
        if (info->fd.suspicious_paths[i][0])
            printf("  [SUSP FD]  : %s\n", info->fd.suspicious_paths[i]);

    printf("  ptrace     : %s\n", info->identity.has_ptrace ? "YES" : "no");
    printf("  startTime  : %lu\n", info->startTime);
    printf("  captured   : %ld.%06ld  (interval: %.1f ms)\n",
           (long)info->capture_time.tv_sec,
           (long)info->capture_time.tv_usec,
           info->elapsed_ms);

    if (info->scoring.alert_flags)
        printf("  score      : %.2f  flags: 0x%03X  [%s]\n",
               info->scoring.anomaly_score, info->scoring.alert_flags,
               info->scoring.baseline_deviation);
}


/* ── OCP: Table-driven scoring rules ─────────────────────────────────────── */

static float fuzzy_high(float val, float low, float high) {
    if (val <= low)  return 0.0f;
    if (val >= high) return 1.0f;
    return (val - low) / (high - low);
}

/* One evaluator per rule — each depends only on the sub-struct it needs. */

static float eval_priv_esc   (const ProcessInfo *p) { return (p->identity.uid != p->identity.euid) ? 1.0f : 0.0f; }
static float eval_deleted_exe(const ProcessInfo *p) { return p->identity.is_deleted_exe            ? 1.0f : 0.0f; }
static float eval_ptrace     (const ProcessInfo *p) { return p->identity.has_ptrace                ? 1.0f : 0.0f; }
static float eval_susp_path  (const ProcessInfo *p) { return p->fd.suspicious_paths[0][0]          ? 1.0f : 0.0f; }
static float eval_zombie     (const ProcessInfo *p) { return (p->state == 'Z')                     ? 1.0f : 0.0f; }
static float eval_high_fd    (const ProcessInfo *p) { return fuzzy_high((float)p->fd.open_fd_count,          FUZZY_FD_LOW,       FUZZY_FD_HIGH);       }
static float eval_net_scan   (const ProcessInfo *p) { return fuzzy_high((float)p->network.open_connections,  FUZZY_CONN_LOW,     FUZZY_CONN_HIGH);     }
static float eval_high_cpu   (const ProcessInfo *p) { return fuzzy_high(p->metrics.cpuUsage,                 FUZZY_CPU_LOW,      FUZZY_CPU_HIGH);      }
static float eval_fork_bomb  (const ProcessInfo *p) { return fuzzy_high((float)p->metrics.fork_rate,         FUZZY_FORK_LOW,     FUZZY_FORK_HIGH);     }
static float eval_high_io_w  (const ProcessInfo *p) { return fuzzy_high((float)p->metrics.io_write_bps,      FUZZY_IO_WRITE_LOW, FUZZY_IO_WRITE_HIGH); }
static float eval_high_io_r  (const ProcessInfo *p) { return fuzzy_high((float)p->metrics.io_read_bps,       FUZZY_IO_READ_LOW,  FUZZY_IO_READ_HIGH);  }

typedef struct {
    const char *name;
    int         flag_bit;
    float       max_weight;
    float     (*evaluate)(const ProcessInfo *);
    int         is_binary; /* 1 = on/off rule, 0 = fuzzy ramp */
} ScoringRule;

static const ScoringRule RULES[] = {
    { "PRIV_ESC",    ALERT_PRIV_ESC,    0.35f, eval_priv_esc,    1 },
    { "DELETED_EXE", ALERT_DELETED_EXE, 0.40f, eval_deleted_exe, 1 },
    { "PTRACE",      ALERT_PTRACE,      0.20f, eval_ptrace,      1 },
    { "SUSP_PATH",   ALERT_SUSP_PATH,   0.15f, eval_susp_path,   1 },
    { "ZOMBIE",      ALERT_ZOMBIE,      0.35f, eval_zombie,      1 },
    { "HIGH_FD",     ALERT_HIGH_FD,     0.15f, eval_high_fd,     0 },
    { "NET_SCAN",    ALERT_NET_SCAN,    0.10f, eval_net_scan,    0 },
    { "HIGH_CPU",    ALERT_HIGH_CPU,    0.10f, eval_high_cpu,    0 },
    { "FORK_BOMB",   ALERT_FORK_BOMB,   0.25f, eval_fork_bomb,   0 },
    { "HIGH_IO_W",   ALERT_HIGH_IO_W,   0.20f, eval_high_io_w,   0 },
    { "HIGH_IO_R",   ALERT_HIGH_IO_R,   0.10f, eval_high_io_r,   0 },
};
#define RULE_COUNT ((int)(sizeof(RULES) / sizeof(RULES[0])))


/* ── JSON output ─────────────────────────────────────────────────────────── */

static void json_str(const char *s) {
    putchar('"');
    for (; *s; s++) {
        switch (*s) {
            case '"':  fputs("\\\"", stdout); break;
            case '\\': fputs("\\\\", stdout); break;
            case '\n': fputs("\\n",  stdout); break;
            case '\r': fputs("\\r",  stdout); break;
            case '\t': fputs("\\t",  stdout); break;
            default:
                if ((unsigned char)*s < 0x20)
                    printf("\\u%04x", (unsigned char)*s);
                else
                    putchar(*s);
        }
    }
    putchar('"');
}

void json_print_str(const char *s) { json_str(s); }

void printProcessJson(const ProcessInfo *info) {
    printf("{\n");
    printf("  \"pid\": %d,\n",    info->pid);
    printf("  \"ppid\": %d,\n",   info->ppid);
    printf("  \"name\": ");       json_str(info->name);        printf(",\n");
    printf("  \"cmdline\": ");    json_str(info->cmdline[0] ? info->cmdline : ""); printf(",\n");
    printf("  \"state\": \"%c\",\n", info->state);
    printf("  \"threads\": %d,\n", info->numThreads);

    printf("  \"identity\": {\n");
    printf("    \"uid\": %u,\n",      info->identity.uid);
    printf("    \"euid\": %u,\n",     info->identity.euid);
    printf("    \"suid\": %u,\n",     info->identity.suid);
    printf("    \"gid\": %u,\n",      info->identity.gid);
    printf("    \"egid\": %u,\n",     info->identity.egid);
    printf("    \"username\": ");     json_str(info->identity.username[0] ? info->identity.username : ""); printf(",\n");
    printf("    \"exe_path\": ");  json_str(info->identity.exe_path);  printf(",\n");
    printf("    \"exe_hash\": ");  json_str(info->identity.exe_hash);  printf(",\n");
    printf("    \"is_deleted_exe\": %s,\n", info->identity.is_deleted_exe ? "true" : "false");
    printf("    \"has_ptrace\": %s\n",      info->identity.has_ptrace     ? "true" : "false");
    printf("  },\n");

    printf("  \"metrics\": {\n");
    printf("    \"cpu_percent\": %.2f,\n",    info->metrics.cpuUsage);
    printf("    \"rss_kb\": %.0f,\n",         info->metrics.rss);
    printf("    \"vsz_kb\": %.0f,\n",         info->metrics.vsz);
    printf("    \"utime\": %lu,\n",           info->metrics.utime);
    printf("    \"stime\": %lu,\n",           info->metrics.stime);
    printf("    \"fork_rate\": %lu,\n",       info->metrics.fork_rate);
    printf("    \"io_read_bytes\": %lu,\n",   info->metrics.io_read_bytes);
    printf("    \"io_write_bytes\": %lu,\n",  info->metrics.io_write_bytes);
    printf("    \"io_read_bps\": %.2f,\n",    info->metrics.io_read_bps);
    printf("    \"io_write_bps\": %.2f\n",    info->metrics.io_write_bps);
    printf("  },\n");

    printf("  \"network\": {\n");
    printf("    \"open_connections\": %d,\n", info->network.open_connections);
    printf("    \"listen_ports\": [");
    for (int i = 0; i < info->network.port_count; i++) {
        if (i > 0) printf(", ");
        printf("%d", info->network.listen_ports[i]);
    }
    printf("],\n");
    printf("    \"remote_ips\": [");
    for (int i = 0; i < info->network.remote_ip_count; i++) {
        if (i > 0) printf(", ");
        json_str(info->network.remote_ips[i]);
    }
    printf("]\n");
    printf("  },\n");

    printf("  \"fd\": {\n");
    printf("    \"open_fd_count\": %d,\n",   info->fd.open_fd_count);
    printf("    \"open_files_count\": %d,\n", info->fd.open_files_count);
    printf("    \"suspicious_paths\": [");
    int first = 1;
    for (int i = 0; i < 4; i++) {
        if (info->fd.suspicious_paths[i][0]) {
            if (!first) printf(", ");
            json_str(info->fd.suspicious_paths[i]);
            first = 0;
        }
    }
    printf("]\n");
    printf("  },\n");

    printf("  \"scoring\": {\n");
    printf("    \"anomaly_score\": %.4f,\n", info->scoring.anomaly_score);
    printf("    \"alert_flags\": %d,\n",     info->scoring.alert_flags);
    printf("    \"triggered_rules\": [");
    first = 1;
    for (int i = 0; i < RULE_COUNT; i++) {
        float m = RULES[i].evaluate(info);
        if (m > 0.0f) {
            if (!first) printf(",");
            printf("\n      {\"name\": \"%s\", \"type\": \"%s\", \"membership\": %.4f, \"contribution_pct\": %.1f}",
                   RULES[i].name,
                   RULES[i].is_binary ? "binary" : "fuzzy",
                   m,
                   m * RULES[i].max_weight * 100.0f);
            first = 0;
        }
    }
    if (!first) printf("\n    ");
    printf("]\n");
    printf("  },\n");

    printf("  \"capture_time_sec\": %ld,\n",  (long)info->capture_time.tv_sec);
    printf("  \"capture_time_usec\": %ld,\n", (long)info->capture_time.tv_usec);
    printf("  \"elapsed_ms\": %.1f\n",        info->elapsed_ms);
    printf("}");
}


/* ── SRP: Separated scoring concerns ─────────────────────────────────────── */

/** Computes anomaly_score and alert_flags. No output. */
static void scoreProcess(ProcessInfo *info) {
    info->scoring.alert_flags   = 0;
    info->scoring.anomaly_score = 0.0f;

    for (int i = 0; i < RULE_COUNT; i++) {
        float m = RULES[i].evaluate(info);
        if (m > 0.0f) {
            info->scoring.alert_flags   |= RULES[i].flag_bit;
            info->scoring.anomaly_score += m * RULES[i].max_weight;
        }
    }
    if (info->scoring.anomaly_score > 1.0f)
        info->scoring.anomaly_score = 1.0f;
}

/** Builds baseline_deviation from active flags. No output. */
static void buildBaselineDeviation(ProcessInfo *info) {
    char *p  = info->scoring.baseline_deviation;
    int left = (int)sizeof(info->scoring.baseline_deviation);
    info->scoring.baseline_deviation[0] = '\0';

    for (int i = 0; i < RULE_COUNT; i++) {
        if (info->scoring.alert_flags & RULES[i].flag_bit) {
            int w = snprintf(p, left, "%s ", RULES[i].name);
            if (w > 0 && w < left) { p += w; left -= w; }
        }
    }
}

int isSuspicious(ProcessInfo *info) {
    scoreProcess(info);
    buildBaselineDeviation(info);
    return (info->scoring.anomaly_score >= ANOMALY_THRESHOLD) ? 1 : 0;
}

/** Prints triggered rules with membership values. Separate from detection. */
void printProcessAlerts(const ProcessInfo *info) {
    printf("--- PID %d (%s)  score=%.2f  flags=0x%03X ---\n",
           info->pid, info->name,
           info->scoring.anomaly_score, info->scoring.alert_flags);

    for (int i = 0; i < RULE_COUNT; i++) {
        float m = RULES[i].evaluate(info);
        if (m > 0.0f) {
            printf("  [%c] %-14s  μ=%.2f  +%.0f%%\n",
                   (m >= 1.0f) ? '!' : '~',
                   RULES[i].name, m,
                   m * RULES[i].max_weight * 100.0f);
        }
    }
}


/* ── SRP: analize() decomposed into focused helpers ─────────────────────── */

/** First-pass: fills prev_table with a ProcessInfo for each PID in the snapshot. */
static void fillPrevTable(ProcessInfo **prev_table, const PidSnapshot *snap) {
    for (int i = 0; i < snap->actCount; i++) {
        int pid = snap->actPids[i];
        prev_table[pid] = getProcessInfo(pid, 0.0, NULL);
    }
}

/** Second-pass: scores each process, collects suspicious ones, optionally builds tree. */
static ProcessInfo **collectSuspiciousProcesses(ProcessInfo **prev_table,
                                                  const PidSnapshot *snap,
                                                  int *count,
                                                  ProcessTreeNode **tree_out,
                                                  int *tree_count_out) {
    int capacity = 16;
    *count = 0;
    ProcessInfo **result = malloc(capacity * sizeof(ProcessInfo *));
    if (!result) return NULL;

    ProcessTreeNode *tree = NULL;
    int tcount = 0;
    if (tree_out) {
        tree = malloc(snap->actCount * sizeof(ProcessTreeNode));
        /* continue without tree on alloc failure */
    }

    for (int i = 0; i < snap->actCount; i++) {
        int pid = snap->actPids[i];
        ProcessInfo *info = getProcessInfo(pid, snap->elapsed_ms, prev_table[pid]);

        free(prev_table[pid]);
        prev_table[pid] = NULL;

        if (!info) continue;

        int susp = isSuspicious(info);

        if (tree && tcount < snap->actCount) {
            tree[tcount].pid          = info->pid;
            tree[tcount].ppid         = info->ppid;
            memcpy(tree[tcount].name, info->name, sizeof(info->name));
            tree[tcount].state        = info->state ? info->state : '?';
            tree[tcount].threads      = info->numThreads;
            tree[tcount].is_suspicious = susp;
            tree[tcount].anomaly_score = info->scoring.anomaly_score;
            memcpy(tree[tcount].username, info->identity.username, sizeof(tree[tcount].username));
            tcount++;
        }

        if (susp) {
            if (*count == capacity) {
                capacity *= 2;
                ProcessInfo **tmp = realloc(result, capacity * sizeof(ProcessInfo *));
                if (!tmp) { free(info); break; }
                result = tmp;
            }
            result[(*count)++] = info;
        } else {
            free(info);
        }
    }

    if (tree_out)       *tree_out       = tree;
    if (tree_count_out) *tree_count_out = tcount;
    return result;
}

/**
 * @brief Runs the full analysis cycle and returns the suspicious processes.
 *
 * @param count         Out: number of suspicious processes returned.
 * @param tree_out      Out: if non-NULL, receives a malloc'd array of ProcessTreeNode
 *                      for every process in the second snapshot. Caller must free().
 * @param tree_count    Out: if non-NULL, receives the number of nodes in *tree_out
 *                      (also equals the total number of processes seen).
 *
 * Single cleanup path via goto ensures no memory is leaked on any error.
 */
ProcessInfo **analize_ex(int *count, ProcessTreeNode **tree_out, int *tree_count) {
    *count = 0;
    if (tree_out)   *tree_out   = NULL;
    if (tree_count) *tree_count = 0;

    ProcessInfo  **prev_table = NULL;
    PidSnapshot   *snapshot   = NULL;
    ProcessInfo  **suspicious = NULL;
    int           *pids       = NULL;
    int            pidCount   = 0;

    prev_table = calloc(MAX_PROCESSES, sizeof(ProcessInfo *));
    if (!prev_table) goto cleanup;

    pids = getPids(&pidCount);
    if (!pids) goto cleanup;

    snapshot = initPidSnapshot(MAX_PROCESSES);
    if (!snapshot) goto cleanup;

    takeSnapshot(snapshot, pids, pidCount);
    pids = NULL; /* takeSnapshot took ownership */

    fillPrevTable(prev_table, snapshot);

    { struct timespec _ts = { SAMPLE_INTERVAL_MS / 1000, (long)(SAMPLE_INTERVAL_MS % 1000) * 1000000L }; nanosleep(&_ts, NULL); }

    pids = getPids(&pidCount);
    if (!pids) goto cleanup;

    takeSnapshot(snapshot, pids, pidCount);
    pids = NULL;

    build_net_table();

    suspicious = collectSuspiciousProcesses(prev_table, snapshot, count,
                                            tree_out, tree_count);

cleanup:
    if (prev_table) {
        for (int i = 0; i < MAX_PROCESSES; i++) {
            if (prev_table[i]) { free(prev_table[i]); }
        }
        free(prev_table);
    }
    if (snapshot) {
        free(snapshot->actPids);
        free(snapshot->prevPids);
        free(snapshot);
    }
    free(pids);

    return suspicious;
}

ProcessInfo **analize(int *count) {
    return analize_ex(count, NULL, NULL);
}


/* ── analize_full: three-tier process classification ────────────────────── */

static float get_cpu     (const ProcessInfo *p) { return p->metrics.cpuUsage;            }
static float get_rss     (const ProcessInfo *p) { return p->metrics.rss;                 }
static float get_io_write(const ProcessInfo *p) { return (float)p->metrics.io_write_bps; }

/**
 * Marks into top_selected the top TOP_RESOURCE_N unclaimed entries of arr,
 * ranked by get_val. Already-claimed or already-selected indices are skipped.
 */
static void select_top_n(ProcessInfo **arr, int count,
                          const int *claimed, int *top_selected,
                          float (*get_val)(const ProcessInfo *)) {
    float top_vals[TOP_RESOURCE_N];
    int   top_idxs[TOP_RESOURCE_N];
    int   found = 0;

    for (int i = 0; i < count; i++) {
        if (!arr[i] || claimed[i] || top_selected[i]) continue;
        float v = get_val(arr[i]);
        if (v <= 0.0f) continue;
        if (found < TOP_RESOURCE_N) {
            top_vals[found] = v;
            top_idxs[found] = i;
            found++;
        } else {
            int min_j = 0;
            for (int j = 1; j < found; j++)
                if (top_vals[j] < top_vals[min_j]) min_j = j;
            if (v > top_vals[min_j]) {
                top_vals[min_j] = v;
                top_idxs[min_j] = i;
            }
        }
    }
    for (int k = 0; k < found; k++)
        top_selected[top_idxs[k]] = 1;
}

void free_analysis_result(AnalysisResult *r) {
    if (!r) return;
    for (int i = 0; i < r->suspicious_count;   i++) free(r->suspicious[i]);
    for (int i = 0; i < r->notable_count;       i++) free(r->notable[i]);
    for (int i = 0; i < r->top_resources_count; i++) free(r->top_resources[i]);
    free(r->suspicious);
    free(r->notable);
    free(r->top_resources);
    free(r->tree);
    free(r);
}

/**
 * @brief Runs a full analysis cycle and classifies every process into three tiers.
 *
 * @param include_tree  If non-zero, allocates and fills result->tree with minimal
 *                      data for every running process in the second snapshot.
 * @return Heap-allocated AnalysisResult. Free with free_analysis_result().
 *         Returns NULL on allocation or /proc read failure.
 */
AnalysisResult *analize_full(int include_tree) {
    AnalysisResult *result = calloc(1, sizeof(AnalysisResult));
    if (!result) return NULL;

    ProcessInfo  **prev_table   = NULL;
    PidSnapshot   *snapshot     = NULL;
    ProcessInfo  **all_procs    = NULL;
    int           *claimed      = NULL;
    int           *top_selected = NULL;
    int           *pids         = NULL;
    int            pidCount     = 0;
    int            all_count    = 0;
    int            partitioned  = 0;

    prev_table = calloc(MAX_PROCESSES, sizeof(ProcessInfo *));
    if (!prev_table) goto cleanup;

    pids = getPids(&pidCount);
    if (!pids) goto cleanup;

    snapshot = initPidSnapshot(MAX_PROCESSES);
    if (!snapshot) goto cleanup;

    takeSnapshot(snapshot, pids, pidCount);
    pids = NULL;
    fillPrevTable(prev_table, snapshot);
    { struct timespec _ts = { SAMPLE_INTERVAL_MS / 1000, (long)(SAMPLE_INTERVAL_MS % 1000) * 1000000L }; nanosleep(&_ts, NULL); }

    pids = getPids(&pidCount);
    if (!pids) goto cleanup;
    takeSnapshot(snapshot, pids, pidCount);
    pids = NULL;

    build_net_table();

    all_procs = calloc(snapshot->actCount, sizeof(ProcessInfo *));
    if (!all_procs) goto cleanup;

    if (include_tree)
        result->tree = calloc(snapshot->actCount, sizeof(ProcessTreeNode));

    /* Score every process and collect all into all_procs. */
    for (int i = 0; i < snapshot->actCount; i++) {
        int pid = snapshot->actPids[i];
        ProcessInfo *info = getProcessInfo(pid, snapshot->elapsed_ms, prev_table[pid]);
        free(prev_table[pid]);
        prev_table[pid] = NULL;
        if (!info) continue;

        isSuspicious(info);

        if (result->tree) {
            ProcessTreeNode *node = &result->tree[all_count];
            node->pid           = info->pid;
            node->ppid          = info->ppid;
            memcpy(node->name, info->name, sizeof(info->name));
            node->state         = info->state ? info->state : '?';
            node->threads       = info->numThreads;
            node->is_suspicious = (info->scoring.anomaly_score >= ANOMALY_THRESHOLD);
            node->anomaly_score = info->scoring.anomaly_score;
            node->cpu_percent   = info->metrics.cpuUsage;
            node->rss_kb        = info->metrics.rss;
            memcpy(node->username, info->identity.username, sizeof(node->username));
        }

        all_procs[all_count++] = info;
    }
    result->tree_count = all_count;

    /* Count tiers. */
    int n_susp = 0, n_notable = 0;
    for (int i = 0; i < all_count; i++) {
        float s = all_procs[i]->scoring.anomaly_score;
        if      (s >= ANOMALY_THRESHOLD)  n_susp++;
        else if (s >= NOTABLE_THRESHOLD)  n_notable++;
    }

    result->suspicious = malloc((n_susp    > 0 ? n_susp    : 1) * sizeof(ProcessInfo *));
    result->notable    = malloc((n_notable > 0 ? n_notable : 1) * sizeof(ProcessInfo *));
    if (!result->suspicious || !result->notable) goto cleanup;

    claimed      = calloc(all_count, sizeof(int));
    top_selected = calloc(all_count, sizeof(int));
    if (!claimed || !top_selected) goto cleanup;

    /* Partition tier 1 (suspicious) and tier 2 (notable). */
    int si = 0, ni = 0;
    for (int i = 0; i < all_count; i++) {
        float s = all_procs[i]->scoring.anomaly_score;
        if (s >= ANOMALY_THRESHOLD) {
            result->suspicious[si++] = all_procs[i];
            claimed[i] = 1;
        } else if (s >= NOTABLE_THRESHOLD) {
            result->notable[ni++] = all_procs[i];
            claimed[i] = 1;
        }
    }
    result->suspicious_count = si;
    result->notable_count    = ni;

    /* Tier 3: top-N by CPU, RSS, and I/O write from unclaimed processes. */
    select_top_n(all_procs, all_count, claimed, top_selected, get_cpu);
    select_top_n(all_procs, all_count, claimed, top_selected, get_rss);
    select_top_n(all_procs, all_count, claimed, top_selected, get_io_write);

    int n_top = 0;
    for (int i = 0; i < all_count; i++)
        if (top_selected[i]) n_top++;

    if (n_top > 0) {
        result->top_resources = malloc(n_top * sizeof(ProcessInfo *));
        if (result->top_resources) {
            int ti = 0;
            for (int i = 0; i < all_count; i++)
                if (top_selected[i])
                    result->top_resources[ti++] = all_procs[i];
            result->top_resources_count = n_top;
        } else {
            /* malloc failed: free top_selected processes to avoid leak.
               top_resources_count stays 0, so free_analysis_result is safe. */
            for (int i = 0; i < all_count; i++)
                if (top_selected[i]) free(all_procs[i]);
        }
    }

    /* Free processes that didn't make any tier. */
    for (int i = 0; i < all_count; i++)
        if (!claimed[i] && !top_selected[i])
            free(all_procs[i]);

    partitioned = 1;

cleanup:
    /* If we failed before partitioning, free all collected ProcessInfo*. */
    if (!partitioned && all_procs)
        for (int i = 0; i < all_count; i++)
            if (all_procs[i]) free(all_procs[i]);

    free(all_procs);
    free(claimed);
    free(top_selected);

    if (prev_table) {
        for (int i = 0; i < MAX_PROCESSES; i++)
            if (prev_table[i]) free(prev_table[i]);
        free(prev_table);
    }
    if (snapshot) {
        free(snapshot->actPids);
        free(snapshot->prevPids);
        free(snapshot);
    }
    free(pids);

    if (!partitioned) {
        free_analysis_result(result);
        return NULL;
    }
    return result;
}
