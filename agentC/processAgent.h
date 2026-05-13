/**
 * @file processAgent.h
 * @brief Public API and definitions for the Linux process anomaly detection agent.
 *
 * @author Luis Fierro <luisfierroor@gmail.com>
 * @date 2026
 *
 * @note Development assisted by Claude (Anthropic) — claude.ai/code
 */

#ifndef PROCESSAGENT_H
#define PROCESSAGENT_H

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include "funtions.h"

/** @brief Maximum PID value supported by the Linux kernel (2^22). */
#define MAX_PROCESSES 4194304

/* ── Alert flag bitmasks ─────────────────────────────────────────────────── */

/**
 * @defgroup alert_flags Alert bitmask flags for ProcessScoring.alert_flags
 * @{
 */
#define ALERT_PRIV_ESC    (1 << 0)  /**< uid != euid: possible privilege escalation.     */
#define ALERT_DELETED_EXE (1 << 1)  /**< Executable deleted after process launch.        */
#define ALERT_SUSP_PATH   (1 << 2)  /**< Open FD pointing to /tmp, /dev/shm, etc.       */
#define ALERT_HIGH_FD     (1 << 3)  /**< Fuzzy: open FD count in ramp 250–500.          */
#define ALERT_PTRACE      (1 << 4)  /**< Process is being traced (TracerPid != 0).       */
#define ALERT_NET_SCAN    (1 << 5)  /**< Fuzzy: active connections in ramp 25–50.        */
#define ALERT_HIGH_CPU    (1 << 6)  /**< Fuzzy: CPU usage in ramp 60–90 %.              */
#define ALERT_FORK_BOMB   (1 << 7)  /**< Fuzzy: fork rate in ramp 50–100 /s.            */
#define ALERT_HIGH_IO_W   (1 << 8)  /**< Fuzzy: write throughput in ramp 5–10 MB/s.     */
#define ALERT_HIGH_IO_R   (1 << 9)  /**< Fuzzy: read throughput in ramp 25–50 MB/s.     */
#define ALERT_ZOMBIE      (1 << 10) /**< Process state is Z: terminated but not reaped. */
#define ALERT_ZOMBIE_PARENT (1 << 11) /**< Process has unreaped zombie children (not calling wait). */
/** @} */

/* ── DIP: Named threshold constants ─────────────────────────────────────── */

#define ANOMALY_THRESHOLD       0.30f  /**< Minimum score to classify a process as suspicious. */

#define FUZZY_CPU_LOW           60.0f  /**< CPU %: ramp start.           */
#define FUZZY_CPU_HIGH          90.0f  /**< CPU %: ramp end (full weight).*/

#define FUZZY_FD_LOW           250.0f  /**< Open FDs: ramp start.         */
#define FUZZY_FD_HIGH          500.0f  /**< Open FDs: ramp end.           */

#define FUZZY_CONN_LOW          25.0f  /**< Connections: ramp start.      */
#define FUZZY_CONN_HIGH         50.0f  /**< Connections: ramp end.        */

#define FUZZY_FORK_LOW          50.0f  /**< Fork rate /s: ramp start.     */
#define FUZZY_FORK_HIGH        100.0f  /**< Fork rate /s: ramp end.       */

#define FUZZY_IO_WRITE_LOW   ( 5.0f * 1024.0f * 1024.0f)  /**< Write B/s: ramp start. */
#define FUZZY_IO_WRITE_HIGH  (10.0f * 1024.0f * 1024.0f)  /**< Write B/s: ramp end.   */

#define FUZZY_IO_READ_LOW    (25.0f * 1024.0f * 1024.0f)  /**< Read B/s: ramp start.  */
#define FUZZY_IO_READ_HIGH   (50.0f * 1024.0f * 1024.0f)  /**< Read B/s: ramp end.    */

#define MAX_SOCK_INODES 256

/* ── ISP: Domain sub-structs ─────────────────────────────────────────────── */

/** @brief Identity and permission data for a process. */
typedef struct {
    uid_t uid;              /**< Real UID.                                           */
    uid_t euid;             /**< Effective UID (differs from uid = possible escalation). */
    uid_t suid;             /**< Saved set-user-ID.                                  */
    gid_t gid;              /**< Real GID.                                           */
    gid_t egid;             /**< Effective GID.                                      */
    char  username[64];     /**< Login name of the real UID owner (empty if unknown).*/
    char  exe_path[512];    /**< Absolute path of the running binary.               */
    char  exe_hash[65];     /**< SHA-256 hash of the binary (64 hex chars + '\0'). */
    int   is_deleted_exe;   /**< 1 if the binary was deleted after launch.          */
    int   has_ptrace;       /**< 1 if TracerPid != 0 (process is being debugged).  */
} ProcessIdentity;

/** @brief CPU, memory, and I/O metrics for a process. */
typedef struct {
    float         cpuUsage;       /**< CPU usage in the last interval (%).          */
    float         rss;            /**< Resident Set Size in KB.                     */
    float         vsz;            /**< Virtual memory size in KB.                   */
    unsigned long utime;          /**< CPU ticks in user mode (cumulative).         */
    unsigned long stime;          /**< CPU ticks in kernel mode (cumulative).       */
    unsigned long prev_utime;     /**< utime from the previous snapshot (for delta).*/
    unsigned long prev_stime;     /**< stime from the previous snapshot (for delta).*/
    unsigned long fork_rate;        /**< Fork rate in calls per second.               */
    unsigned long syscall_rate;     /**< Syscall rate per second (reserved).          */
    int           zombie_child_count; /**< Number of direct children in state Z.      */
    unsigned long io_read_bytes;  /**< Bytes read accumulated since process start.  */
    unsigned long io_write_bytes; /**< Bytes written accumulated since process start.*/
    double        io_read_bps;    /**< Read rate in bytes/second (last interval).   */
    double        io_write_bps;   /**< Write rate in bytes/second (last interval).  */
} ProcessMetrics;

/** @brief Network activity data for a process. */
typedef struct {
    int  open_connections;   /**< Total active TCP/UDP connections.                 */
    int  listen_ports[32];   /**< TCP ports in LISTEN state.                       */
    int  port_count;         /**< Number of valid entries in listen_ports.         */
    char remote_ips[8][46];  /**< Remote IPs of established connections (IPv4/6). */
    int  remote_ip_count;    /**< Number of valid entries in remote_ips.           */
} ProcessNetwork;

/** @brief Open file descriptor data for a process. */
typedef struct {
    int  open_fd_count;          /**< Total number of open file descriptors.       */
    int  open_files_count;       /**< Descriptors pointing to regular files.       */
    char suspicious_paths[4][256]; /**< Up to 4 suspicious paths found in FDs.   */
} ProcessFd;

/** @brief Anomaly scoring results for a process. */
typedef struct {
    float anomaly_score;         /**< Accumulated anomaly score: 0.0 to 1.0.      */
    int   alert_flags;           /**< Bitmask of active ALERT_* flags.             */
    char  baseline_deviation[128]; /**< Space-separated list of triggered alerts. */
} ProcessScoring;

/* ── Snapshot type ───────────────────────────────────────────────────────── */

/**
 * @brief Snapshot of the set of active PIDs at a given point in time.
 */
typedef struct {
    int firstTime;           /**< 1 on the first capture, 0 afterwards.            */
    int actCount;            /**< Number of PIDs in the current snapshot.          */
    int prevCount;           /**< Number of PIDs in the previous snapshot.         */
    int *prevPids;           /**< Array of PIDs from the previous snapshot.        */
    int *actPids;            /**< Array of PIDs from the current snapshot.         */
    int act[MAX_PROCESSES];  /**< Presence map: act[pid]=1 if the PID is alive.   */
    int prev[MAX_PROCESSES]; /**< Presence map of the previous snapshot.           */
    struct timeval act_time; /**< Timestamp of the current snapshot.               */
    struct timeval prev_time;/**< Timestamp of the previous snapshot.              */
    double elapsed_ms;       /**< Milliseconds elapsed between snapshots.          */
} PidSnapshot;

/* ── Main process info aggregate ────────────────────────────────────────── */

/**
 * @brief Complete information about a Linux process at a given instant.
 *
 * Top-level fields hold identity data (pid, name, state). Domain-specific
 * data is grouped into sub-structs so callers only depend on the subset
 * they actually need.
 */
typedef struct {
    int    pid;
    int    ppid;
    char   name[256];
    char   cmdline[512];
    char   state;
    int    numThreads;
    int    childrenCount;
    float  avgCpu;
    float  avgMemory;
    unsigned long  startTime;
    unsigned long  lastSeenTime;
    struct timeval capture_time;
    double         elapsed_ms;

    ProcessIdentity identity; /**< Identity, permissions, exe info, ptrace.  */
    ProcessMetrics  metrics;  /**< CPU, memory, I/O rates.                   */
    ProcessNetwork  network;  /**< Connections, ports, remote IPs.           */
    ProcessFd       fd;       /**< Open file descriptors and suspicious paths.*/
    ProcessScoring  scoring;  /**< Anomaly score, alert flags, summary.      */
} ProcessInfo;

/* ── Process tree node (minimal data for all processes) ─────────────────── */

/**
 * @brief Minimal process record used to build the full process tree.
 *
 * Populated by analize_full() for every running process, not just suspicious ones.
 */
typedef struct {
    int   pid;
    int   ppid;
    char  name[256];
    char  state;
    int   threads;
    int   is_suspicious;  /**< 1 if anomaly_score >= ANOMALY_THRESHOLD. */
    float anomaly_score;
    float cpu_percent;
    float rss_kb;
    char  username[64];   /**< Login name of the real UID owner.        */
    int   alert_flags;    /**< Bitmask of active ALERT_* flags.         */
} ProcessTreeNode;

/* ── Analysis result ─────────────────────────────────────────────────────── */

#define NOTABLE_THRESHOLD  0.05f  /**< Minimum score to include in notable_processes.    */
#define TOP_RESOURCE_N     5      /**< Top-N processes per resource metric (CPU/RSS/IO). */

/** Sampling window between the two /proc snapshots used to compute CPU/IO rates.
 *  Shorter = faster cycles; longer = smoother CPU% readings.
 *  250 ms is the default (was 1000 ms). */
#define SAMPLE_INTERVAL_MS 50

/**
 * @brief Full output of a single analysis cycle.
 *
 * Three tiers of processes are returned:
 *   - suspicious:    anomaly_score >= ANOMALY_THRESHOLD (0.30)
 *   - notable:       NOTABLE_THRESHOLD (0.05) <= score < ANOMALY_THRESHOLD
 *   - top_resources: top-N by CPU, RSS, and I/O write, not already in the above sets
 *
 * Caller owns all memory. Release with free_analysis_result().
 */
typedef struct {
    ProcessInfo    **suspicious;          /**< Processes with score >= 0.30.           */
    int              suspicious_count;
    ProcessInfo    **notable;             /**< Processes with 0.05 <= score < 0.30.    */
    int              notable_count;
    ProcessInfo    **top_resources;       /**< Top resource consumers (CPU/RSS/IO).    */
    int              top_resources_count;
    ProcessTreeNode *tree;                /**< All processes (NULL if not requested).  */
    int              tree_count;
} AnalysisResult;

/* ── Public API ──────────────────────────────────────────────────────────── */

int            *getPids(int *count);
void            takeSnapshot(PidSnapshot *snapshot, int *pids, int count);
void            diffSnapshot(PidSnapshot *snapshot);
PidSnapshot    *initPidSnapshot(int size);
void            printPids(int *pids, int count);
ProcessInfo    *getProcessInfo(int pid, double elapsed_ms, const ProcessInfo *prev);
void            printProcessInfo(const ProcessInfo *info);
void            printProcessJson(const ProcessInfo *info);
void            printProcessAlerts(const ProcessInfo *info);
void            json_print_str(const char *s);
int             isSuspicious(ProcessInfo *info);
ProcessInfo   **analize(int *count);
ProcessInfo   **analize_ex(int *count, ProcessTreeNode **tree_out, int *tree_count);
AnalysisResult *analize_full(int include_tree);
void            free_analysis_result(AnalysisResult *r);

#endif
