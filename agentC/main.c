/**
 * @file main.c
 * @brief Entry point for the Linux process anomaly detection agent.
 *
 * Supports three modes:
 *   - Default: runs one or more analysis cycles and reports suspicious processes.
 *   - Single-process (-i PID): prints all collected metrics for one PID.
 *   - Daemon-friendly: --cycles N --interval-ms M loops N times with M ms pause
 *     between cycles, emitting one JSON envelope per cycle to stdout so that a
 *     parent process (e.g. Java backend) can read and process each cycle independently.
 *
 * @author Luis Fierro <luisfierroor@gmail.com>
 * @date 2026
 *
 * @note Development assisted by Claude (Anthropic) — claude.ai/code
 */

#include "processAgent.h"

void printHelp(const char *prog);

/* ── Signal handling ─────────────────────────────────────────────────────── */

static volatile sig_atomic_t g_stop = 0;

/**
 * @brief Signal handler for SIGTERM and SIGINT.
 *
 * Sets g_stop so the main loop exits cleanly after the current cycle
 * completes, rather than terminating mid-write.
 */
static void handle_stop(int sig) {
     (void)sig; g_stop = 1;
}

/* ── Flag parsing helpers ────────────────────────────────────────────────── */

/**
 * @brief Returns 1 if short_f or long_f appears anywhere in argv.
 *
 * @param argc    Argument count from main().
 * @param argv    Argument vector from main().
 * @param short_f Short flag string (e.g. "-j").
 * @param long_f  Long flag string  (e.g. "--json").
 * @return 1 if either form is present, 0 otherwise.
 */
static int has_flag(int argc, char *argv[], const char *short_f, const char *long_f) {
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], short_f) == 0 || strcmp(argv[i], long_f) == 0)
            return 1;
    return 0;
}

/**
 * @brief Returns the integer value of the argument following short_f or long_f.
 *
 * Scans argv for the first occurrence of either flag form and converts the
 * next token with atoi(). Returns default_val when the flag is absent or
 * the parsed value is non-positive.
 *
 * @param argc        Argument count from main().
 * @param argv        Argument vector from main().
 * @param short_f     Short flag string (e.g. "-n").
 * @param long_f      Long flag string  (e.g. "--cycles").
 * @param default_val Value to return when the flag is absent.
 * @return Parsed positive integer, or default_val.
 */
static int get_int_arg(int argc, char *argv[], const char *short_f, const char *long_f, int default_val){
    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], short_f) == 0 || strcmp(argv[i], long_f) == 0) {
            int v = atoi(argv[i + 1]);
            return v > 0 ? v : default_val;
        }
    }
    return default_val;
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {

    /* Install handlers so a SIGTERM/SIGINT finishes the current cycle cleanly. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_stop;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);

    int json_mode   = has_flag(argc, argv, "-j", "--json");
    int include_all = has_flag(argc, argv, "-a", "--include-all");
    int cycles      = get_int_arg(argc, argv, "-n", "--cycles",      1);
    int interval_ms = get_int_arg(argc, argv, "-w", "--interval-ms", 0);
    int want_help   = has_flag(argc, argv, "-h", "--help");
    int inspect     = has_flag(argc, argv, "-i", "--inspect");

    if (argc > 1) {

        if (want_help) {
            printHelp(argv[0]);
            return 0;
        }

        if (inspect) {
            int pid = 0;
            for (int i = 1; i < argc - 1; i++) {
                if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--inspect") == 0) {
                    pid = atoi(argv[i + 1]);
                    break;
                }
            }
            if (pid <= 0) {
                fprintf(stderr, "Error: -i requires a valid PID argument.\n");
                fprintf(stderr, "Usage: %s -i <PID> [--json]\n", argv[0]);
                return 1;
            }
            ProcessInfo *info = getProcessInfo(pid, 0.0, NULL);
            if (!info) {
                fprintf(stderr, "Error: could not read process %d "
                        "(may have exited or insufficient permissions).\n", pid);
                return 1;
            }
            isSuspicious(info);
            if (json_mode) {
                printProcessJson(info);
                putchar('\n');
            } else {
                printProcessInfo(info);
            }
            free(info);
            return 0;
        }

        /* Reject truly unknown flags. */
        for (int i = 1; i < argc; i++) {
            const char *a = argv[i];
            if (strcmp(a, "-j") == 0 || strcmp(a, "--json") == 0) 
                continue;
            if (strcmp(a, "-a") == 0 || strcmp(a, "--include-all") == 0) 
                continue;
            if ((strcmp(a, "-n") == 0 || strcmp(a, "--cycles") == 0) && i + 1 < argc) {
                    i++;
                    continue; 
            }
            if ((strcmp(a, "-w") == 0 || strcmp(a, "--interval-ms") == 0) && i + 1 < argc){ 
                    i++; 
                    continue; 
                
            }
            fprintf(stderr, "Unknown option: %s\n", a);
            fprintf(stderr, "Run '%s --help' for usage information.\n", argv[0]);
            return 1;
        }
    }

    /* ── Multi-cycle analysis loop ──────────────────────────────────────── */

    char agent_id[256];
    if (gethostname(agent_id, sizeof(agent_id)) != 0)
        strncpy(agent_id, "unknown", sizeof(agent_id) - 1);

    for (int cycle = 1; cycle <= cycles && !g_stop; cycle++) {
        struct timeval ts;
        gettimeofday(&ts, NULL);

        AnalysisResult *analysis_result = analize_full(include_all);
        if (!analysis_result) {
            fprintf(stderr, "Error: analysis failed.\n");
            return 1;
        }

        if (json_mode) {
            printf("{\n");
            printf("  \"schema_version\": \"1.0\",\n");
            printf("  \"agent_id\": "); json_print_str(agent_id); printf(",\n");
            printf("  \"cycle\": %d,\n", cycle);
            printf("  \"timestamp\": %ld.%06ld,\n",
                   (long)ts.tv_sec, (long)ts.tv_usec);
            printf("  \"total_processes\": %d,\n",    analysis_result->tree_count);
            printf("  \"suspicious_count\": %d,\n",   analysis_result->suspicious_count);
            printf("  \"notable_count\": %d,\n",      analysis_result->notable_count);
            printf("  \"top_resources_count\": %d",   analysis_result->top_resources_count);

            if (analysis_result->tree) {
                printf(",\n  \"process_tree\": [");
                for (int i = 0; i < analysis_result->tree_count; i++) {
                    if (i > 0) printf(",");
                    printf("\n    {\"pid\": %d, \"ppid\": %d, \"name\": ",
                           analysis_result->tree[i].pid, analysis_result->tree[i].ppid);
                    json_print_str(analysis_result->tree[i].name);
                    printf(", \"state\": \"%c\", \"threads\": %d,"
                           " \"suspicious\": %s, \"anomaly_score\": %.4f,"
                           " \"cpu_percent\": %.2f, \"rss_kb\": %.0f,"
                           " \"alert_flags\": %d, \"username\": ",
                            analysis_result->tree[i].state,
                            analysis_result->tree[i].threads,
                            analysis_result->tree[i].is_suspicious ? "true" : "false",
                            analysis_result->tree[i].anomaly_score,
                            analysis_result->tree[i].cpu_percent,
                            analysis_result->tree[i].rss_kb,
                            analysis_result->tree[i].alert_flags);
                    json_print_str(analysis_result->tree[i].username[0] ? analysis_result->tree[i].username : "");
                    printf("}");
                }
                if (analysis_result->tree_count > 0) printf("\n  ");
                printf("]");
            }
            /* suspicious_processes */
            printf(",\n  \"suspicious_processes\": [");
            for (int i = 0; i < analysis_result->suspicious_count; i++) {
                if (i > 0) printf(",");
                printf("\n    ");
                printProcessJson(analysis_result->suspicious[i]);
            }
            if (analysis_result->suspicious_count > 0) printf("\n  ");
            printf("]");
            /* notable_processes */
            printf(",\n  \"notable_processes\": [");
            for (int i = 0; i < analysis_result->notable_count; i++) {
                if (i > 0) printf(",");
                printf("\n    ");
                printProcessJson(analysis_result->notable[i]);
            }
            if (analysis_result->notable_count > 0) printf("\n  ");
            printf("]");

            /* top_resources */
            printf(",\n  \"top_resources\": [");
            for (int i = 0; i < analysis_result->top_resources_count; i++) {
                if (i > 0) printf(",");
                printf("\n    ");
                printProcessJson(analysis_result->top_resources[i]);
            }
            if (analysis_result->top_resources_count > 0) printf("\n  ");
            printf("]\n}\n");
            fflush(stdout);
        } else {
            if (analysis_result->suspicious_count == 0 && analysis_result->notable_count == 0
                && analysis_result->top_resources_count == 0) {
                printf("No processes of interest detected.\n");
            } else {
                if (analysis_result->suspicious_count > 0) {
                    printf("\n=== Suspicious processes (%d) ===\n\n",
                           analysis_result->suspicious_count);
                    for (int i = 0; i < analysis_result->suspicious_count; i++) {
                        printProcessAlerts(analysis_result->suspicious[i]);
                        printProcessInfo(analysis_result->suspicious[i]);
                    }
                }
                if (analysis_result->notable_count > 0) {
                    printf("\n=== Notable processes — score %.2f to %.2f (%d) ===\n\n",
                           NOTABLE_THRESHOLD, ANOMALY_THRESHOLD, analysis_result->notable_count);
                    for (int i = 0; i < analysis_result->notable_count; i++) {
                        printProcessAlerts(analysis_result->notable[i]);
                        printProcessInfo(analysis_result->notable[i]);
                    }
                }
                if (analysis_result->top_resources_count > 0) {
                    printf("\n=== Top resource consumers (%d) ===\n\n",
                           analysis_result->top_resources_count);
                    for (int i = 0; i < analysis_result->top_resources_count; i++)
                        printProcessInfo(analysis_result->top_resources[i]);
                }
            }
        }

        free_analysis_result(analysis_result);

        if (!g_stop && cycle < cycles && interval_ms > 0) {
            struct timespec ts_sleep = {
                interval_ms / 1000,
                (long)(interval_ms % 1000) * 1000000L
            };
            nanosleep(&ts_sleep, NULL);
        }
    }

    return 0;
}

/**
 * @brief Prints usage information to stdout.
 */
void printHelp(const char *prog) {
    printf(
        "Usage: %s [OPTION]...\n"
        "\n"
        "Linux process anomaly detection agent.\n"
        "Reads metrics from /proc and scores each process using fuzzy logic.\n"
        "Processes with anomaly_score >= 0.30 are reported as suspicious.\n"
        "\n"
        "Options:\n"
        "  (none)                   Run one analysis cycle over all running processes.\n"
        "  -i, --inspect <PID>      Inspect a single process and print all metrics.\n"
        "  -j, --json               Output results as JSON (one envelope per cycle).\n"
        "  -n, --cycles <N>         Run N analysis cycles then exit  (default: 1).\n"
        "  -w, --interval-ms <N>    Sleep N ms between cycles        (default: 0).\n"
        "                           Total period per cycle: ~1000 ms (analysis) + N ms.\n"
        "  -a, --include-all        Add process_tree array to JSON with all processes.\n"
        "  -h, --help               Show this help message and exit.\n"
        "\n"
        "Alert flags (binary — triggered or not):\n"
        "  PRIV_ESC      uid != euid: possible privilege escalation  (+35%%)\n"
        "  DELETED_EXE   Executable deleted after launch             (+40%%)\n"
        "  PTRACE        Process is being traced (TracerPid != 0)    (+20%%)\n"
        "  SUSP_PATH     Open FD pointing to /tmp, /dev/shm, etc.   (+15%%)\n"
        "  ZOMBIE        State Z: terminated but parent not waiting  (+35%%)\n"
        "  ZOMBIE_PARENT Has unreaped zombie children (not calling wait) (+40%%)\n"
        "\n"
        "Alert flags (fuzzy — weight proportional to metric value):\n"
        "  HIGH_FD       Open file descriptors  ramp: 250 → 500     (max +15%%)\n"
        "  NET_SCAN      Active connections      ramp:  25 →  50     (max +10%%)\n"
        "  HIGH_CPU      CPU usage              ramp:  60%% →  90%%   (max +10%%)\n"
        "  FORK_BOMB     Fork rate              ramp:  50 → 100 /s  (max +25%%)\n"
        "  HIGH_IO_W     Write throughput        ramp:   5 →  10 MB/s(max +20%%)\n"
        "  HIGH_IO_R     Read throughput         ramp:  25 →  50 MB/s(max +10%%)\n"
        "\n"
        "Output symbols:\n"
        "  [!]  Binary alert fired at full weight\n"
        "  [~]  Fuzzy alert fired with partial weight (shows μ value)\n"
        "\n"
        "Examples:\n"
        "  %s                              # one cycle, plain text\n"
        "  %s --json                       # one cycle, JSON envelope\n"
        "  %s --json --include-all         # one cycle, JSON + full process tree\n"
        "  %s -n 6 -w 9000 --json -a      # 6 cycles every ~10 s, JSON + tree\n"
        "  %s -i 1234                      # inspect PID 1234\n"
        "  %s -i 1234 --json              # inspect PID 1234, JSON output\n"
        "\n"
        "Note: reading /proc/<pid>/io requires root or the process owner.\n",
        prog, prog, prog, prog, prog, prog, prog
    );
}
