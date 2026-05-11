package com.anomaly.detection.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public record ProcessDto(
        int pid,
        int ppid,
        String name,
        String cmdline,
        String state,
        int threads,
        Identity identity,
        Metrics metrics,
        Network network,
        Fd fd,
        Scoring scoring,
        @JsonProperty("elapsed_ms") double elapsedMs
) {
    public record Identity(
            int uid,
            int euid,
            int suid,
            int gid,
            int egid,
            String username,
            @JsonProperty("exe_path")       String exePath,
            @JsonProperty("exe_hash")       String exeHash,
            @JsonProperty("is_deleted_exe") boolean isDeletedExe,
            @JsonProperty("has_ptrace")     boolean hasPtrace
    ) {}

    public record Metrics(
            @JsonProperty("cpu_percent")     double cpuPercent,
            @JsonProperty("rss_kb")          double rssKb,
            @JsonProperty("vsz_kb")          double vszKb,
            @JsonProperty("io_read_bps")     double ioReadBps,
            @JsonProperty("io_write_bps")    double ioWriteBps,
            @JsonProperty("io_read_bytes")   long ioReadBytes,
            @JsonProperty("io_write_bytes")  long ioWriteBytes,
            long utime,
            long stime,
            @JsonProperty("fork_rate")       long forkRate
    ) {}

    public record Network(
            @JsonProperty("open_connections") int openConnections,
            @JsonProperty("listen_ports")     List<Integer> listenPorts,
            @JsonProperty("remote_ips")       List<String> remoteIps
    ) {}

    public record Fd(
            @JsonProperty("open_fd_count")     int openFdCount,
            @JsonProperty("open_files_count")  int openFilesCount,
            @JsonProperty("suspicious_paths")  List<String> suspiciousPaths
    ) {}

    public record TriggeredRule(
            String name,
            String type,
            double membership,
            @JsonProperty("contribution_pct") double contributionPct
    ) {}

    public record Scoring(
            @JsonProperty("anomaly_score")    double anomalyScore,
            @JsonProperty("alert_flags")      int alertFlags,
            @JsonProperty("triggered_rules")  List<TriggeredRule> triggeredRules
    ) {}
}
