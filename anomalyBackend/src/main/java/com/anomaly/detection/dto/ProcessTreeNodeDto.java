package com.anomaly.detection.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record ProcessTreeNodeDto(
        int pid,
        int ppid,
        String name,
        String state,
        int threads,
        boolean suspicious,
        @JsonProperty("anomaly_score") double anomalyScore,
        @JsonProperty("cpu_percent")   double cpuPercent,
        @JsonProperty("rss_kb")        double rssKb,
        String username
) {}
