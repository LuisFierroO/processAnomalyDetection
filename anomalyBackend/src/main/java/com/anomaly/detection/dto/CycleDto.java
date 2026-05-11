package com.anomaly.detection.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public record CycleDto(
        @JsonProperty("schema_version")    String schemaVersion,
        @JsonProperty("agent_id")          String agentId,
        @JsonProperty("cycle")             int cycleNumber,
        double timestamp,
        @JsonProperty("total_processes")   int totalProcesses,
        @JsonProperty("suspicious_count")  int suspiciousCount,
        @JsonProperty("notable_count")     int notableCount,
        @JsonProperty("top_resources_count") int topResourcesCount,
        @JsonProperty("process_tree")      List<ProcessTreeNodeDto> processTree,
        @JsonProperty("suspicious_processes") List<ProcessDto> suspiciousProcesses,
        @JsonProperty("notable_processes") List<ProcessDto> notableProcesses,
        @JsonProperty("top_resources")     List<ProcessDto> topResources
) {}
