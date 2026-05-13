package com.anomaly.detection.dto;

import com.anomaly.detection.model.SuspiciousEvent;

public record SuspiciousEventDto(
        Long    id,
        String  detectedAt,
        String  agentId,
        Long    cycleId,
        int     pid,
        String  name,
        String  cmdline,
        String  exePath,
        String  exeHash,
        int     uid,
        int     euid,
        String  username,
        boolean isDeletedExe,
        boolean hasPtrace,
        double  anomalyScore,
        int     alertFlags,
        String  triggeredRules,
        double  cpuPercent,
        double  rssKb,
        long    ioWriteBps,
        int     openConnections,
        int     openFdCount,
        String  severity,
        boolean isAcknowledged,
        String  notes
) {
    public static SuspiciousEventDto from(SuspiciousEvent e) {
        return new SuspiciousEventDto(
                e.getId(),
                e.getDetectedAt().toString(),
                e.getAgentId(),
                e.getCycleId(),
                e.getPid(),
                e.getName(),
                e.getCmdline(),
                e.getExePath(),
                e.getExeHash(),
                e.getUid(),
                e.getEuid(),
                e.getUsername(),
                e.isDeletedExe(),
                e.isHasPtrace(),
                e.getAnomalyScore(),
                e.getAlertFlags(),
                e.getTriggeredRules(),
                e.getCpuPercent(),
                e.getRssKb(),
                e.getIoWriteBps(),
                e.getOpenConnections(),
                e.getOpenFdCount(),
                e.getSeverity().name(),
                e.isAcknowledged(),
                e.getNotes()
        );
    }
}
