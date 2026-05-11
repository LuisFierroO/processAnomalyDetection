package com.anomaly.detection.model;

import jakarta.persistence.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "analysis_cycle")
public class AnalysisCycle {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String agentId;
    private int cycleNumber;
    private double timestamp;
    private int totalProcesses;
    private int suspiciousCount;
    private int notableCount;
    private int topResourcesCount;

    @Column(nullable = false)
    private LocalDateTime receivedAt;

    @OneToMany(mappedBy = "cycle", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ProcessRecord> processes = new ArrayList<>();

    @OneToMany(mappedBy = "cycle", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ProcessTreeRecord> processTree = new ArrayList<>();

    public AnalysisCycle() {}

    public Long getId() { return id; }
    public String getAgentId() { return agentId; }
    public void setAgentId(String agentId) { this.agentId = agentId; }
    public int getCycleNumber() { return cycleNumber; }
    public void setCycleNumber(int cycleNumber) { this.cycleNumber = cycleNumber; }
    public double getTimestamp() { return timestamp; }
    public void setTimestamp(double timestamp) { this.timestamp = timestamp; }
    public int getTotalProcesses() { return totalProcesses; }
    public void setTotalProcesses(int totalProcesses) { this.totalProcesses = totalProcesses; }
    public int getSuspiciousCount() { return suspiciousCount; }
    public void setSuspiciousCount(int suspiciousCount) { this.suspiciousCount = suspiciousCount; }
    public int getNotableCount() { return notableCount; }
    public void setNotableCount(int notableCount) { this.notableCount = notableCount; }
    public int getTopResourcesCount() { return topResourcesCount; }
    public void setTopResourcesCount(int topResourcesCount) { this.topResourcesCount = topResourcesCount; }
    public LocalDateTime getReceivedAt() { return receivedAt; }
    public void setReceivedAt(LocalDateTime receivedAt) { this.receivedAt = receivedAt; }
    public List<ProcessRecord> getProcesses() { return processes; }
    public List<ProcessTreeRecord> getProcessTree() { return processTree; }
}
