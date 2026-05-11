package com.anomaly.detection.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;

@Entity
@Table(name = "process_tree_record")
public class ProcessTreeRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @JsonIgnore
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "cycle_id", nullable = false)
    private AnalysisCycle cycle;

    private int pid;
    private int ppid;
    private String name;
    private String state;
    private int threads;
    private boolean suspicious;
    private double anomalyScore;
    private double cpuPercent;
    private double rssKb;

    @Column(length = 64)
    private String username;

    public ProcessTreeRecord() {}

    public Long getId() { return id; }
    public AnalysisCycle getCycle() { return cycle; }
    public void setCycle(AnalysisCycle cycle) { this.cycle = cycle; }
    public int getPid() { return pid; }
    public void setPid(int pid) { this.pid = pid; }
    public int getPpid() { return ppid; }
    public void setPpid(int ppid) { this.ppid = ppid; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getState() { return state; }
    public void setState(String state) { this.state = state; }
    public int getThreads() { return threads; }
    public void setThreads(int threads) { this.threads = threads; }
    public boolean isSuspicious() { return suspicious; }
    public void setSuspicious(boolean suspicious) { this.suspicious = suspicious; }
    public double getAnomalyScore() { return anomalyScore; }
    public void setAnomalyScore(double anomalyScore) { this.anomalyScore = anomalyScore; }
    public double getCpuPercent() { return cpuPercent; }
    public void setCpuPercent(double cpuPercent) { this.cpuPercent = cpuPercent; }
    public double getRssKb() { return rssKb; }
    public void setRssKb(double rssKb) { this.rssKb = rssKb; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
}
