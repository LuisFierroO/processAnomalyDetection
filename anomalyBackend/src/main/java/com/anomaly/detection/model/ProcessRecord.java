package com.anomaly.detection.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;

@Entity
@Table(name = "process_record")
public class ProcessRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @JsonIgnore
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "cycle_id", nullable = false)
    private AnalysisCycle cycle;

    @Enumerated(EnumType.STRING)
    private ProcessTier tier;

    /* Core */
    private int pid;
    private int ppid;
    private String name;

    @Column(length = 1024)
    private String cmdline;

    private String state;
    private int threads;

    /* Identity */
    private int uid;
    private int euid;

    @Column(length = 64)
    private String username;

    @Column(length = 512)
    private String exePath;

    @Column(length = 64)
    private String exeHash;

    private boolean isDeletedExe;
    private boolean hasPtrace;

    /* Metrics */
    private double cpuPercent;
    private double rssKb;
    private double vszKb;
    private double ioReadBps;
    private double ioWriteBps;

    /* Network */
    private int openConnections;

    /* FD */
    private int openFdCount;

    /* Scoring */
    private double anomalyScore;
    private int alertFlags;

    /* Triggered rules stored as compact string: "HIGH_CPU,DELETED_EXE" */
    @Column(length = 256)
    private String triggeredRules;

    public ProcessRecord() {}

    public Long getId() { return id; }
    public AnalysisCycle getCycle() { return cycle; }
    public void setCycle(AnalysisCycle cycle) { this.cycle = cycle; }
    public ProcessTier getTier() { return tier; }
    public void setTier(ProcessTier tier) { this.tier = tier; }
    public int getPid() { return pid; }
    public void setPid(int pid) { this.pid = pid; }
    public int getPpid() { return ppid; }
    public void setPpid(int ppid) { this.ppid = ppid; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getCmdline() { return cmdline; }
    public void setCmdline(String cmdline) { this.cmdline = cmdline; }
    public String getState() { return state; }
    public void setState(String state) { this.state = state; }
    public int getThreads() { return threads; }
    public void setThreads(int threads) { this.threads = threads; }
    public int getUid() { return uid; }
    public void setUid(int uid) { this.uid = uid; }
    public int getEuid() { return euid; }
    public void setEuid(int euid) { this.euid = euid; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getExePath() { return exePath; }
    public void setExePath(String exePath) { this.exePath = exePath; }
    public String getExeHash() { return exeHash; }
    public void setExeHash(String exeHash) { this.exeHash = exeHash; }
    public boolean isDeletedExe() { return isDeletedExe; }
    public void setDeletedExe(boolean deletedExe) { isDeletedExe = deletedExe; }
    public boolean isHasPtrace() { return hasPtrace; }
    public void setHasPtrace(boolean hasPtrace) { this.hasPtrace = hasPtrace; }
    public double getCpuPercent() { return cpuPercent; }
    public void setCpuPercent(double cpuPercent) { this.cpuPercent = cpuPercent; }
    public double getRssKb() { return rssKb; }
    public void setRssKb(double rssKb) { this.rssKb = rssKb; }
    public double getVszKb() { return vszKb; }
    public void setVszKb(double vszKb) { this.vszKb = vszKb; }
    public double getIoReadBps() { return ioReadBps; }
    public void setIoReadBps(double ioReadBps) { this.ioReadBps = ioReadBps; }
    public double getIoWriteBps() { return ioWriteBps; }
    public void setIoWriteBps(double ioWriteBps) { this.ioWriteBps = ioWriteBps; }
    public int getOpenConnections() { return openConnections; }
    public void setOpenConnections(int openConnections) { this.openConnections = openConnections; }
    public int getOpenFdCount() { return openFdCount; }
    public void setOpenFdCount(int openFdCount) { this.openFdCount = openFdCount; }
    public double getAnomalyScore() { return anomalyScore; }
    public void setAnomalyScore(double anomalyScore) { this.anomalyScore = anomalyScore; }
    public int getAlertFlags() { return alertFlags; }
    public void setAlertFlags(int alertFlags) { this.alertFlags = alertFlags; }
    public String getTriggeredRules() { return triggeredRules; }
    public void setTriggeredRules(String triggeredRules) { this.triggeredRules = triggeredRules; }
}
