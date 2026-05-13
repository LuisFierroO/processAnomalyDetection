package com.anomaly.detection.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "suspicious_event",
       indexes = @Index(name = "idx_event_detected_at", columnList = "detectedAt"))
public class SuspiciousEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private LocalDateTime detectedAt;

    private String agentId;
    private Long   cycleId;

    /* Process identity */
    private int    pid;
    private String name;

    @Column(length = 1024)
    private String cmdline;

    @Column(length = 512)
    private String exePath;

    @Column(length = 64)
    private String exeHash;

    private int     uid;
    private int     euid;

    @Column(length = 64)
    private String  username;

    private boolean isDeletedExe;
    private boolean hasPtrace;

    /* Scoring */
    private double  anomalyScore;
    private int     alertFlags;

    @Column(length = 256)
    private String  triggeredRules;

    /* Metrics */
    private double  cpuPercent;
    private double  rssKb;
    private long    ioWriteBps;
    private int     openConnections;
    private int     openFdCount;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private EventSeverity severity;

    private boolean isAcknowledged;

    @Column(length = 512)
    private String notes;

    public SuspiciousEvent() {}

    public Long getId()                        { return id; }
    public LocalDateTime getDetectedAt()       { return detectedAt; }
    public void setDetectedAt(LocalDateTime v) { this.detectedAt = v; }
    public String getAgentId()                 { return agentId; }
    public void setAgentId(String v)           { this.agentId = v; }
    public Long getCycleId()                   { return cycleId; }
    public void setCycleId(Long v)             { this.cycleId = v; }
    public int getPid()                        { return pid; }
    public void setPid(int v)                  { this.pid = v; }
    public String getName()                    { return name; }
    public void setName(String v)              { this.name = v; }
    public String getCmdline()                 { return cmdline; }
    public void setCmdline(String v)           { this.cmdline = v; }
    public String getExePath()                 { return exePath; }
    public void setExePath(String v)           { this.exePath = v; }
    public String getExeHash()                 { return exeHash; }
    public void setExeHash(String v)           { this.exeHash = v; }
    public int getUid()                        { return uid; }
    public void setUid(int v)                  { this.uid = v; }
    public int getEuid()                       { return euid; }
    public void setEuid(int v)                 { this.euid = v; }
    public String getUsername()                { return username; }
    public void setUsername(String v)          { this.username = v; }
    public boolean isDeletedExe()              { return isDeletedExe; }
    public void setDeletedExe(boolean v)       { this.isDeletedExe = v; }
    public boolean isHasPtrace()               { return hasPtrace; }
    public void setHasPtrace(boolean v)        { this.hasPtrace = v; }
    public double getAnomalyScore()            { return anomalyScore; }
    public void setAnomalyScore(double v)      { this.anomalyScore = v; }
    public int getAlertFlags()                 { return alertFlags; }
    public void setAlertFlags(int v)           { this.alertFlags = v; }
    public String getTriggeredRules()          { return triggeredRules; }
    public void setTriggeredRules(String v)    { this.triggeredRules = v; }
    public double getCpuPercent()              { return cpuPercent; }
    public void setCpuPercent(double v)        { this.cpuPercent = v; }
    public double getRssKb()                   { return rssKb; }
    public void setRssKb(double v)             { this.rssKb = v; }
    public long getIoWriteBps()                { return ioWriteBps; }
    public void setIoWriteBps(long v)          { this.ioWriteBps = v; }
    public int getOpenConnections()            { return openConnections; }
    public void setOpenConnections(int v)      { this.openConnections = v; }
    public int getOpenFdCount()                { return openFdCount; }
    public void setOpenFdCount(int v)          { this.openFdCount = v; }
    public EventSeverity getSeverity()         { return severity; }
    public void setSeverity(EventSeverity v)   { this.severity = v; }
    public boolean isAcknowledged()            { return isAcknowledged; }
    public void setAcknowledged(boolean v)     { this.isAcknowledged = v; }
    public String getNotes()                   { return notes; }
    public void setNotes(String v)             { this.notes = v; }
}
