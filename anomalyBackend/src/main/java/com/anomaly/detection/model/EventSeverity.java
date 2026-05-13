package com.anomaly.detection.model;

public enum EventSeverity {
    NOTABLE,      // score 0.30 – 0.50
    SUSPICIOUS,   // score 0.50 – 0.70
    CRITICAL      // score > 0.70
}
