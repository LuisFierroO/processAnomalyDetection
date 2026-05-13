package com.anomaly.detection.repository;

import com.anomaly.detection.model.EventSeverity;
import com.anomaly.detection.model.SuspiciousEvent;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SuspiciousEventRepository extends JpaRepository<SuspiciousEvent, Long> {

    Page<SuspiciousEvent> findAllBySeverity(EventSeverity severity, Pageable pageable);
}
