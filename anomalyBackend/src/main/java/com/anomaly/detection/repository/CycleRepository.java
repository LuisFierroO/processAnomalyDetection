package com.anomaly.detection.repository;

import com.anomaly.detection.model.AnalysisCycle;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CycleRepository extends JpaRepository<AnalysisCycle, Long> {

    Optional<AnalysisCycle> findTopByOrderByReceivedAtDesc();
}
