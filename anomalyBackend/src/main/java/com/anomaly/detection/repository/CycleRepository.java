package com.anomaly.detection.repository;

import com.anomaly.detection.model.AnalysisCycle;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface CycleRepository extends JpaRepository<AnalysisCycle, Long> {

    Optional<AnalysisCycle> findTopByOrderByReceivedAtDesc();

    @Query("SELECT c.id FROM AnalysisCycle c ORDER BY c.id ASC")
    List<Long> findOldestIds(Pageable pageable);
}
