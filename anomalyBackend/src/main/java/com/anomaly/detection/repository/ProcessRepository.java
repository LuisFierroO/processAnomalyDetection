package com.anomaly.detection.repository;

import com.anomaly.detection.model.ProcessRecord;
import com.anomaly.detection.model.ProcessTier;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ProcessRepository extends JpaRepository<ProcessRecord, Long> {

    List<ProcessRecord> findByCycle_IdAndTier(Long cycleId, ProcessTier tier);

    List<ProcessRecord> findByTierOrderByAnomalyScoreDesc(ProcessTier tier);
}
