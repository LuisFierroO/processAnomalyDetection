package com.anomaly.detection.service;

import com.anomaly.detection.dto.CycleDto;
import com.anomaly.detection.dto.ProcessDto;
import com.anomaly.detection.dto.SuspiciousEventDto;
import com.anomaly.detection.model.EventSeverity;
import com.anomaly.detection.model.SuspiciousEvent;
import com.anomaly.detection.repository.SuspiciousEventRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Service
public class SuspiciousEventService {

    private static final long   DEDUP_WINDOW_MS = 5 * 60 * 1_000L;
    private static final double CRITICAL_THRESHOLD   = 0.70;
    private static final double SUSPICIOUS_THRESHOLD = 0.50;

    private final SuspiciousEventRepository repo;
    private final SseService                sseService;

    /* key → epoch-millis of last event for that key */
    private final ConcurrentHashMap<String, Long> dedupCache = new ConcurrentHashMap<>();

    public SuspiciousEventService(SuspiciousEventRepository repo, SseService sseService) {
        this.repo       = repo;
        this.sseService = sseService;
    }

    /**
     * Called for every incoming cycle. Inspects suspicious processes and
     * archives each distinct one that hasn't been seen in the last 5 minutes.
     */
    @Transactional
    public void maybeRecord(CycleDto cycle, Long savedCycleId) {
        if (cycle.suspiciousProcesses() == null) return;
        long now = System.currentTimeMillis();

        for (ProcessDto p : cycle.suspiciousProcesses()) {
            String key = buildKey(cycle.agentId(), p);
            Long   last = dedupCache.get(key);
            if (last != null && (now - last) < DEDUP_WINDOW_MS) continue;

            SuspiciousEvent event = toEntity(p, cycle, savedCycleId, now);
            SuspiciousEvent saved = repo.save(event);
            dedupCache.put(key, now);

            sseService.broadcastNamed("alert", SuspiciousEventDto.from(saved));
        }

        evictExpiredKeys(now);
    }

    public Page<SuspiciousEventDto> findAll(int page, int size, String sort, String severity) {
        Sort s = "score".equals(sort)
            ? Sort.by(Sort.Direction.DESC, "anomalyScore")
            : Sort.by(Sort.Direction.DESC, "detectedAt");
        PageRequest pageable = PageRequest.of(page, size, s);
        Page<SuspiciousEvent> raw = "ALL".equals(severity)
            ? repo.findAll(pageable)
            : repo.findAllBySeverity(EventSeverity.valueOf(severity), pageable);
        return raw.map(SuspiciousEventDto::from);
    }

    @Transactional
    public boolean acknowledge(Long id, boolean value) {
        return repo.findById(id).map(e -> {
            e.setAcknowledged(value);
            repo.save(e);
            return true;
        }).orElse(false);
    }

    /* ── Helpers ── */

    private static String buildKey(String agentId, ProcessDto p) {
        String exeHash = (p.identity() != null && p.identity().exeHash() != null)
                         ? p.identity().exeHash() : "";
        int flags = (p.scoring() != null) ? p.scoring().alertFlags() : 0;
        return agentId + ":" + p.pid() + ":" + p.name() + ":" + exeHash + ":" + flags;
    }

    private static EventSeverity classify(double score) {
        if (score >= CRITICAL_THRESHOLD)   return EventSeverity.CRITICAL;
        if (score >= SUSPICIOUS_THRESHOLD) return EventSeverity.SUSPICIOUS;
        return EventSeverity.NOTABLE;
    }

    private static SuspiciousEvent toEntity(ProcessDto p, CycleDto cycle,
                                            Long cycleId, long epochMs) {
        SuspiciousEvent e = new SuspiciousEvent();
        e.setDetectedAt(LocalDateTime.ofInstant(Instant.ofEpochMilli(epochMs),
                                                ZoneId.systemDefault()));
        e.setAgentId(cycle.agentId());
        e.setCycleId(cycleId);
        e.setPid(p.pid());
        e.setName(p.name());
        e.setCmdline(p.cmdline());

        if (p.identity() != null) {
            e.setExePath(p.identity().exePath());
            e.setExeHash(p.identity().exeHash());
            e.setUid(p.identity().uid());
            e.setEuid(p.identity().euid());
            e.setUsername(p.identity().username());
            e.setDeletedExe(p.identity().isDeletedExe());
            e.setHasPtrace(p.identity().hasPtrace());
        }
        if (p.scoring() != null) {
            e.setAnomalyScore(p.scoring().anomalyScore());
            e.setAlertFlags(p.scoring().alertFlags());
            if (p.scoring().triggeredRules() != null) {
                String rules = p.scoring().triggeredRules().stream()
                        .map(ProcessDto.TriggeredRule::name)
                        .collect(Collectors.joining(","));
                e.setTriggeredRules(rules);
            }
        }
        if (p.metrics() != null) {
            e.setCpuPercent(p.metrics().cpuPercent());
            e.setRssKb(p.metrics().rssKb());
            e.setIoWriteBps((long) p.metrics().ioWriteBps());
        }
        if (p.network() != null) e.setOpenConnections(p.network().openConnections());
        if (p.fd()      != null) e.setOpenFdCount(p.fd().openFdCount());

        e.setSeverity(classify(e.getAnomalyScore()));
        e.setAcknowledged(false);
        return e;
    }

    private void evictExpiredKeys(long now) {
        if (dedupCache.size() < 500) return;
        dedupCache.entrySet().removeIf(entry -> (now - entry.getValue()) >= DEDUP_WINDOW_MS);
    }
}
