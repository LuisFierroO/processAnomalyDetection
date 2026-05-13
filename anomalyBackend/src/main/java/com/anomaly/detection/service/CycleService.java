package com.anomaly.detection.service;

import com.anomaly.detection.dto.CycleDto;
import com.anomaly.detection.dto.ProcessDto;
import com.anomaly.detection.dto.ProcessTreeNodeDto;
import com.anomaly.detection.model.*;
import com.anomaly.detection.repository.CycleRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class CycleService {

    private static final Logger log = LoggerFactory.getLogger(CycleService.class);

    @Value("${retention.max-cycles:50000}")
    private int maxCycles;

    private final CycleRepository        cycleRepository;
    private final SseService             sseService;
    private final SuspiciousEventService eventService;

    public CycleService(CycleRepository cycleRepository, SseService sseService,
                        SuspiciousEventService eventService) {
        this.cycleRepository = cycleRepository;
        this.sseService      = sseService;
        this.eventService    = eventService;
    }

    @Transactional
    public AnalysisCycle saveCycle(CycleDto dto) {
        AnalysisCycle cycle = new AnalysisCycle();
        cycle.setAgentId(dto.agentId());
        cycle.setCycleNumber(dto.cycleNumber());
        cycle.setTimestamp(dto.timestamp());
        cycle.setTotalProcesses(dto.totalProcesses());
        cycle.setSuspiciousCount(dto.suspiciousCount());
        cycle.setNotableCount(dto.notableCount());
        cycle.setTopResourcesCount(dto.topResourcesCount());
        cycle.setReceivedAt(LocalDateTime.now());

        if (dto.suspiciousProcesses() != null)
            dto.suspiciousProcesses().forEach(p -> addProcess(cycle, p, ProcessTier.SUSPICIOUS));

        if (dto.notableProcesses() != null)
            dto.notableProcesses().forEach(p -> addProcess(cycle, p, ProcessTier.NOTABLE));

        if (dto.topResources() != null)
            dto.topResources().forEach(p -> addProcess(cycle, p, ProcessTier.TOP_RESOURCE));

        if (dto.processTree() != null)
            dto.processTree().forEach(n -> addTreeNode(cycle, n));

        AnalysisCycle saved = cycleRepository.save(cycle);

        eventService.maybeRecord(dto, saved.getId());

        sseService.broadcast(new LiveCycleEvent(
                saved.getId(),
                saved.getAgentId(),
                saved.getCycleNumber(),
                saved.getTimestamp(),
                saved.getTotalProcesses(),
                saved.getSuspiciousCount(),
                saved.getNotableCount(),
                saved.getTopResourcesCount(),
                saved.getProcessTree()
        ));

        return saved;
    }

    public List<AnalysisCycle> findAll() {
        return cycleRepository.findAll();
    }

    public Optional<AnalysisCycle> findById(Long id) {
        return cycleRepository.findById(id);
    }

    public Optional<AnalysisCycle> findLatest() {
        return cycleRepository.findTopByOrderByReceivedAtDesc();
    }

    /* ── Helpers ── */

    private void addProcess(AnalysisCycle cycle, ProcessDto dto, ProcessTier tier) {
        ProcessRecord r = new ProcessRecord();
        r.setCycle(cycle);
        r.setTier(tier);
        r.setPid(dto.pid());
        r.setPpid(dto.ppid());
        r.setName(dto.name());
        r.setCmdline(dto.cmdline());
        r.setState(dto.state());
        r.setThreads(dto.threads());

        if (dto.identity() != null) {
            r.setUid(dto.identity().uid());
            r.setEuid(dto.identity().euid());
            r.setUsername(dto.identity().username());
            r.setExePath(dto.identity().exePath());
            r.setExeHash(dto.identity().exeHash());
            r.setDeletedExe(dto.identity().isDeletedExe());
            r.setHasPtrace(dto.identity().hasPtrace());
        }

        if (dto.metrics() != null) {
            r.setCpuPercent(dto.metrics().cpuPercent());
            r.setRssKb(dto.metrics().rssKb());
            r.setVszKb(dto.metrics().vszKb());
            r.setIoReadBps(dto.metrics().ioReadBps());
            r.setIoWriteBps(dto.metrics().ioWriteBps());
        }

        if (dto.network() != null)
            r.setOpenConnections(dto.network().openConnections());

        if (dto.fd() != null)
            r.setOpenFdCount(dto.fd().openFdCount());

        if (dto.scoring() != null) {
            r.setAnomalyScore(dto.scoring().anomalyScore());
            r.setAlertFlags(dto.scoring().alertFlags());
            if (dto.scoring().triggeredRules() != null) {
                String rules = dto.scoring().triggeredRules().stream()
                        .map(ProcessDto.TriggeredRule::name)
                        .collect(Collectors.joining(","));
                r.setTriggeredRules(rules);
            }
        }

        cycle.getProcesses().add(r);
    }

    @Scheduled(fixedDelay = 30_000)
    @Transactional
    public void pruneOldCycles() {
        long count = cycleRepository.count();
        if (count <= maxCycles) return;
        int toDelete = (int) Math.min(count - maxCycles, 1000);
        List<Long> ids = cycleRepository.findOldestIds(PageRequest.of(0, toDelete));
        if (!ids.isEmpty()) {
            cycleRepository.deleteAllById(ids);
            log.debug("Pruned {} old cycles (total was {})", ids.size(), count);
        }
    }

    private void addTreeNode(AnalysisCycle cycle, ProcessTreeNodeDto dto) {
        ProcessTreeRecord n = new ProcessTreeRecord();
        n.setCycle(cycle);
        n.setPid(dto.pid());
        n.setPpid(dto.ppid());
        n.setName(dto.name());
        n.setState(dto.state());
        n.setThreads(dto.threads());
        n.setSuspicious(dto.suspicious());
        n.setAnomalyScore(dto.anomalyScore());
        n.setCpuPercent(dto.cpuPercent());
        n.setRssKb(dto.rssKb());
        n.setAlertFlags(dto.alertFlags());
        n.setUsername(dto.username());
        cycle.getProcessTree().add(n);
    }

    private record LiveCycleEvent(
            Long id,
            String agentId,
            int cycleNumber,
            double timestamp,
            int totalProcesses,
            int suspiciousCount,
            int notableCount,
            int topResourcesCount,
            List<ProcessTreeRecord> tree
    ) {}
}
