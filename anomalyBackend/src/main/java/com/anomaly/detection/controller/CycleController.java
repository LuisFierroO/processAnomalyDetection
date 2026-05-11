package com.anomaly.detection.controller;

import com.anomaly.detection.dto.CycleDto;
import com.anomaly.detection.model.AnalysisCycle;
import com.anomaly.detection.model.ProcessRecord;
import com.anomaly.detection.model.ProcessTreeRecord;
import com.anomaly.detection.service.CycleService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/cycles")
@CrossOrigin(origins = "*")
public class CycleController {

    private final CycleService cycleService;

    public CycleController(CycleService cycleService) {
        this.cycleService = cycleService;
    }

    /** Receives a full analysis cycle from the C agent. */
    @PostMapping
    public ResponseEntity<Long> receiveCycle(@RequestBody CycleDto dto) {
        AnalysisCycle saved = cycleService.saveCycle(dto);
        return ResponseEntity.ok(saved.getId());
    }

    /** Lists all stored cycles (summary only, no process lists). */
    @GetMapping
    public List<CycleSummary> listCycles() {
        return cycleService.findAll().stream()
                .map(CycleSummary::from)
                .toList();
    }

    /** Returns the most recent cycle. */
    @GetMapping("/latest")
    public ResponseEntity<AnalysisCycleResponse> getLatest() {
        return cycleService.findLatest()
                .map(c -> ResponseEntity.ok(AnalysisCycleResponse.from(c)))
                .orElse(ResponseEntity.notFound().build());
    }

    /** Returns a specific cycle with all its processes. */
    @GetMapping("/{id}")
    public ResponseEntity<AnalysisCycleResponse> getCycle(@PathVariable Long id) {
        return cycleService.findById(id)
                .map(c -> ResponseEntity.ok(AnalysisCycleResponse.from(c)))
                .orElse(ResponseEntity.notFound().build());
    }

    /** Returns the process tree for a cycle (used by the frontend graph). */
    @GetMapping("/{id}/tree")
    public ResponseEntity<List<ProcessTreeRecord>> getTree(@PathVariable Long id) {
        return cycleService.findById(id)
                .map(c -> ResponseEntity.ok(c.getProcessTree()))
                .orElse(ResponseEntity.notFound().build());
    }

    /* ── Response projections ── */

    record CycleSummary(
            Long id,
            String agentId,
            int cycleNumber,
            double timestamp,
            int totalProcesses,
            int suspiciousCount,
            int notableCount,
            int topResourcesCount,
            String receivedAt
    ) {
        static CycleSummary from(AnalysisCycle c) {
            return new CycleSummary(
                    c.getId(), c.getAgentId(), c.getCycleNumber(), c.getTimestamp(),
                    c.getTotalProcesses(), c.getSuspiciousCount(),
                    c.getNotableCount(), c.getTopResourcesCount(),
                    c.getReceivedAt().toString()
            );
        }
    }

    record AnalysisCycleResponse(
            CycleSummary summary,
            List<ProcessRecord> suspiciousProcesses,
            List<ProcessRecord> notableProcesses,
            List<ProcessRecord> topResources
    ) {
        static AnalysisCycleResponse from(AnalysisCycle c) {
            return new AnalysisCycleResponse(
                    CycleSummary.from(c),
                    c.getProcesses().stream()
                            .filter(p -> p.getTier().name().equals("SUSPICIOUS")).toList(),
                    c.getProcesses().stream()
                            .filter(p -> p.getTier().name().equals("NOTABLE")).toList(),
                    c.getProcesses().stream()
                            .filter(p -> p.getTier().name().equals("TOP_RESOURCE")).toList()
            );
        }
    }
}
