package com.anomaly.detection.controller;

import com.anomaly.detection.dto.SuspiciousEventDto;
import com.anomaly.detection.service.SuspiciousEventService;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/events")
@CrossOrigin(origins = "*")
public class SuspiciousEventController {

    private final SuspiciousEventService service;

    public SuspiciousEventController(SuspiciousEventService service) {
        this.service = service;
    }

    @GetMapping
    public Page<SuspiciousEventDto> listEvents(
            @RequestParam(defaultValue = "0")    int    page,
            @RequestParam(defaultValue = "50")   int    size,
            @RequestParam(defaultValue = "time") String sort,
            @RequestParam(defaultValue = "ALL")  String severity) {
        return service.findAll(page, size, sort, severity);
    }

    @PutMapping("/{id}/acknowledge")
    public ResponseEntity<Void> acknowledge(@PathVariable Long id,
                                            @RequestParam(defaultValue = "true") boolean value) {
        return service.acknowledge(id, value)
                ? ResponseEntity.noContent().build()
                : ResponseEntity.notFound().build();
    }
}
