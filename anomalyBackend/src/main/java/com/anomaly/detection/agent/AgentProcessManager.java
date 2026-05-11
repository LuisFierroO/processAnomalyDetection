package com.anomaly.detection.agent;

import com.anomaly.detection.dto.CycleDto;
import com.anomaly.detection.service.CycleService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;

@Component
public class AgentProcessManager implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AgentProcessManager.class);

    @Value("${agent.binary.path}")
    private String agentBinaryPath;

    @Value("${agent.interval-ms:10000}")
    private int intervalMs;

    @Value("${agent.enabled:true}")
    private boolean agentEnabled;

    private final CycleService cycleService;
    private final ObjectMapper objectMapper;

    private volatile Process agentProcess;

    public AgentProcessManager(CycleService cycleService, ObjectMapper objectMapper) {
        this.cycleService = cycleService;
        this.objectMapper = objectMapper;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!agentEnabled) {
            log.info("Agent integration disabled (agent.enabled=false)");
            return;
        }

        if (!Files.isExecutable(Path.of(agentBinaryPath))) {
            log.warn("Agent binary not found or not executable at '{}'. " +
                     "Continuing without agent — use POST /api/cycles to ingest data manually.",
                     agentBinaryPath);
            return;
        }

        Thread reader = new Thread(this::runAgentLoop, "agent-reader");
        reader.setDaemon(true);
        reader.start();
    }

    private void runAgentLoop() {
        log.info("Starting agent: {} --json --include-all --cycles 999999 --interval-ms {}",
                 agentBinaryPath, intervalMs);

        ProcessBuilder pb = new ProcessBuilder(
                agentBinaryPath,
                "--json", "--include-all",
                "--cycles", "999999",
                "--interval-ms", String.valueOf(intervalMs)
        );
        pb.redirectErrorStream(false);

        try {
            agentProcess = pb.start();

            /* Drain stderr to avoid blocking the agent process. */
            Thread stderrDrainer = new Thread(() -> {
                try (BufferedReader err = new BufferedReader(
                        new InputStreamReader(agentProcess.getErrorStream()))) {
                    String line;
                    while ((line = err.readLine()) != null)
                        log.debug("[agent stderr] {}", line);
                } catch (IOException ignored) {}
            }, "agent-stderr");
            stderrDrainer.setDaemon(true);
            stderrDrainer.start();

            readJsonEnvelopes(agentProcess);

            int exit = agentProcess.waitFor();
            log.info("Agent process exited with code {}", exit);

        } catch (IOException e) {
            log.error("Failed to start agent process: {}", e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Reads the agent stdout line by line. Tracks brace depth to detect when
     * a complete JSON envelope has been received, then parses and persists it.
     *
     * The agent emits one top-level JSON object per cycle, each on separate
     * lines, with no delimiters between envelopes.
     */
    private void readJsonEnvelopes(Process process) throws IOException {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {

            StringBuilder buffer = new StringBuilder();
            int depth = 0;
            String line;

            while ((line = reader.readLine()) != null) {
                buffer.append(line).append('\n');

                for (int i = 0; i < line.length(); i++) {
                    char c = line.charAt(i);
                    if (c == '{') depth++;
                    else if (c == '}') depth--;
                }

                if (depth == 0 && !buffer.isEmpty()) {
                    handleEnvelope(buffer.toString().trim());
                    buffer.setLength(0);
                }
            }
        }
    }

    private void handleEnvelope(String json) {
        if (json.isEmpty()) return;
        try {
            CycleDto dto = objectMapper.readValue(json, CycleDto.class);
            cycleService.saveCycle(dto);
            log.info("Cycle {} saved — {} processes, {} suspicious",
                     dto.cycleNumber(), dto.totalProcesses(), dto.suspiciousCount());
        } catch (Exception e) {
            log.error("Failed to parse or save cycle: {}", e.getMessage());
        }
    }

    @PreDestroy
    public void shutdown() {
        if (agentProcess != null && agentProcess.isAlive()) {
            log.info("Sending SIGTERM to agent process");
            agentProcess.destroy();
        }
    }
}
