package com.example.javaservice;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.MediaType;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

@RestController
public class EchoController {

    private final AtomicLong metricsCounter = new AtomicLong();

    @PostMapping(value = "/echo", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> echo(@RequestBody Map<String, Object> payload) {
        Map<String, Object> response = new HashMap<>();
        response.put("service", "Java");
        response.put("receivedPayload", payload);
        response.put("message", "Echo successful");
        return response;
    }

    @GetMapping(value = "/metrics", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> metrics() {
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("service_name", "JavaService");
        metrics.put("requests_processed_count", metricsCounter.incrementAndGet());
        // Add other metrics here as needed
        return metrics;
    }
}
