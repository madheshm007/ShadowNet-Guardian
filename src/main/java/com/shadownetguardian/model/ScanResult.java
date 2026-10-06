package com.shadownetguardian.model;

import java.time.LocalDateTime;
import java.util.List;

public record ScanResult(String targetUrl, int totalScore, String classification, List<DetectionResult> detectionResults, LocalDateTime timestamp) {
}
