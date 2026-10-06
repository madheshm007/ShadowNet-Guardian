package com.shadownetguardian.engine;

import com.shadownetguardian.detectors.ThreatDetector;
import com.shadownetguardian.model.DetectionResult;
import com.shadownetguardian.model.ParsedUrl;
import com.shadownetguardian.model.ScanResult;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Central weighted heuristic engine for ShadowNet Guardian.
 *
 * The detector weights produce a score from 0 to 100. In addition to the
 * numeric score, the engine applies a high-confidence escalation rule so
 * that a single strong phishing indicator cannot be hidden by the SAFE
 * threshold. The escalation only changes classification; it never increases
 * the displayed numeric score.
 */
public class ThreatAnalysisEngine {
    private static final int SUSPICIOUS_THRESHOLD = 25;
    private static final int PHISHING_THRESHOLD = 61;

    private final List<ThreatDetector> detectors;

    public ThreatAnalysisEngine(List<ThreatDetector> detectors) {
        if (detectors == null || detectors.isEmpty()) {
            throw new IllegalArgumentException("At least one threat detector is required.");
        }

        int totalWeight = detectors.stream().mapToInt(ThreatDetector::getMaxWeight).sum();
        if (totalWeight != 100) {
            throw new IllegalArgumentException(
                    "The ten-detector engine must total exactly 100 points. Configured total: " + totalWeight);
        }

        this.detectors = List.copyOf(detectors);
    }

    public ScanResult analyzeUrl(String url) {
        ParsedUrl parsedUrl = new ParsedUrl(url);
        List<DetectionResult> detectionResults = new ArrayList<>();

        if (!parsedUrl.isValid()) {
            detectionResults.add(new DetectionResult(
                    "URL Validation", true, 0,
                    "Invalid URL. Enter a valid HTTP or HTTPS URL with a host."));
            return new ScanResult(url, 0, "INVALID", detectionResults, LocalDateTime.now());
        }

        int totalScore = 0;
        for (ThreatDetector detector : detectors) {
            DetectionResult result = detector.analyze(parsedUrl);
            detectionResults.add(result);
            if (result.triggered()) {
                totalScore += Math.max(0, result.scoreContribution());
            }
        }

        totalScore = Math.max(0, Math.min(100, totalScore));
        String classification = classifyRisk(totalScore, detectionResults);

        return new ScanResult(url, totalScore, classification, detectionResults, LocalDateTime.now());
    }

    /**
     * Classifies the URL using both the weighted score and high-confidence
     * escalation rules.
     *
     * Normal score bands:
     *   0-24   SAFE
     *   25-60  SUSPICIOUS
     *   61-100 PHISHING
     *
     * High-confidence indicators force at least SUSPICIOUS classification:
     *   - Domain Similarity Detector
     *   - IP Address Detector
     *   - User-Info Detector
     *   - Obfuscation Detector when it reports two or more obfuscation signals
     *
     * This prevents a strong individual signal such as paypa1.com (+15)
     * from being classified as SAFE merely because its total is below 25.
     */
    private String classifyRisk(int score, List<DetectionResult> results) {
        if (score >= PHISHING_THRESHOLD) {
            return "PHISHING";
        }

        if (score >= SUSPICIOUS_THRESHOLD) {
            return "SUSPICIOUS";
        }

        if (hasHighConfidenceIndicator(results)) {
            return "SUSPICIOUS";
        }

        return "SAFE";
    }

    private boolean hasHighConfidenceIndicator(List<DetectionResult> results) {
        for (DetectionResult result : results) {
            if (!result.triggered()) {
                continue;
            }

            String detectorName = result.detectorName();

            if ("Domain Similarity Detector".equals(detectorName)
                    || "IP Address Detector".equals(detectorName)
                    || "User-Info Detector".equals(detectorName)) {
                return true;
            }

            // One percent-encoded character is not necessarily malicious.
            // Require the full 10-point obfuscation contribution (two signals)
            // before treating obfuscation as a high-confidence indicator.
            if ("Obfuscation Detector".equals(detectorName)
                    && result.scoreContribution() >= 10) {
                return true;
            }
        }

        return false;
    }
}
