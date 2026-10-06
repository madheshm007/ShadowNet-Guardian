package com.shadownetguardian.detectors;

import com.shadownetguardian.constants.DetectionWeights;
import com.shadownetguardian.model.DetectionResult;
import com.shadownetguardian.model.ParsedUrl;
import java.util.HashMap;
import java.util.Map;

public class EntropyDetector implements ThreatDetector {
    private static final double THRESHOLD = 4.5;
    private static final int WEIGHT = DetectionWeights.ENTROPY;

    @Override
    public String getName() {
        return "Entropy Detector";
    }

    @Override
    public int getMaxWeight() {
        return WEIGHT;
    }

    @Override
    public DetectionResult analyze(ParsedUrl parsedUrl) {
        String targetString = parsedUrl.getHost()
                + parsedUrl.getPath()
                + (parsedUrl.getQuery().isEmpty() ? "" : "?" + parsedUrl.getQuery());

        if (targetString.isEmpty()) {
            return new DetectionResult(getName(), false, 0, "No host, path or query present");
        }

        double entropy = calculateShannonEntropy(targetString);
        boolean triggered = entropy > THRESHOLD;
        int score = triggered ? WEIGHT : 0;
        String reason = triggered
                ? String.format("High entropy detected (%.2f > %.1f)", entropy, THRESHOLD)
                : String.format("Normal entropy (%.2f)", entropy);

        return new DetectionResult(getName(), triggered, score, reason);
    }

    private double calculateShannonEntropy(String s) {
        Map<Character, Integer> frequencies = new HashMap<>();
        for (char c : s.toCharArray()) {
            frequencies.put(c, frequencies.getOrDefault(c, 0) + 1);
        }

        double entropy = 0;
        double length = s.length();
        for (int freq : frequencies.values()) {
            double p = freq / length;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }
}
