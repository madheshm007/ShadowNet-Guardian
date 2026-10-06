package com.shadownetguardian.detectors;

import com.shadownetguardian.constants.DetectionWeights;
import com.shadownetguardian.model.DetectionResult;
import com.shadownetguardian.model.ParsedUrl;
import java.util.Arrays;
import java.util.List;

public class SuspiciousTldDetector implements ThreatDetector {
    private static final int WEIGHT = DetectionWeights.SUSPICIOUS_TLD;
    private static final List<String> SUSPICIOUS_TLDS = Arrays.asList(
            ".xyz", ".top", ".pw", ".cc");

    @Override
    public String getName() {
        return "Suspicious TLD Detector";
    }

    @Override
    public int getMaxWeight() {
        return WEIGHT;
    }

    @Override
    public DetectionResult analyze(ParsedUrl parsedUrl) {
        String host = parsedUrl.getHost();
        if (host == null || host.isEmpty()) {
            return new DetectionResult(getName(), false, 0, "No host available");
        }

        for (String tld : SUSPICIOUS_TLDS) {
            if (host.endsWith(tld)) {
                return new DetectionResult(getName(), true, WEIGHT,
                        "Host uses a TLD in the configured suspicious list: " + tld);
            }
        }

        return new DetectionResult(getName(), false, 0, "TLD is not in the configured suspicious list");
    }
}
