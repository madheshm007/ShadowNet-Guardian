package com.shadownetguardian.detectors;

import com.shadownetguardian.constants.DetectionWeights;
import com.shadownetguardian.model.DetectionResult;
import com.shadownetguardian.model.ParsedUrl;

public class SubdomainDetector implements ThreatDetector {
    private static final int WEIGHT = DetectionWeights.SUBDOMAIN;
    private static final int SUSPICIOUS_SUBDOMAIN_COUNT = 3;

    @Override
    public String getName() {
        return "Subdomain Detector";
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

        if (host.matches("^(?:\\d{1,3}\\.){3}\\d{1,3}$") || host.contains(":")) {
            return new DetectionResult(getName(), false, 0,
                    "Subdomain analysis is not applicable to a raw IP address");
        }

        String[] labels = host.split("\\.");
        int subdomainCount = Math.max(0, labels.length - 2);

        if (subdomainCount >= SUSPICIOUS_SUBDOMAIN_COUNT) {
            return new DetectionResult(getName(), true, WEIGHT,
                    "Host contains " + subdomainCount + " subdomain levels");
        }

        return new DetectionResult(getName(), false, 0,
                "Host contains " + subdomainCount + " subdomain level(s)");
    }
}
