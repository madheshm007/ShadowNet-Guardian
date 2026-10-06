package com.shadownetguardian.detectors;

import com.shadownetguardian.constants.DetectionWeights;
import com.shadownetguardian.model.DetectionResult;
import com.shadownetguardian.model.ParsedUrl;
import com.shadownetguardian.utils.LevenshteinDistance;
import java.util.Arrays;
import java.util.List;

public class DomainSimilarityDetector implements ThreatDetector {
    private static final int WEIGHT = DetectionWeights.DOMAIN_SIMILARITY;
    private static final List<String> TARGETS = Arrays.asList(
            "paypal", "apple", "google", "microsoft", "amazon");

    @Override
    public String getName() {
        return "Domain Similarity Detector";
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

        String[] labels = host.split("\\.");
        int baseIndex = getBaseDomainLabelIndex(labels);

        for (int i = 0; i < labels.length; i++) {
            String label = labels[i];
            if ("www".equals(label) || label.isEmpty()) {
                continue;
            }

            for (String target : TARGETS) {
                // An exact brand match is acceptable in the registrable domain
                // itself, but suspicious when it appears in a subdomain.
                if (i != baseIndex && label.equals(target)) {
                    return new DetectionResult(getName(), true, WEIGHT,
                            "Brand name appears in a subdomain: " + target);
                }

                int distance = LevenshteinDistance.calculate(label, target);
                if (distance == 1 || distance == 2) {
                    return new DetectionResult(getName(), true, WEIGHT,
                            "Domain label closely resembles target: " + target
                                    + " (Distance: " + distance + ")");
                }
            }

            // Also inspect hyphen-separated brand tokens, including small
            // typos such as paypa1-security or g00gle-login.
            String[] tokens = label.split("-");
            for (String token : tokens) {
                if (token.isEmpty()) {
                    continue;
                }
                for (String target : TARGETS) {
                    if (token.equals(target) && i == baseIndex && tokens.length > 1) {
                        return new DetectionResult(getName(), true, WEIGHT,
                                "Brand name appears in a compound domain label: " + target);
                    }

                    int tokenDistance = LevenshteinDistance.calculate(token, target);
                    if (i == baseIndex && tokenDistance == 1 && token.length() >= 4) {
                        return new DetectionResult(getName(), true, WEIGHT,
                                "Compound domain token closely resembles target: " + target
                                        + " (Distance: " + tokenDistance + ")");
                    }
                }
            }
        }

        return new DetectionResult(getName(), false, 0, "No similar domains found");
    }

    private int getBaseDomainLabelIndex(String[] labels) {
        if (labels.length < 2) {
            return 0;
        }
        // Simple handling for common two-part country-code suffixes such as
        // .co.uk, .com.au and .co.in. This avoids treating the suffix as the
        // main domain label without requiring an external public-suffix list.
        if (labels.length >= 3 && labels[labels.length - 1].length() == 2) {
            return labels.length - 3;
        }
        return labels.length - 2;
    }

}
