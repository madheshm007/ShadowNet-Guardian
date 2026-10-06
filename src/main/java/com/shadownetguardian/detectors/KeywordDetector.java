package com.shadownetguardian.detectors;

import com.shadownetguardian.constants.DetectionWeights;
import com.shadownetguardian.model.DetectionResult;
import com.shadownetguardian.model.ParsedUrl;
import java.util.Arrays;
import java.util.List;

public class KeywordDetector implements ThreatDetector {
    private static final int WEIGHT = DetectionWeights.KEYWORD;
    private static final int SCORE_PER_KEYWORD = 5;
    private static final List<String> KEYWORDS = Arrays.asList(
            "login", "verify", "update", "secure", "wallet", "account");

    @Override
    public String getName() {
        return "Keyword Detector";
    }

    @Override
    public int getMaxWeight() {
        return WEIGHT;
    }

    @Override
    public DetectionResult analyze(ParsedUrl parsedUrl) {
        String urlString = parsedUrl.getOriginalUrl().toLowerCase();
        int matches = 0;
        String firstMatch = null;

        for (String keyword : KEYWORDS) {
            if (urlString.contains(keyword)) {
                matches++;
                if (firstMatch == null) {
                    firstMatch = keyword;
                }
            }
        }

        if (matches == 0) {
            return new DetectionResult(getName(), false, 0, "No high-risk keywords found");
        }

        int score = Math.min(WEIGHT, matches * SCORE_PER_KEYWORD);
        return new DetectionResult(getName(), true, score,
                "Found high-risk keyword(s), first match: " + firstMatch + " (" + matches + " matched)");
    }
}
