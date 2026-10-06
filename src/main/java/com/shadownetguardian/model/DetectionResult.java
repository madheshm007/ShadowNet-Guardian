package com.shadownetguardian.model;

public record DetectionResult(String detectorName, boolean triggered, int scoreContribution, String reason) {
}
