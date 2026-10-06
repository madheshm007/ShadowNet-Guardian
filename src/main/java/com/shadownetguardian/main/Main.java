package com.shadownetguardian.main;

import com.shadownetguardian.database.ScanHistoryRepository;
import com.shadownetguardian.detectors.*;
import com.shadownetguardian.engine.ThreatAnalysisEngine;
import com.shadownetguardian.model.ScanResult;
import com.shadownetguardian.report.PdfReportGenerator;

import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

public class Main {
    private static final String ANSI_RESET = "\u001B[0m";
    private static final String ANSI_RED = "\u001B[31m";
    private static final String ANSI_GREEN = "\u001B[32m";
    private static final String ANSI_YELLOW = "\u001B[33m";
    private static final String ANSI_CYAN = "\u001B[36m";

    public static void main(String[] args) {
        List<ThreatDetector> detectors = Arrays.asList(
                new HttpsDetector(),
                new KeywordDetector(),
                new UrlLengthDetector(),
                new IpAddressDetector(),
                new EntropyDetector(),
                new ObfuscationDetector(),
                new SubdomainDetector(),
                new SuspiciousTldDetector(),
                new DomainSimilarityDetector(),
                new UserInfoDetector()
        );

        ThreatAnalysisEngine engine = new ThreatAnalysisEngine(detectors);
        ScanHistoryRepository repository = new ScanHistoryRepository();
        Scanner scanner = new Scanner(System.in);
        ScanResult lastResult = null;

        System.out.println(ANSI_CYAN + "========================================" + ANSI_RESET);
        System.out.println(ANSI_CYAN + "        SHADOWNET GUARDIAN v1.0 - 10 DETECTOR ENGINE         " + ANSI_RESET);
        System.out.println(ANSI_CYAN + "========================================" + ANSI_RESET);

        while (true) {
            System.out.println("\nSelect an option:");
            System.out.println("1. Scan URL");
            System.out.println("2. View Scan History");
            System.out.println("3. Generate PDF for the last scan");
            System.out.println("4. Exit");
            System.out.print("> ");

            String choice = scanner.nextLine().trim();

            switch (choice) {
                case "1":
                    System.out.print("Enter URL to scan: ");
                    String url = scanner.nextLine().trim();
                    if (url.isEmpty()) {
                        System.out.println(ANSI_RED + "URL cannot be empty." + ANSI_RESET);
                        break;
                    }
                    System.out.println("\nAnalyzing URL...");
                    lastResult = engine.analyzeUrl(url);
                    repository.save(lastResult);
                    printScanResult(lastResult);
                    break;
                case "2":
                    System.out.println("\nLatest Scans History:");
                    repository.printTop10Latest();
                    break;
                case "3":
                    if (lastResult == null) {
                        System.out.println(ANSI_YELLOW + "No scan has been performed yet." + ANSI_RESET);
                    } else {
                        String filePath = "ScanReport_" + System.currentTimeMillis() + ".pdf";
                        PdfReportGenerator.generateReport(lastResult, filePath);
                    }
                    break;
                case "4":
                    System.out.println(ANSI_CYAN + "Exiting ShadowNet Guardian. Stay safe!" + ANSI_RESET);
                    scanner.close();
                    return;
                default:
                    System.out.println(ANSI_RED + "Invalid choice. Please try again." + ANSI_RESET);
            }
        }
    }

    private static boolean isHighConfidenceIndicator(com.shadownetguardian.model.DetectionResult result) {
        if (!result.triggered()) {
            return false;
        }

        String detectorName = result.detectorName();
        if ("Domain Similarity Detector".equals(detectorName)
                || "IP Address Detector".equals(detectorName)
                || "User-Info Detector".equals(detectorName)) {
            return true;
        }

        return "Obfuscation Detector".equals(detectorName)
                && result.scoreContribution() >= 10;
    }

    private static void printScanResult(ScanResult result) {
        System.out.println("\n" + ANSI_CYAN + "--- Detailed Scan Results ---" + ANSI_RESET);
        System.out.println("Target URL : " + result.targetUrl());
        System.out.println("Time       : " + result.timestamp());

        System.out.println("\nDetector-by-Detector Analysis:");
        System.out.println("--------------------------------------------------------------------------");
        System.out.printf("%-26s %-15s %-10s %s%n", "Detector", "Status", "Score", "Reason");
        System.out.println("--------------------------------------------------------------------------");

        int triggeredCount = 0;
        for (var dr : result.detectionResults()) {
            String status = dr.triggered() ? "TRIGGERED" : "NOT TRIGGERED";
            String score = dr.triggered() ? "+" + dr.scoreContribution() : "0";

            if (dr.triggered()) {
                triggeredCount++;
                System.out.printf(ANSI_RED + "%-26s %-15s %-10s %s%n" + ANSI_RESET,
                        dr.detectorName(), status, score, dr.reason());
            } else {
                System.out.printf(ANSI_GREEN + "%-26s %-15s %-10s %s%n" + ANSI_RESET,
                        dr.detectorName(), status, score, dr.reason());
            }
        }

        System.out.println("--------------------------------------------------------------------------");
        System.out.println("Triggered Detectors : " + triggeredCount + " / " + result.detectionResults().size());

        String color = ANSI_GREEN;
        if (result.classification().equals("SUSPICIOUS")) {
            color = ANSI_YELLOW;
        }
        if (result.classification().equals("PHISHING") || result.classification().equals("INVALID")) {
            color = ANSI_RED;
        }

        System.out.println("\n" + color + "Total Score     : " + result.totalScore() + " / 100" + ANSI_RESET);
        System.out.println(color + "Classification   : " + result.classification() + ANSI_RESET);

        if ("SUSPICIOUS".equals(result.classification()) && result.totalScore() < 25) {
            boolean highConfidence = result.detectionResults().stream().anyMatch(Main::isHighConfidenceIndicator);
            if (highConfidence) {
                System.out.println(ANSI_YELLOW +
                        "Risk Escalation  : High-confidence indicator detected; minimum classification raised to SUSPICIOUS."
                        + ANSI_RESET);
            }
        }

        System.out.println(ANSI_CYAN + "--------------------------------------------------------------------------" + ANSI_RESET);
    }
}
