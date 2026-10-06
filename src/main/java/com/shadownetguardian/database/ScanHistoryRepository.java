package com.shadownetguardian.database;

import com.shadownetguardian.model.ScanResult;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;

public class ScanHistoryRepository {

    public void save(ScanResult scanResult) {
        String sql = "INSERT INTO scan_history (url, risk_score, classification, scan_time) VALUES (?, ?, ?, ?)";
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, scanResult.targetUrl());
            pstmt.setInt(2, scanResult.totalScore());
            pstmt.setString(3, scanResult.classification());
            pstmt.setTimestamp(4, Timestamp.valueOf(scanResult.timestamp()));
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Error saving scan history: " + e.getMessage());
        }
    }

    public void printTop10Latest() {
        String sql = "SELECT url, risk_score, classification, scan_time FROM scan_history ORDER BY scan_time DESC LIMIT 10";
        try (Connection conn = DatabaseConnection.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {

            System.out.println("--------------------------------------------------------------------------------");
            System.out.printf("%-30s | %-10s | %-15s | %-20s%n", "URL", "Score", "Class", "Time");
            System.out.println("--------------------------------------------------------------------------------");
            while (rs.next()) {
                String url = rs.getString("url");
                if (url.length() > 30) {
                    url = url.substring(0, 27) + "...";
                }
                int score = rs.getInt("risk_score");
                String classification = rs.getString("classification");
                Timestamp time = rs.getTimestamp("scan_time");
                System.out.printf("%-30s | %-10d | %-15s | %-20s%n",
                        url, score, classification, time);
            }
            System.out.println("--------------------------------------------------------------------------------");
        } catch (SQLException e) {
            System.err.println("Error retrieving scan history: " + e.getMessage());
        }
    }
}
