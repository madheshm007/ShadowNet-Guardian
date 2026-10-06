package com.shadownetguardian.database;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

public class DatabaseConnection {
    private static final String URL = System.getenv().getOrDefault(
            "SHADOWNET_DB_URL",
            "jdbc:mysql://localhost:3306/shadownet_db?allowPublicKeyRetrieval=true&useSSL=false");
    private static final String USER = System.getenv().getOrDefault("SHADOWNET_DB_USER", "root");
    private static final String PASSWORD = System.getenv().getOrDefault("SHADOWNET_DB_PASSWORD", "maddy04@11");

    private DatabaseConnection() {
    }

    public static Connection getConnection() throws SQLException {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            Connection connection = DriverManager.getConnection(URL, USER, PASSWORD);
            initializeDatabase(connection);
            return connection;
        } catch (ClassNotFoundException e) {
            throw new SQLException("MySQL Driver not found. Add the MySQL Connector/J dependency.", e);
        }
    }

    private static void initializeDatabase(Connection connection) throws SQLException {
        String createTableSql = "CREATE TABLE IF NOT EXISTS scan_history (" +
                "id INT AUTO_INCREMENT PRIMARY KEY," +
                "url VARCHAR(2048) NOT NULL," +
                "risk_score INT NOT NULL," +
                "classification VARCHAR(50) NOT NULL," +
                "scan_time TIMESTAMP NOT NULL" +
                ")";

        try (Statement stmt = connection.createStatement()) {
            stmt.execute(createTableSql);
        }
    }
}
