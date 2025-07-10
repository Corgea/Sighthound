package com.example.insecurejava;
import java.sql.Connection;
import java.sql.Statement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class SQLInjectionService {
    
    public void vulnerableQuery(String userInput, Connection conn) throws SQLException {
        Statement stmt = conn.createStatement();
        // This should trigger SQL injection rule
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userInput);
        
        // This should also trigger
        stmt.execute("DELETE FROM logs WHERE user = '" + userInput + "'");
        
        // This should NOT trigger (literal string)
        stmt.execute("SELECT COUNT(*) FROM users");
    }
    
    public void anotherVulnerableMethod(String name, Statement statement) throws SQLException {
        // This should trigger
        statement.executeUpdate("INSERT INTO users (name) VALUES ('" + name + "')");
    }
} 