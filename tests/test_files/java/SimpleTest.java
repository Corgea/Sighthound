package com.example.test;
import java.sql.Statement;
import java.sql.SQLException;

public class SimpleTest {
    
    public void testMethod(String userInput, Statement stmt) throws SQLException {
        // This should definitely trigger the SQL injection rule
        stmt.execute("SELECT * FROM users WHERE id = " + userInput);
        
        // This should trigger command injection
        Runtime.getRuntime().exec(userInput);
    }
} 