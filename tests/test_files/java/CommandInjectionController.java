package com.example.insecurejava;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.io.IOException;

@RestController
public class CommandInjectionController {
    
    @GetMapping("/exec")
    public String executeCommand(@RequestParam String command) throws IOException {
        // This should trigger command injection rule
        Runtime.getRuntime().exec(command);
        return "Command executed";
    }
    
    @GetMapping("/ping")
    public String pingHost(@RequestParam String host) throws IOException {
        // This should trigger command injection rule
        Runtime.getRuntime().exec("ping -c 1 " + host);
        return "Ping completed";
    }
    
    public void safeCommand() throws IOException {
        // This should NOT trigger (literal string)
        Runtime.getRuntime().exec("ls -la");
    }
} 