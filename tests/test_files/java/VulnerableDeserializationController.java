package com.example.insecurejava;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

@RestController
public class VulnerableDeserializationController {

    @PostMapping("/unsafeDeserialize")
    public ResponseEntity<String> unsafeDeserialization(@RequestBody byte[] data) {
        try {
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            Object deserializedObject = ois.readObject();
            return ResponseEntity.ok("Object deserialized: " + deserializedObject.toString());
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error during deserialization");
        }
    }
} 