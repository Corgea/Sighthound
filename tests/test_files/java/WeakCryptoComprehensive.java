package com.example.weakcrypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

public class WeakCryptoComprehensive {
    
    // ==================== Weak Hash Algorithms ====================
    public void weakHashAlgorithms() throws NoSuchAlgorithmException {
        // These should trigger weak crypto rules
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        MessageDigest sha1Alt = MessageDigest.getInstance("SHA1");
        
        // These should be fine
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
    }
    
    // ==================== Weak Encryption Algorithms ====================
    public void weakEncryptionAlgorithms() throws NoSuchAlgorithmException {
        // These should trigger weak crypto rules
        Cipher desCipher = Cipher.getInstance("DES");
        Cipher rc4Cipher = Cipher.getInstance("RC4");
        Cipher arc4Cipher = Cipher.getInstance("ARC4");
        Cipher tripleDesCipher = Cipher.getInstance("DESede");
        Cipher tripleDesAlt = Cipher.getInstance("3DES");
        
        // These should be fine
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        Cipher aesCbcCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    }
    
    // ==================== Weak Encryption Modes ====================
    public void weakEncryptionModes() throws NoSuchAlgorithmException {
        // These should trigger weak crypto rules
        Cipher ecbAes = Cipher.getInstance("AES/ECB/PKCS5Padding");
        Cipher ecbDes = Cipher.getInstance("DES/ECB/PKCS5Padding");
        Cipher ecb3Des = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        
        // These should be fine
        Cipher cbcAes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        Cipher gcmAes = Cipher.getInstance("AES/GCM/NoPadding");
    }
    
    // ==================== Weak Random Number Generation ====================
    public void weakRandomGeneration() {
        // These should trigger weak crypto rules
        Random weakRandom = new Random();
        int weakInt = weakRandom.nextInt();
        long weakLong = weakRandom.nextLong();
        double weakDouble = weakRandom.nextDouble();
        
        // These should be fine
        SecureRandom secureRandom = new SecureRandom();
        int secureInt = secureRandom.nextInt();
        byte[] secureBytes = new byte[16];
        secureRandom.nextBytes(secureBytes);
    }
    
    // ==================== Hardcoded Cryptographic Material ====================
    public void hardcodedSecrets() throws NoSuchAlgorithmException {
        // These should trigger hardcoded key rules
        String key = "my-secret-key-12345";
        String password = "admin123";
        String secret = "super-secret-token";
        String token = "jwt-token-here";
        String privateKey = "-----BEGIN PRIVATE KEY-----";
        String publicKey = "-----BEGIN PUBLIC KEY-----";
        
        // Use the hardcoded values in cryptographic operations
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(password.getBytes());
    }
    
    // ==================== Weak Key Sizes ====================
    public void weakKeySizes() throws NoSuchAlgorithmException {
        // These should trigger weak key size rules
        KeyGenerator rsaGen = KeyGenerator.getInstance("RSA");
        rsaGen.init(1024); // Weak RSA key size
        
        // This should be fine
        KeyGenerator aesGen = KeyGenerator.getInstance("AES");
        aesGen.init(256); // Strong AES key size
    }
    
    // ==================== Taint Flow Examples ====================
    public void taintFlowExamples(String userInput) throws NoSuchAlgorithmException {
        // These should trigger taint flow rules
        String hardcodedKey = "hardcoded-secret-key";
        SecretKeySpec key = new SecretKeySpec(hardcodedKey.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        
        // User input flowing to cryptographic operations
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(userInput.getBytes());
    }
    
    // ==================== Safe Examples (should not trigger rules) ====================
    public void safeCryptographicUsage() throws NoSuchAlgorithmException {
        // Strong hash algorithms
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        
        // Strong encryption algorithms
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        Cipher aesCbcCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        
        // Secure random number generation
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        
        // Strong key sizes
        KeyGenerator aesGen = KeyGenerator.getInstance("AES");
        aesGen.init(256);
    }
}
