package com.example.insecurejava;
import javax.crypto.Cipher;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;

public class WeakCryptoService {
    
    public void weakEncryption() throws NoSuchAlgorithmException, NoSuchPaddingException {
        // These should trigger weak crypto rules
        Cipher desCipher = Cipher.getInstance("DES");
        Cipher rc4Cipher = Cipher.getInstance("RC4");
        
        // This should be fine
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
    }
    
    public void weakHashing() throws NoSuchAlgorithmException {
        // These should trigger weak crypto rules
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        
        // This should be fine
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
    }
} 