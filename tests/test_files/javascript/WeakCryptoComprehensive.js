// ==================== Weak Hash Algorithms ====================
function weakHashAlgorithms() {
    const crypto = require('crypto');
    const CryptoJS = require('crypto-js');
    
    // These should trigger weak crypto rules
    const md5Hash = crypto.createHash('md5');
    const md5HashAlt = crypto.createHash('MD5');
    const sha1Hash = crypto.createHash('sha1');
    const sha1HashAlt = crypto.createHash('SHA1');
    
    // CryptoJS weak algorithms
    const md5CryptoJS = CryptoJS.MD5('test');
    const sha1CryptoJS = CryptoJS.SHA1('test');
    
    // These should be fine
    const sha256Hash = crypto.createHash('sha256');
    const sha512Hash = crypto.createHash('sha512');
    const sha256CryptoJS = CryptoJS.SHA256('test');
}

// ==================== Weak Encryption Algorithms ====================
function weakEncryptionAlgorithms() {
    const crypto = require('crypto');
    const CryptoJS = require('crypto-js');
    
    // These should trigger weak crypto rules
    const desCipher = crypto.createCipher('des', 'password');
    const desDecipher = crypto.createDecipher('des', 'password');
    const rc4Cipher = crypto.createCipher('rc4', 'password');
    const arc4Cipher = crypto.createCipher('arc4', 'password');
    const tripleDesCipher = crypto.createCipher('des3', 'password');
    
    // CryptoJS weak algorithms
    const desCryptoJS = CryptoJS.DES.encrypt('message', 'password');
    const rc4CryptoJS = CryptoJS.RC4.encrypt('message', 'password');
    const tripleDesCryptoJS = CryptoJS.TripleDES.encrypt('message', 'password');
    
    // These should be fine
    const aesCipher = crypto.createCipher('aes-256-cbc', 'password');
    const aesGcmCipher = crypto.createCipher('aes-256-gcm', 'password');
    const aesCryptoJS = CryptoJS.AES.encrypt('message', 'password');
}

// ==================== Weak Encryption Modes ====================
function weakEncryptionModes() {
    const crypto = require('crypto');
    const CryptoJS = require('crypto-js');
    
    // These should trigger weak crypto rules
    const ecbAes = crypto.createCipher('aes-256-ecb', 'password');
    const ecbDes = crypto.createCipher('des-ecb', 'password');
    const ecb3Des = crypto.createCipher('des3-ecb', 'password');
    
    // CryptoJS ECB mode
    const ecbCryptoJS = CryptoJS.AES.encrypt('message', 'password', { mode: CryptoJS.mode.ECB });
    
    // These should be fine
    const cbcAes = crypto.createCipher('aes-256-cbc', 'password');
    const gcmAes = crypto.createCipher('aes-256-gcm', 'password');
    const cbcCryptoJS = CryptoJS.AES.encrypt('message', 'password', { mode: CryptoJS.mode.CBC });
}

// ==================== Weak Random Number Generation ====================
function weakRandomGeneration() {
    // These should trigger weak crypto rules
    const weakRandom = Math.random();
    const weakInt = Math.floor(Math.random() * 100);
    const weakCeil = Math.ceil(Math.random() * 100);
    const weakRound = Math.round(Math.random() * 100);
    const timeBased = Date.now();
    const performanceBased = performance.now();
    
    // These should be fine
    const secureRandom = crypto.getRandomValues(new Uint8Array(16));
    const secureRandom32 = crypto.getRandomValues(new Uint32Array(4));
}

// ==================== Hardcoded Cryptographic Material ====================
function hardcodedSecrets() {
    // These should trigger hardcoded key rules
    const key = "my-secret-key-12345";
    const password = "admin123";
    const secret = "super-secret-token";
    const token = "jwt-token-here";
    const apiKey = "api-key-12345";
    const privateKey = "-----BEGIN PRIVATE KEY-----";
    const publicKey = "-----BEGIN PUBLIC KEY-----";
    
    // Use the hardcoded values in cryptographic operations
    const crypto = require('crypto');
    const hash = crypto.createHash('sha256');
    hash.update(key);
    
    const cipher = crypto.createCipher('aes-256-cbc', password);
}

// ==================== Weak Key Derivation ====================
function weakKeyDerivation() {
    const crypto = require('crypto');
    const CryptoJS = require('crypto-js');
    
    // These should trigger weak key derivation rules
    const md5Hash = crypto.createHash('md5').update('password').digest();
    const sha1Hash = crypto.createHash('sha1').update('password').digest();
    const md5CryptoJS = CryptoJS.MD5('password');
    const sha1CryptoJS = CryptoJS.SHA1('password');
    
    // These should be fine
    const pbkdf2 = crypto.pbkdf2Sync('password', 'salt', 100000, 64, 'sha512');
    const scrypt = crypto.scryptSync('password', 'salt', 64);
}

// ==================== Insecure JWT Usage ====================
function insecureJWTUsage() {
    const jwt = require('jsonwebtoken');
    
    // These should trigger insecure JWT rules
    const token1 = jwt.sign({ user: 'test' }, 'secret', { algorithm: 'none' });
    const token2 = jwt.sign({ user: 'test' }, 'secret', { algorithm: 'HS256' });
    const token3 = jwt.sign({ user: 'test' }, 'secret', { algorithm: 'HS384' });
    const token4 = jwt.sign({ user: 'test' }, 'secret', { algorithm: 'HS512' });
    
    // These should be fine
    const secureToken = jwt.sign({ user: 'test' }, 'secret', { algorithm: 'RS256' });
    const secureToken2 = jwt.sign({ user: 'test' }, 'secret', { algorithm: 'ES256' });
}

// ==================== Taint Flow Examples ====================
function taintFlowExamples(userInput) {
    const crypto = require('crypto');
    
    // These should trigger taint flow rules
    const hardcodedKey = "hardcoded-secret-key";
    const hash = crypto.createHash('sha256');
    hash.update(hardcodedKey);
    
    const cipher = crypto.createCipher('aes-256-cbc', hardcodedKey);
    
    // User input flowing to cryptographic operations
    const userHash = crypto.createHash('sha256');
    userHash.update(userInput);
}

// ==================== Safe Examples (should not trigger rules) ====================
function safeCryptographicUsage() {
    const crypto = require('crypto');
    const CryptoJS = require('crypto-js');
    
    // Strong hash algorithms
    const sha256Hash = crypto.createHash('sha256');
    const sha512Hash = crypto.createHash('sha512');
    const sha256CryptoJS = CryptoJS.SHA256('test');
    
    // Strong encryption algorithms
    const aesCipher = crypto.createCipher('aes-256-cbc', 'password');
    const aesGcmCipher = crypto.createCipher('aes-256-gcm', 'password');
    const aesCryptoJS = CryptoJS.AES.encrypt('message', 'password');
    
    // Secure random number generation
    const secureRandom = crypto.getRandomValues(new Uint8Array(32));
    
    // Strong key derivation
    const pbkdf2 = crypto.pbkdf2Sync('password', 'salt', 100000, 64, 'sha512');
    const scrypt = crypto.scryptSync('password', 'salt', 64);
    
    // Secure JWT
    const jwt = require('jsonwebtoken');
    const secureToken = jwt.sign({ user: 'test' }, 'secret', { algorithm: 'RS256' });
}
