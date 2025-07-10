/**
 * FALSE POSITIVE REGRESSION TEST: Clear-text Transmission
 * 
 * ISSUE DESCRIPTION:
 * The Clear-text Transmission rule (js-cleartext-network-taint-001) was generating
 * false positives due to overly broad taint source patterns that matched any variable
 * name containing sensitive keywords, rather than actual user input sources.
 * 
 * PROBLEM PATTERNS (Fixed):
 * - "password" - matched any variable named "password"
 * - "*[type=password]*" - matched any identifier containing "type=password"
 * - "*[name*=token]*" - matched any identifier containing "name*=token"
 * - "*[name*=key]*" - matched any identifier containing "name*=key"
 * 
 * REAL WORLD IMPACT:
 * - THREE.js library: 20 false positives from constants like DDPF_ALPHAPIXELS
 * - Any library with variables containing "password", "token", "key", etc.
 * - Function parameters with these names were incorrectly flagged
 * 
 * EXPECTED BEHAVIOR:
 * - This file should produce 3 TRUE POSITIVES (legitimate vulnerabilities)
 * - This file should produce 0 FALSE POSITIVES (library code, constants, etc.)
 * 
 * FIXED RULE DATE: 2024-01-XX
 * RULE ID: js-cleartext-network-taint-001
 * 
 * TEST COMMAND:
 * ./target/debug/sighthound tests/test_files/false_positives/cleartext_transmission_false_positives.js --code-type frontend --taint-analysis
 * 
 * EXPECTED RESULTS:
 * - 3 Clear-text Transmission vulnerabilities (lines 43, 52, 61)
 * - 0 false positives from library code section
 */

// ========================================================================
// TRUE POSITIVES: These SHOULD be detected as vulnerabilities
// ========================================================================

// 1. Real password field access transmitted over HTTP
function submitLoginForm() {
    var password = document.getElementById('password').value;
    var xhr = new XMLHttpRequest();
    xhr.open('POST', 'http://example.com/login'); // HTTP not HTTPS
    xhr.send(JSON.stringify({ password: password }));
}

// 2. Real form data with sensitive token transmitted over HTTP
function submitTokenForm() {
    var userToken = document.querySelector('input[name=token]').value;
    fetch('http://api.example.com/data', { // HTTP not HTTPS
        method: 'POST',
        body: JSON.stringify({ token: userToken })
    });
}

// 3. Real localStorage sensitive data transmitted over HTTP
function sendStoredApiKey() {
    var apiKey = localStorage.getItem('apiKey');
    var request = new XMLHttpRequest();
    request.open('GET', 'http://api.example.com/data?key=' + apiKey); // HTTP not HTTPS
    request.send();
}

// ========================================================================
// FALSE POSITIVES: These should NOT be detected (library code patterns)
// ========================================================================

// THREE.js-style constants (should NOT be flagged)
var DDPF_ALPHAPIXELS = 0x1;
var DDPF_ALPHA = 0x2;
var DDPF_FOURCC = 0x4;
var DDPF_RGB = 0x40;
var DDPF_YUV = 0x200;
var DDPF_LUMINANCE = 0x20000;

// THREE.js-style texture loading (should NOT be flagged)
function loadTexture(url, mapping, onLoad, onError) {
    var loader = new ImageLoader();
    loader.crossOrigin = this.crossOrigin;
    
    var texture = new Texture(undefined, mapping);
    var request = new XMLHttpRequest();
    
    request.onload = function() {
        var buffer = request.response;
        texture.needsUpdate = true;
        if (onLoad) onLoad(texture);
    };
    
    request.onerror = onError;
    request.open('GET', url, true);
    request.responseType = "arraybuffer";
    request.send(null);
    
    return texture;
}

// Generic library code with "sensitive" variable names (should NOT be flagged)
function processConfig() {
    var password = "hardcoded_config_value";
    var token = "Bearer " + "static_token";
    var key = "encryption_key_constant";
    var secret = "app_secret_constant";
    var apiKey = "public_api_key";
    
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'https://api.example.com/config'); // HTTPS is OK
    xhr.send();
}

// Function parameters with sensitive names (should NOT be flagged)
function authenticateUser(username, password, token, apiKey) {
    var request = new XMLHttpRequest();
    request.open('POST', 'https://secure.example.com/auth'); // HTTPS is OK
    request.send(JSON.stringify({
        username: username,
        // These are parameters, not DOM inputs
        password: password,
        token: token,
        apiKey: apiKey
    }));
}

// Graphics library patterns (should NOT be flagged)
var ImageUtils = {
    crossOrigin: undefined,
    
    loadCompressedTexture: function(url, mapping, onLoad, onError) {
        var texture = new CompressedTexture();
        texture.mapping = mapping;
        
        var request = new XMLHttpRequest();
        
        request.onload = function() {
            var buffer = request.response;
            texture.needsUpdate = true;
            if (onLoad) onLoad(texture);
        };
        
        request.onerror = onError;
        request.open('GET', url, true);
        request.responseType = "arraybuffer";
        request.send(null);
        
        return texture;
    }
};

// Crypto library constants (should NOT be flagged)
var CRYPTO_CONSTANTS = {
    DES_KEY_SIZE: 8,
    AES_KEY_SIZE: 32,
    RSA_KEY_SIZE: 2048,
    HMAC_SECRET_SIZE: 64
};

function initializeCrypto() {
    var key = CRYPTO_CONSTANTS.AES_KEY_SIZE;
    var secret = CRYPTO_CONSTANTS.HMAC_SECRET_SIZE;
    
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'https://crypto.example.com/init'); // HTTPS is OK
    xhr.send();
}

// Database connection strings (should NOT be flagged - these are config, not user input)
var DB_CONFIG = {
    password: "db_password_from_env",
    token: "db_access_token",
    key: "db_encryption_key"
};

function connectToDatabase() {
    var request = new XMLHttpRequest();
    request.open('POST', 'https://database.example.com/connect'); // HTTPS is OK
    request.send(JSON.stringify(DB_CONFIG));
}

// ========================================================================
// EDGE CASES: These should NOT be flagged
// ========================================================================

// Variable names that contain sensitive substrings but aren't actual sensitive data
var passwordValidator = "regex_pattern";
var tokenParser = "parsing_function";
var keyGenerator = "key_generation_algorithm";
var secretManager = "secret_management_service";

function utilityFunction() {
    var request = new XMLHttpRequest();
    request.open('GET', 'https://utils.example.com/tools'); // HTTPS is OK
    request.send();
}

// Comments and strings containing sensitive words (should NOT be flagged)
function documentedFunction() {
    // This function handles password validation
    // It also manages token refresh
    // API key rotation is handled separately
    
    var message = "Enter your password to continue";
    var instruction = "Your token will expire in 1 hour";
    
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'https://docs.example.com/help'); // HTTPS is OK
    xhr.send();
}

/**
 * REGRESSION TEST VALIDATION:
 * 
 * To validate this test file:
 * 1. Run: ./target/debug/sighthound tests/test_files/false_positives/cleartext_transmission_false_positives.js --code-type frontend --taint-analysis
 * 2. Expected: Exactly 3 Clear-text Transmission vulnerabilities
 * 3. Expected: 0 false positives from library code sections
 * 4. If more than 3 vulnerabilities are found, the rule has regressed
 * 5. If fewer than 3 vulnerabilities are found, the rule is too restrictive
 * 
 * MAINTENANCE:
 * - Update this file when adding new sensitive data patterns
 * - Add new false positive cases when encountered in real projects
 * - Keep the expected results count updated in comments
 */ 