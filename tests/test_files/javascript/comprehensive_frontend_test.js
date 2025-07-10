// Comprehensive Frontend JavaScript Security Test
// This file tests all CWEs covered by the frontend security rules

// ==================== CWE-79: DOM-based XSS ====================
function domXssVulnerabilities(userInput) {
    // Vulnerable: innerHTML assignment
    document.getElementById('content').innerHTML = userInput;
    
    // Vulnerable: outerHTML assignment  
    document.getElementById('wrapper').outerHTML = userInput;
    
    // Vulnerable: document.write
    document.write('<div>' + userInput + '</div>');
    
    // Vulnerable: insertAdjacentHTML
    element.insertAdjacentHTML('beforeend', userInput);
    
    // Safe: sanitized innerHTML
    document.getElementById('safe').innerHTML = DOMPurify.sanitize(userInput);
    
    // Safe: textContent (no HTML parsing)
    document.getElementById('safe2').textContent = userInput;
}

// ==================== CWE-80 & CWE-95: Code Injection ====================
function codeInjectionVulnerabilities(userInput) {
    // Critical: eval with user input
    eval(userInput);
    
    // Critical: Function constructor with user input
    const dynamicFunc = new Function(userInput);
    
    // High: setTimeout with string (can execute code)
    setTimeout(userInput, 1000);
    
    // High: setInterval with string
    setInterval(userInput, 5000);
    
    // Safe: Function with hardcoded string
    const safeFunc = new Function('return 42;');
}

// ==================== CWE-200 & CWE-359: Information Exposure ====================
function informationExposure(password, token, apiKey, secret) {
    // Vulnerable: logging sensitive data
    console.log('User password: ' + password);
    console.log('Auth token: ' + token);
    console.debug('API key: ' + apiKey);
    console.debug('Secret: ' + secret);
    
    // Safe: logging non-sensitive data
    console.log('User logged in successfully');
}

// ==================== CWE-922: Insecure Storage ====================
function insecureStorage(password, token, apiKey, secret) {
    // Vulnerable: storing sensitive data in localStorage
    localStorage.setItem('user_password', password);
    localStorage.setItem('auth_token', token);
    sessionStorage.setItem('api_key', apiKey);
    sessionStorage.setItem('secret_key', secret);
    
    // Safe: storing non-sensitive data
    localStorage.setItem('user_preferences', 'dark_theme');
}

// ==================== CWE-601: Open Redirect ====================
function openRedirectVulnerabilities(redirectUrl) {
    // Vulnerable: unvalidated redirects
    window.location = redirectUrl;
    location.href = redirectUrl;
    location.assign(redirectUrl);
    location.replace(redirectUrl);
    
    // Safe: validated redirect (example)
    if (redirectUrl.startsWith('/app/')) {
        window.location = redirectUrl;
    }
}

// ==================== CWE-1173 & CWE-927: Insecure postMessage ====================
function postMessageVulnerabilities(data) {
    // Vulnerable: wildcard origin
    window.postMessage(data, '*');
    parent.postMessage(data, '*');
    
    // Vulnerable: missing origin validation in listener
    window.addEventListener('message', function(event) {
        // No origin validation - dangerous!
        document.getElementById('result').innerHTML = event.data;
    });
    
    // Safe: specific origin
    window.postMessage(data, 'https://trusted-domain.com');
    
    // Safe: origin validation
    window.addEventListener('message', function(event) {
        if (event.origin === 'https://trusted-domain.com') {
            document.getElementById('result').textContent = event.data;
        }
    });
}

// ==================== Prototype Pollution ====================
function prototypePollutionVulnerabilities(userInput) {
    const obj = {};
    
    // Vulnerable: direct prototype manipulation
    obj.__proto__ = userInput;
    obj['__proto__'] = userInput;
    obj["__proto__"] = userInput;
    
    // Safe: Object.create with null prototype
    const safeObj = Object.create(null);
}

// ==================== CWE-338: Weak Randomness ====================
function weakRandomness() {
    // Vulnerable: Math.random for security purposes
    const sessionId = Math.random().toString(36);
    const csrfToken = Math.random() * 1000000;
    
    // Safe: crypto.getRandomValues for security
    const secureRandom = crypto.getRandomValues(new Uint32Array(1))[0];
}

// ==================== CWE-319: Clear-text Network Requests ====================
function cleartextRequests() {
    // Vulnerable: HTTP requests
    fetch('http://api.example.com/data');
    fetch("http://insecure-api.com/user");
    
    const xhr = new XMLHttpRequest();
    xhr.open('GET', 'http://api.example.com/sensitive');
    
    // Vulnerable: HTTP with popular libraries
    axios.get('http://api.example.com/data');
    axios.post("http://api.example.com/submit");
    
    // Safe: HTTPS requests
    fetch('https://api.example.com/data');
    axios.get('https://secure-api.com/data');
}

// ==================== CWE-95: Dynamic Code Loading ====================
function dynamicCodeLoading(userModule, userScript) {
    // Vulnerable: dynamic imports with user input
    import(userModule).then(module => {
        module.execute();
    });
    
    // Vulnerable: require with user input (Node.js style)
    const userLib = require(userScript);
    
    // Safe: static imports
    import('./trusted-module.js').then(module => {
        module.execute();
    });
}

// ==================== CWE-1333: ReDoS ====================
function regexDoSVulnerabilities(userInput) {
    // Vulnerable: dynamic regex with user input
    const dynamicRegex = new RegExp(userInput);
    const result1 = 'test string'.match(userInput);
    const result2 = 'test string'.replace(userInput, 'replacement');
    const result3 = dynamicRegex.test('test string');
    
    // Safe: static regex patterns
    const safeRegex = /^[a-zA-Z0-9]+$/;
    const safeResult = safeRegex.test(userInput);
}

// ==================== CWE-1336: Template Injection ====================
function templateInjectionVulnerabilities(userTemplate) {
    // Vulnerable: client-side template compilation with user input
    const template1 = Handlebars.compile(userTemplate);
    const template2 = _.template(userTemplate);
    const template3 = someLibrary.compile(userTemplate);
    
    // Safe: pre-compiled templates
    const safeTemplate = Handlebars.compile('<div>{{safeData}}</div>');
    const result = safeTemplate({safeData: userTemplate});
} 