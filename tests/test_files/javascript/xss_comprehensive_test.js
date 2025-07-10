// Comprehensive XSS Test Cases - Both vulnerable and safe patterns
// This file tests the accuracy of our XSS detection rules

// ==================== VULNERABLE PATTERNS (Should be detected) ====================

// 1. innerHTML with user input from URL parameters
function vulnerableURLToInnerHTML() {
    const urlParams = new URLSearchParams(window.location.search);
    const userInput = urlParams.get('content');
    const element = document.getElementById('content');
    
    // VULNERABILITY: URL parameter flows to innerHTML
    element.innerHTML = userInput;
}

// 2. innerHTML with user input from localStorage
function vulnerableLocalStorageToInnerHTML() {
    const userContent = localStorage.getItem('userContent');
    const element = document.getElementById('display');
    
    // VULNERABILITY: localStorage content flows to innerHTML
    element.innerHTML = userContent;
}

// 3. innerHTML with user input from form data
function vulnerableFormDataToInnerHTML() {
    const form = document.getElementById('userForm');
    const formData = new FormData(form);
    const userInput = formData.get('message');
    const preview = document.getElementById('preview');
    
    // VULNERABILITY: Form data flows to innerHTML
    preview.innerHTML = userInput;
}

// 4. innerHTML with user input from PostMessage
function vulnerablePostMessageToInnerHTML() {
    window.addEventListener('message', function(event) {
        const data = event.data;
        const contentDiv = document.getElementById('content');
        
        // VULNERABILITY: PostMessage data flows to innerHTML
        contentDiv.innerHTML = data.html;
    });
}

// 5. innerHTML with user input from network response
function vulnerableNetworkToInnerHTML() {
    fetch('/api/user-content')
        .then(response => response.text())
        .then(data => {
            const userContent = document.getElementById('userContent');
            // VULNERABILITY: Network response flows to innerHTML
            userContent.innerHTML = data;
        });
}

// 6. Script src with user input
function vulnerableScriptSrc() {
    const urlParams = new URLSearchParams(window.location.search);
    const scriptUrl = urlParams.get('script');
    
    const script = document.createElement('script');
    // VULNERABILITY: URL parameter flows to script src
    script.src = scriptUrl;
    document.head.appendChild(script);
}

// 7. Iframe srcdoc with user input
function vulnerableIframeSrcdoc() {
    const urlParams = new URLSearchParams(window.location.search);
    const userContent = urlParams.get('content');
    
    const iframe = document.createElement('iframe');
    // VULNERABILITY: URL parameter flows to srcdoc
    iframe.srcdoc = `<html><body>${userContent}</body></html>`;
    document.body.appendChild(iframe);
}

// 8. SVG innerHTML with user input
function vulnerableSVGInnerHTML() {
    const urlParams = new URLSearchParams(window.location.search);
    const svgContent = urlParams.get('svg');
    
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    // VULNERABILITY: URL parameter flows to SVG innerHTML
    svg.innerHTML = svgContent;
    document.body.appendChild(svg);
}

// 9. Attribute manipulation with user input
function vulnerableAttributeManipulation() {
    const urlParams = new URLSearchParams(window.location.search);
    const userUrl = urlParams.get('url');
    const userTitle = urlParams.get('title');
    
    const link = document.createElement('a');
    // VULNERABILITY: URL parameters flow to href and title attributes
    link.href = userUrl;
    link.title = userTitle;
    
    document.body.appendChild(link);
}

// 10. Event handler with user input
function vulnerableEventHandler() {
    const urlParams = new URLSearchParams(window.location.search);
    const clickHandler = urlParams.get('onclick');
    
    const button = document.createElement('button');
    // VULNERABILITY: URL parameter flows to onclick attribute
    button.setAttribute('onclick', clickHandler);
    
    document.body.appendChild(button);
}

// 11. Dataset manipulation with user input
function vulnerableDatasetManipulation() {
    const urlParams = new URLSearchParams(window.location.search);
    const userId = urlParams.get('userId');
    const userData = urlParams.get('userData');
    
    const element = document.createElement('div');
    // VULNERABILITY: URL parameters flow to dataset
    element.dataset.id = userId;
    element.dataset.user = userData;
    
    document.body.appendChild(element);
}

// 12. Template literal with user input
function vulnerableTemplateLiteral() {
    const urlParams = new URLSearchParams(window.location.search);
    const userInput = urlParams.get('input');
    
    const template = `<div class="user-content">${userInput}</div>`;
    const output = document.getElementById('output');
    
    // VULNERABILITY: User input in template flows to innerHTML
    output.innerHTML = template;
}

// ==================== SAFE PATTERNS (Should NOT be detected) ====================

// 1. textContent is safe (not innerHTML)
function safeTextContent() {
    const urlParams = new URLSearchParams(window.location.search);
    const userInput = urlParams.get('content');
    const element = document.getElementById('content');
    
    // SAFE: textContent is not vulnerable to XSS
    element.textContent = userInput;
}

// 2. Static innerHTML (no user input)
function safeStaticInnerHTML() {
    const element = document.getElementById('content');
    
    // SAFE: Static content, no user input
    element.innerHTML = '<div>Welcome to our site!</div>';
}

// 3. Sanitized innerHTML
function safeSanitizedInnerHTML() {
    const urlParams = new URLSearchParams(window.location.search);
    const userInput = urlParams.get('content');
    const element = document.getElementById('content');
    
    // SAFE: Content is sanitized
    const sanitizedContent = DOMPurify.sanitize(userInput);
    element.innerHTML = sanitizedContent;
}

// 4. createElement with textContent
function safeCreateElement() {
    const urlParams = new URLSearchParams(window.location.search);
    const userInput = urlParams.get('content');
    
    const element = document.createElement('div');
    // SAFE: Using textContent instead of innerHTML
    element.textContent = userInput;
    
    document.body.appendChild(element);
}

// 5. createTextNode
function safeCreateTextNode() {
    const urlParams = new URLSearchParams(window.location.search);
    const userInput = urlParams.get('content');
    
    const textNode = document.createTextNode(userInput);
    const container = document.getElementById('container');
    
    // SAFE: createTextNode is not vulnerable
    container.appendChild(textNode);
}

// 6. URL validation before use
function safeURLValidation() {
    const urlParams = new URLSearchParams(window.location.search);
    const userUrl = urlParams.get('url');
    
    // SAFE: URL is validated before use
    if (isValidURL(userUrl) && userUrl.startsWith('https://trusted-domain.com')) {
        const link = document.createElement('a');
        link.href = userUrl;
        document.body.appendChild(link);
    }
}

// 7. Escaped HTML
function safeEscapedHTML() {
    const urlParams = new URLSearchParams(window.location.search);
    const userInput = urlParams.get('content');
    const element = document.getElementById('content');
    
    // SAFE: Content is escaped
    const escapedContent = escapeHTML(userInput);
    element.innerHTML = escapedContent;
}

// 8. Safe DOM operations
function safeDOMOperations() {
    const urlParams = new URLSearchParams(window.location.search);
    const className = urlParams.get('class');
    const styleValue = urlParams.get('style');
    
    const element = document.getElementById('target');
    
    // SAFE: These operations are generally safe
    element.className = className;
    element.style.color = styleValue;
}

// 9. Reading location (not setting)
function safeLocationReading() {
    const currentUrl = window.location.href;
    const currentPath = window.location.pathname;
    
    // SAFE: Reading location is safe
    console.log('Current URL:', currentUrl);
    console.log('Current path:', currentPath);
}

// 10. Safe event listeners
function safeEventListeners() {
    const button = document.getElementById('myButton');
    
    // SAFE: Adding event listeners is safe
    button.addEventListener('click', function() {
        console.log('Button clicked');
    });
}

// ==================== EDGE CASES ====================

// 1. Mixed safe and unsafe operations
function mixedOperations() {
    const urlParams = new URLSearchParams(window.location.search);
    const userInput = urlParams.get('content');
    const element = document.getElementById('content');
    
    // SAFE operation
    element.textContent = 'Loading...';
    
    // VULNERABILITY: This should still be detected
    element.innerHTML = userInput;
}

// 2. Conditional vulnerability
function conditionalVulnerability() {
    const urlParams = new URLSearchParams(window.location.search);
    const userInput = urlParams.get('content');
    const element = document.getElementById('content');
    const isAdmin = checkAdminStatus();
    
    if (isAdmin) {
        // VULNERABILITY: Still vulnerable even in conditional
        element.innerHTML = userInput;
    } else {
        // SAFE: Safe operation
        element.textContent = 'Access denied';
    }
}

// 3. Chained operations
function chainedOperations() {
    const urlParams = new URLSearchParams(window.location.search);
    const userInput = urlParams.get('content');
    
    // VULNERABILITY: User input flows through chain to innerHTML
    const processedInput = processUserInput(userInput);
    const finalContent = formatContent(processedInput);
    
    document.getElementById('content').innerHTML = finalContent;
}

// Helper functions
function isValidURL(url) {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
}

function escapeHTML(str) {
    return str.replace(/[&<>"']/g, function(match) {
        const escapeMap = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        };
        return escapeMap[match];
    });
}

function checkAdminStatus() {
    return false; // Mock function
}

function processUserInput(input) {
    return input; // Mock function
}

function formatContent(content) {
    return content; // Mock function
} 