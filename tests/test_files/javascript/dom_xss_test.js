// Test cases for DOM XSS vulnerabilities

// Case 1: innerHTML with unsanitized input
function testInnerHTML(userInput) {
    const div = document.createElement('div');
    div.innerHTML = userInput; // Should trigger DOM XSS
}

// Case 2: document.write with concatenation
function testDocumentWrite(userInput) {
    document.write('<div>' + userInput + '</div>'); // Should trigger DOM XSS
}

// Case 3: insertAdjacentHTML with unsanitized input
function testInsertAdjacentHTML(userInput) {
    const div = document.createElement('div');
    div.insertAdjacentHTML('beforeend', userInput); // Should trigger DOM XSS
}

// Case 4: Safe usage with sanitization
function testSafeInnerHTML(userInput) {
    const div = document.createElement('div');
    div.innerHTML = DOMPurify.sanitize(userInput); // Should not trigger
}

// Case 5: Safe usage with textContent
function testSafeTextContent(userInput) {
    const div = document.createElement('div');
    div.textContent = userInput; // Should not trigger
}

// Case 6: Function call chain DOM XSS (like in test fixtures)
function waitForElementsInnerHtmlToBe(selector, htmlContent) {
    const element = document.querySelector(selector);
    if (element) {
        element.innerHTML = htmlContent; // Should trigger DOM XSS
    }
}

// Case 7: Test fixture pattern with function call
function testFixturePattern() {
    const testFixture = {
        text: 'Hit enter again.',
        fixture: '.fill-remaining-space',
        unskippable: true,
        resolved: waitForElementsInnerHtmlToBe('#searchValue', '<h1>owasp</h1>') // Should be flagged
    };
    
    // More obvious XSS case with user input
    const userInput = window.location.search;
    waitForElementsInnerHtmlToBe('#searchValue', userInput); // Should definitely be caught
} 