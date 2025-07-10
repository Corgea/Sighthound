// Test cases for code injection vulnerabilities

// Case 1: Unsafe eval
function testUnsafeEval(userInput) {
    eval(userInput); // Should trigger code injection
}

// Case 2: Unsafe Function constructor
function testUnsafeFunction(userInput) {
    const func = new Function(userInput); // Should trigger code injection
    func();
}

// Case 3: Unsafe setTimeout
function testUnsafeSetTimeout(userInput) {
    setTimeout(userInput, 1000); // Should trigger code injection
}

// Case 4: Unsafe dynamic import
function testUnsafeImport(userInput) {
    import(userInput); // Should trigger dynamic code loading
}

// Case 5: Safe function usage
function testSafeFunction() {
    const func = new Function('return 42;'); // Should not trigger
    return func();
} 