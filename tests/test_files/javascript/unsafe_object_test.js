// Test cases for unsafe object operations

// Case 1: Unsafe JSON.parse
function testUnsafeJSONParse(userInput) {
    const data = JSON.parse(userInput); // Should trigger unsafe JSON parsing
}

// Case 2: Prototype pollution
function testPrototypePollution(userInput) {
    const obj = {};
    obj.__proto__ = userInput; // Should trigger prototype pollution
}

// Case 3: Unsafe Object.assign
function testUnsafeObjectAssign(userInput) {
    const target = {};
    Object.assign(target, userInput); // Should trigger prototype pollution
}

// Case 4: Safe JSON.parse with try-catch
function testSafeJSONParse(userInput) {
    try {
        const data = JSON.parse(userInput);
        return data;
    } catch (e) {
        return null;
    }
}

// Case 5: Safe object creation
function testSafeObjectCreate() {
    const obj = Object.create(null); // Should not trigger
    return obj;
} 