// CWE-95 vs CWE-79 sink precision. Eval-family sinks are CWE-95.
// HTML writes, HTMX, DOMPurify, and parse-only template helpers are not.

// TP: eval / Function / setTimeout(string) with user input → CWE-95
function evalUser(userInput) {
    eval(userInput);
}

function functionUser(userInput) {
    const fn = new Function(userInput);
    return fn();
}

function timeoutUser(userInput) {
    setTimeout(userInput, 1000);
}

function evalFromHash() {
    eval(location.hash);
}

// TP XSS, not CWE-95: tainted HTML write
function xssFromHash() {
    document.body.innerHTML = location.hash;
}

// TN CWE-95: sanitized HTML write
function sanitizedInnerHtml(userInput) {
    const el = document.createElement('div');
    el.innerHTML = DOMPurify.sanitize(userInput);
}

// TN CWE-95: parse-only helper (doghouse issues_table.js shape)
function htmlToElement(html) {
    const template = document.createElement('template');
    template.innerHTML = html;
    return template.content.firstElementChild;
}

// TN CWE-95: textContent → escaped innerHTML helper
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// TN CWE-95: HTMX trigger is not eval
function applyFilters() {
    htmx.trigger('#applyFilterButton', 'click');
}

// TN CWE-95: Bootstrap / jQuery HTML without eval
function renderPanel(html) {
    $('.collapse').html(html);
    new bootstrap.Collapse(document.getElementById('panel'));
}

// TN CWE-95: setTimeout function callback is not eval
function delayedPaint(userInput) {
    setTimeout(function () {
        document.getElementById('out').textContent = userInput;
    }, 0);
}
