// Simple XSS Test Cases - Core patterns from the false negative cases
// These should be detected by our XSS taint analysis rules

// Case 1: innerHTML with user input from DOM elements
function updateFilterTags() {
    const activeFilters = document.getElementById('activeFilters');
    const selects = document.querySelectorAll('.form-select');
    
    selects.forEach(select => {
        const selectedOptions = Array.from(select.selectedOptions);
        selectedOptions.forEach(option => {
            const tag = document.createElement('span');
            // VULNERABILITY: User input flows to innerHTML
            tag.innerHTML = `Filter: ${option.text}`;
            activeFilters.appendChild(tag);
        });
    });
}

// Case 2: innerHTML with URL parameters
function updateFromURL() {
    const urlParams = new URLSearchParams(window.location.search);
    const filterValue = urlParams.get('filter');
    const element = document.getElementById('content');
    
    if (filterValue) {
        // VULNERABILITY: URL parameter flows to innerHTML
        element.innerHTML = `<div>Filter: ${filterValue}</div>`;
    }
}

// Case 3: Dataset manipulation with user data
function setUserData() {
    const urlParams = new URLSearchParams(window.location.search);
    const userId = urlParams.get('userId');
    const userName = urlParams.get('userName');
    
    const profile = document.createElement('img');
    // VULNERABILITY: URL parameters flow to dataset
    profile.dataset.id = userId;
    profile.dataset.name = userName;
    // VULNERABILITY: URL parameter flows to src attribute
    profile.src = urlParams.get('avatar');
    
    document.body.appendChild(profile);
}

// Case 4: Script injection via srcdoc
function createEmbed(userUrl) {
    const iframe = document.createElement('iframe');
    // VULNERABILITY: User input flows to srcdoc with script tag
    iframe.srcdoc = `<script src="${userUrl}"></script>`;
    document.body.appendChild(iframe);
}

// Case 5: localStorage exposure
function debugSession() {
    const userToken = localStorage.getItem('authToken');
    const debugElement = document.getElementById('debug');
    
    // VULNERABILITY: Sensitive data flows to innerHTML
    debugElement.innerHTML = `<pre>Token: ${userToken}</pre>`;
}

// Case 6: SVG manipulation
function createSVG(userContent) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    const textElement = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    
    // VULNERABILITY: User input flows to SVG innerHTML
    textElement.innerHTML = userContent;
    svg.appendChild(textElement);
    
    document.body.appendChild(svg);
}

// Case 7: PostMessage handling
window.addEventListener('message', function(event) {
    const data = event.data;
    const contentElement = document.getElementById('content');
    
    // VULNERABILITY: PostMessage data flows to innerHTML
    contentElement.innerHTML = data.html;
});

// Case 8: Form data handling
function handleForm() {
    const form = document.getElementById('userForm');
    form.addEventListener('submit', (event) => {
        event.preventDefault();
        const formData = new FormData(form);
        const userInput = formData.get('userContent');
        const preview = document.getElementById('preview');
        
        // VULNERABILITY: Form data flows to innerHTML
        preview.innerHTML = userInput;
    });
}

// Case 9: AJAX response handling
function loadContent() {
    fetch('/api/user-content')
        .then(response => response.text())
        .then(data => {
            const userContent = document.getElementById('userContent');
            // VULNERABILITY: Network response flows to innerHTML
            userContent.innerHTML = data;
        });
}

// Case 10: Attribute manipulation
function setAttributes() {
    const urlParams = new URLSearchParams(window.location.search);
    const userUrl = urlParams.get('url');
    const userTitle = urlParams.get('title');
    
    const link = document.createElement('a');
    // VULNERABILITY: URL parameters flow to href and title attributes
    link.href = userUrl;
    link.title = userTitle;
    
    document.body.appendChild(link);
}

// Case 11: Event handler injection
function addHandler() {
    const urlParams = new URLSearchParams(window.location.search);
    const clickHandler = urlParams.get('onclick');
    
    const button = document.createElement('button');
    // VULNERABILITY: URL parameter flows to onclick attribute
    button.setAttribute('onclick', clickHandler);
    
    document.body.appendChild(button);
}

// Case 12: Template literal injection
function renderTemplate(userInput) {
    const template = `<div>${userInput}</div>`;
    const output = document.getElementById('output');
    
    // VULNERABILITY: User input in template flows to innerHTML
    output.innerHTML = template;
} 