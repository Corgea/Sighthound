// XSS False Negative Test Cases
// These test cases should be detected by our XSS taint analysis rules

// ==================== Case 1: innerHTML manipulation with user input ====================
// This case involves dynamic HTML content generation with user input
function updateFilterTags() {
    const activeFilters = document.getElementById('activeFilters');
    activeFilters.innerHTML = '';
    
    // Get all select elements
    const selects = document.querySelectorAll('.form-select');
    selects.forEach(select => {
        const selectedOptions = Array.from(select.selectedOptions);
        if (selectedOptions.length > 0) {
            const filterName = select.previousElementSibling.textContent.trim();
            selectedOptions.forEach(option => {
                const tag = document.createElement('span');
                tag.className = 'badge btn-secondary me-2 mb-2';
                // VULNERABILITY: User input flows to innerHTML without sanitization
                tag.innerHTML = `
                    ${filterName}: ${option.text}
                    <button type="button" class="btn-close btn-close ms-2" 
                            onclick="removeFilter('${select.id}', '${option.value}'); htmx.trigger('#applyFilterButton', 'click');" 
                            aria-label="Remove filter"></button>
                `;
                activeFilters.appendChild(tag);
            });
        }
    });
}

// Variant with URL parameter input
function updateFilterTagsFromURL() {
    const urlParams = new URLSearchParams(window.location.search);
    const filterValue = urlParams.get('filter');
    const activeFilters = document.getElementById('activeFilters');
    
    if (filterValue) {
        const tag = document.createElement('span');
        // VULNERABILITY: URL parameter flows to innerHTML
        tag.innerHTML = `Filter: ${filterValue}`;
        activeFilters.appendChild(tag);
    }
}

// Variant with localStorage input
function updateFilterTagsFromStorage() {
    const savedFilter = localStorage.getItem('userFilter');
    const activeFilters = document.getElementById('activeFilters');
    
    if (savedFilter) {
        const tag = document.createElement('span');
        // VULNERABILITY: localStorage content flows to innerHTML
        tag.innerHTML = `Saved: ${savedFilter}`;
        activeFilters.appendChild(tag);
    }
}

// ==================== Case 2: Dataset manipulation with user input ====================
// This case involves setting dataset properties with user-controlled data
function syncQueueOwner() {
    const allQueue = document.querySelectorAll('#queue');

    allQueue.forEach((queue) => {
        const list = Array.from(
            queue?.querySelectorAll('ytmusic-player-queue-item') ?? [],
        );

        list.forEach((item, index) => {
            if (typeof index !== 'number') return;

            const id = this._videoList[index]?.ownerId;
            const data = this.getProfile(id);

            const profile = item.querySelector('.music-together-owner') ?? 
                           document.createElement('img');
            profile.classList.add('music-together-owner');
            
            // VULNERABILITY: User data flows to dataset properties
            profile.dataset.id = id;
            profile.dataset.index = index.toString();

            const name = item.querySelector('.music-together-name') ?? 
                        document.createElement('div');
            name.classList.add('music-together-name');
            
            // VULNERABILITY: User data flows to textContent (this one should be safe)
            name.textContent = data?.name ?? 'Unknown User';

            if (data) {
                // VULNERABILITY: User data flows to dataset properties
                profile.dataset.thumbnail = data.thumbnail ?? '';
                profile.dataset.name = data.name ?? '';
                profile.dataset.handleId = data.handleId ?? '';
                profile.dataset.id = data.id ?? '';

                // VULNERABILITY: User data flows to src attribute
                profile.src = data.thumbnail ?? '';
                profile.title = data.name ?? '';
                profile.alt = data.handleId ?? '';
            }

            if (!profile.isConnected) item.append(profile);
            if (!name.isConnected) item.append(name);
        });
    });
}

// Variant with URL parameter input
function syncQueueOwnerFromURL() {
    const urlParams = new URLSearchParams(window.location.search);
    const userId = urlParams.get('userId');
    const userName = urlParams.get('userName');
    
    const profile = document.createElement('img');
    // VULNERABILITY: URL parameters flow to dataset
    profile.dataset.id = userId;
    profile.dataset.name = userName;
    profile.src = urlParams.get('avatar');
    
    document.body.appendChild(profile);
}

// ==================== Case 3: Script injection via srcdoc ====================
// This case involves creating script elements with user input
function createGistEmbed(link) {
    const RE_GH_GIST = /github\.com\/([^\/]+)\/([^\/]+)/;
    
    if (RE_GH_GIST.test(link)) {
        const [, user, gistId] = link.match(RE_GH_GIST);
        
        // This function should sanitize but doesn't fully protect
        const safeURL = escapeDoubleQuotes(`https://gist.github.com/${user}/${gistId}`);
        
        const iframe = document.createElement('iframe');
        // VULNERABILITY: User input flows to srcdoc with script tags
        iframe.srcdoc = `
            <script src="${safeURL}.js"></script>
            <style type="text/css">
                * { margin: 0px; }
                table, .gist { height: 100%; }
                .gist .gist-file { height: calc(100vh - 2px); padding: 0px; display: grid; grid-template-rows: 1fr auto; }
            </style>
        `;
        
        document.body.appendChild(iframe);
    }
}

// Helper function that provides minimal protection
function escapeDoubleQuotes(str) {
    return str.replace(/"/g, '&quot;');
}

// Variant with direct script creation
function createScriptFromURL() {
    const urlParams = new URLSearchParams(window.location.search);
    const scriptUrl = urlParams.get('script');
    
    if (scriptUrl) {
        const script = document.createElement('script');
        // VULNERABILITY: URL parameter flows to script src
        script.src = scriptUrl;
        document.head.appendChild(script);
    }
}

// ==================== Case 4: Sensitive data exposure via localStorage ====================
// This case involves storing sensitive error information
class ErrorBoundary {
    componentDidCatch(error, errorInfo) {
        const _localStorage = {};
        
        // VULNERABILITY: Copying all localStorage data including sensitive info
        for (const [key, value] of Object.entries({ ...localStorage })) {
            try {
                _localStorage[key] = JSON.parse(value);
            } catch (error) {
                _localStorage[key] = value;
            }
        }

        // VULNERABILITY: Storing sensitive data in state/storage
        this.setState({
            hasError: true,
            sentryEventId: 'some-event-id',
            localStorage: JSON.stringify(_localStorage),
        });
        
        // VULNERABILITY: Potentially exposing sensitive data in error reporting
        console.error('Error with localStorage:', JSON.stringify(_localStorage));
    }
}

// Variant with direct localStorage exposure
function debugUserSession() {
    const userToken = localStorage.getItem('authToken');
    const userSession = localStorage.getItem('sessionData');
    
    // VULNERABILITY: Sensitive data flows to console output
    console.log('Debug info:', userToken, userSession);
    
    // VULNERABILITY: Sensitive data flows to DOM
    document.getElementById('debug').innerHTML = `Token: ${userToken}`;
}

// ==================== Case 5: SVG manipulation without sanitization ====================
// This case involves manipulating SVG elements with user data
function useLibraryItemSvg(id, elements, svgCache) {
    if (elements) {
        if (id) {
            // Try to load cached svg
            const cachedSvg = svgCache.get(id);

            if (cachedSvg) {
                return cachedSvg;
            } else {
                // When there is no svg in cache export it and save to cache
                const exportedSvg = exportLibraryItemToSvg(elements);
                
                // VULNERABILITY: Only removes specific style element, user input may contain other malicious content
                exportedSvg.querySelector(".style-fonts")?.remove();

                if (exportedSvg) {
                    svgCache.set(id, exportedSvg);
                    return exportedSvg;
                }
            }
        } else {
            // When we have no id (usually selected items from canvas) just export the svg
            const exportedSvg = exportLibraryItemToSvg(elements);
            return exportedSvg;
        }
    }
}

// Mock function that processes user elements
function exportLibraryItemToSvg(elements) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    
    elements.forEach(element => {
        if (element.type === 'text') {
            const textElement = document.createElementNS('http://www.w3.org/2000/svg', 'text');
            // VULNERABILITY: User input flows to SVG content without sanitization
            textElement.innerHTML = element.content;
            svg.appendChild(textElement);
        } else if (element.type === 'style') {
            const styleElement = document.createElementNS('http://www.w3.org/2000/svg', 'style');
            styleElement.className = 'style-fonts';
            // VULNERABILITY: User input flows to style content
            styleElement.textContent = element.css;
            svg.appendChild(styleElement);
        }
    });
    
    return svg;
}

// Variant with direct SVG innerHTML manipulation
function createSVGFromUserInput() {
    const urlParams = new URLSearchParams(window.location.search);
    const svgContent = urlParams.get('svg');
    
    if (svgContent) {
        const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        // VULNERABILITY: URL parameter flows to SVG innerHTML
        svg.innerHTML = svgContent;
        document.body.appendChild(svg);
    }
}

// ==================== Additional XSS patterns ====================

// PostMessage XSS
window.addEventListener('message', function(event) {
    const data = event.data;
    
    // VULNERABILITY: PostMessage data flows to innerHTML
    document.getElementById('content').innerHTML = data.html;
    
    // VULNERABILITY: PostMessage data flows to script src
    if (data.scriptUrl) {
        const script = document.createElement('script');
        script.src = data.scriptUrl;
        document.head.appendChild(script);
    }
});

// Form data XSS
function handleFormSubmission() {
    const formData = new FormData(document.getElementById('userForm'));
    const userInput = formData.get('userContent');
    
    // VULNERABILITY: Form data flows to innerHTML
    document.getElementById('preview').innerHTML = userInput;
}

// AJAX response XSS
function loadUserContent() {
    fetch('/api/user-content')
        .then(response => response.text())
        .then(data => {
            // VULNERABILITY: Network response flows to innerHTML
            document.getElementById('userContent').innerHTML = data;
        });
}

// Template literal XSS
function renderTemplate(userInput) {
    const template = `<div>${userInput}</div>`;
    // VULNERABILITY: User input in template flows to innerHTML
    document.getElementById('output').innerHTML = template;
}

// Attribute XSS
function setUserAttributes() {
    const urlParams = new URLSearchParams(window.location.search);
    const userUrl = urlParams.get('url');
    const userTitle = urlParams.get('title');
    
    const link = document.createElement('a');
    // VULNERABILITY: URL parameter flows to href attribute
    link.href = userUrl;
    // VULNERABILITY: URL parameter flows to title attribute
    link.title = userTitle;
    
    document.body.appendChild(link);
}

// Event handler XSS
function addEventHandlers() {
    const urlParams = new URLSearchParams(window.location.search);
    const clickHandler = urlParams.get('onclick');
    
    const button = document.createElement('button');
    // VULNERABILITY: URL parameter flows to onclick attribute
    button.setAttribute('onclick', clickHandler);
    
    document.body.appendChild(button);
} 