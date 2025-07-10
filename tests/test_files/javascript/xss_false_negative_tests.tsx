// XSS False Negative Test Cases - TypeScript Version
// These test cases should be detected by our XSS taint analysis rules

// ==================== Case 1: innerHTML manipulation with user input ====================
// This case involves dynamic HTML content generation with user input
function updateFilterTags() {
    const activeFilters = document.getElementById('activeFilters');
    if (activeFilters) {
        activeFilters.innerHTML = '';
        
        // Get all select elements
        const selects = document.querySelectorAll('.form-select');
        selects.forEach(select => {
            const selectElement = select as HTMLSelectElement;
            const selectedOptions = Array.from(selectElement.selectedOptions);
            if (selectedOptions.length > 0) {
                const filterName = select.previousElementSibling?.textContent?.trim() || '';
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
}

// Variant with URL parameter input
function updateFilterTagsFromURL() {
    const urlParams = new URLSearchParams(window.location.search);
    const filterValue = urlParams.get('filter');
    const activeFilters = document.getElementById('activeFilters');
    
    if (filterValue && activeFilters) {
        const tag = document.createElement('span');
        // VULNERABILITY: URL parameter flows to innerHTML
        tag.innerHTML = `Filter: ${filterValue}`;
        activeFilters.appendChild(tag);
    }
}

// ==================== Case 2: Dataset manipulation with user input ====================
// This case involves setting dataset properties with user-controlled data
interface UserProfile {
    id: string;
    name: string;
    thumbnail?: string;
    handleId?: string;
}

interface VideoItem {
    ownerId: string;
}

class MusicQueueManager {
    private _videoList: VideoItem[] = [];

    syncQueueOwner(): void {
        const allQueue = document.querySelectorAll('#queue');

        allQueue.forEach((queue) => {
            const list = Array.from(
                queue?.querySelectorAll<HTMLElement>('ytmusic-player-queue-item') ?? [],
            );

            list.forEach((item, index: number) => {
                if (typeof index !== 'number') return;

                const id = this._videoList[index]?.ownerId;
                const data = this.getProfile(id);

                const profile = item.querySelector<HTMLImageElement>('.music-together-owner') ??
                               document.createElement('img');
                profile.classList.add('music-together-owner');

                // VULNERABILITY: User data flows to dataset properties
                profile.dataset.id = id;
                profile.dataset.index = index.toString();

                const name = item.querySelector<HTMLElement>('.music-together-name') ??
                            document.createElement('div');
                name.classList.add('music-together-name');

                // Safe: textContent is not vulnerable
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

    private getProfile(id: string): UserProfile | null {
        // Mock implementation
        return {
            id,
            name: `User ${id}`,
            thumbnail: `https://example.com/avatar/${id}`,
            handleId: `@user${id}`
        };
    }
}

// ==================== Case 3: Script injection via srcdoc ====================
// This case involves creating script elements with user input
function createGistEmbed(link: string): any {
    const RE_GH_GIST = /github\.com\/([^\/]+)\/([^\/]+)/;

    if (RE_GH_GIST.test(link)) {
        const match = link.match(RE_GH_GIST);
        if (match) {
            const [, user, gistId] = match;
            
            // This function provides minimal protection
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
            return iframe;
        }
    }
    return null;
}

function escapeDoubleQuotes(str: string): string {
    return str.replace(/"/g, '&quot;');
}

// ==================== Case 4: Sensitive data exposure via localStorage ====================
// This case involves storing sensitive error information
class ErrorBoundary {
    private hasError: boolean = false;
    private sentryEventId?: string;
    private localStorageData?: string;

    componentDidCatch(error: Error, errorInfo: any): void {
        const _localStorage: Record<string, any> = {};
        
        // VULNERABILITY: Copying all localStorage data including sensitive info
        for (const [key, value] of Object.entries({ ...localStorage })) {
            try {
                _localStorage[key] = JSON.parse(value);
            } catch (parseError) {
                _localStorage[key] = value;
            }
        }

        // VULNERABILITY: Storing sensitive data in component state
        this.hasError = true;
        this.sentryEventId = 'some-event-id';
        this.localStorageData = JSON.stringify(_localStorage);

        // VULNERABILITY: Potentially exposing sensitive data in error reporting
        console.error('Error with localStorage:', JSON.stringify(_localStorage));
    }

    render(): string {
        if (this.hasError) {
            // VULNERABILITY: Potentially exposing localStorage data in UI
            return `
                <div>
                    <h2>Something went wrong.</h2>
                    <details>
                        <summary>Debug Information</summary>
                        <pre>${this.localStorageData}</pre>
                    </details>
                </div>
            `;
        }
        return '';
    }
}

// Function variant
function debugUserSession(): void {
    const userToken = localStorage.getItem('authToken');
    const userSession = localStorage.getItem('sessionData');
    const apiKey = localStorage.getItem('apiKey');

    // VULNERABILITY: Sensitive data flows to console
    console.log('Debug info:', userToken, userSession, apiKey);

    // VULNERABILITY: Sensitive data flows to DOM
    const debugElement = document.getElementById('debug');
    if (debugElement && userToken) {
        debugElement.innerHTML = `<pre>Token: ${userToken}</pre>`;
    }
}

// ==================== Case 5: SVG manipulation without sanitization ====================
// This case involves manipulating SVG elements with user data
interface LibraryItem {
    id: string;
    elements: Array<{
        type: string;
        content?: string;
        css?: string;
        attributes?: Record<string, string>;
    }>;
}

type SvgCache = Map<string, SVGSVGElement>;

function useLibraryItemSvg(
    id: LibraryItem["id"] | null,
    elements: LibraryItem["elements"] | undefined,
    svgCache: SvgCache,
): SVGSVGElement | undefined {
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
    return undefined;
}

function exportLibraryItemToSvg(elements: LibraryItem["elements"]): SVGSVGElement {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    
    elements.forEach(element => {
        if (element.type === 'text') {
            const textElement = document.createElementNS('http://www.w3.org/2000/svg', 'text');
            // VULNERABILITY: User input flows to SVG content without sanitization
            textElement.innerHTML = element.content || '';
            
            // VULNERABILITY: User attributes flow to SVG element
            if (element.attributes) {
                Object.entries(element.attributes).forEach(([key, value]) => {
                    textElement.setAttribute(key, value);
                });
            }
            
            svg.appendChild(textElement);
        } else if (element.type === 'style') {
            const styleElement = document.createElementNS('http://www.w3.org/2000/svg', 'style');
            styleElement.setAttribute('class', 'style-fonts');
            // VULNERABILITY: User input flows to style content
            styleElement.textContent = element.css || '';
            svg.appendChild(styleElement);
        } else if (element.type === 'script') {
            const scriptElement = document.createElementNS('http://www.w3.org/2000/svg', 'script');
            // VULNERABILITY: User input flows to script content
            scriptElement.textContent = element.content || '';
            svg.appendChild(scriptElement);
        }
    });
    
    return svg;
}

// ==================== Additional XSS patterns ====================

// PostMessage XSS
function handlePostMessage(): void {
    window.addEventListener('message', function(event) {
        const data = event.data;
        
        // VULNERABILITY: PostMessage data flows to innerHTML
        const contentElement = document.getElementById('content');
        if (contentElement && data.html) {
            contentElement.innerHTML = data.html;
        }
        
        // VULNERABILITY: PostMessage data flows to script src
        if (data.scriptUrl) {
            const script = document.createElement('script');
            script.src = data.scriptUrl;
            document.head.appendChild(script);
        }
    });
}

// Form data XSS
function handleFormSubmission(): void {
    const form = document.getElementById('userForm') as HTMLFormElement;
    if (form) {
        form.addEventListener('submit', (event) => {
            event.preventDefault();
            const formData = new FormData(form);
            const userInput = formData.get('userContent') as string;
            
            // VULNERABILITY: Form data flows to innerHTML
            const preview = document.getElementById('preview');
            if (preview && userInput) {
                preview.innerHTML = userInput;
            }
        });
    }
}

// AJAX response XSS
function loadUserContent(): void {
    fetch('/api/user-content')
        .then(response => response.text())
        .then(data => {
            // VULNERABILITY: Network response flows to innerHTML
            const userContent = document.getElementById('userContent');
            if (userContent) {
                userContent.innerHTML = data;
            }
        });
}

// Template literal XSS
function renderTemplate(userInput: string): void {
    const template = `<div>${userInput}</div>`;
    // VULNERABILITY: User input in template flows to innerHTML
    const output = document.getElementById('output');
    if (output) {
        output.innerHTML = template;
    }
}

// Attribute XSS
function setUserAttributes(): void {
    const urlParams = new URLSearchParams(window.location.search);
    const userUrl = urlParams.get('url');
    const userTitle = urlParams.get('title');
    
    if (userUrl && userTitle) {
        const link = document.createElement('a');
        // VULNERABILITY: URL parameter flows to href attribute
        link.href = userUrl;
        // VULNERABILITY: URL parameter flows to title attribute
        link.title = userTitle;
        link.textContent = userTitle;
        
        document.body.appendChild(link);
    }
}

// Event handler XSS
function addEventHandlers(): void {
    const urlParams = new URLSearchParams(window.location.search);
    const clickHandler = urlParams.get('onclick');
    
    if (clickHandler) {
        const button = document.createElement('button');
        // VULNERABILITY: URL parameter flows to onclick attribute
        button.setAttribute('onclick', clickHandler);
        button.textContent = 'Click me';
        
        document.body.appendChild(button);
    }
}

// Export functions for testing
export {
    updateFilterTags,
    updateFilterTagsFromURL,
    MusicQueueManager,
    createGistEmbed,
    ErrorBoundary,
    debugUserSession,
    useLibraryItemSvg,
    exportLibraryItemToSvg,
    handlePostMessage,
    handleFormSubmission,
    loadUserContent,
    renderTemplate,
    setUserAttributes,
    addEventHandlers
}; 