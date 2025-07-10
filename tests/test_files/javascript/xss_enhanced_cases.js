// Enhanced XSS test cases from user examples

// Case 1: URL search parameter to template literal with innerHTML
function testCase1() {
    const currentUrl = new URL(window.location.href);
    const search = currentUrl.searchParams.get('search');
    let filterTagsHtml = '';
    
    if (search) {
        filterTagsHtml += `
            <span class="badge btn-outline-secondary rounded-pill d-flex align-items-center p-2 ps-3">
                <span class="me-2">Search: ${search}</span>
                <button type="button" class="btn-close"
                        onclick="removeFilter('search')"
                        aria-label="Remove filter"
                        style="font-size: 0.65rem"></button>
            </span>
        `;
    }
    
    // Vulnerable: search parameter flows to innerHTML
    document.getElementById('filters').innerHTML = filterTagsHtml;
}

// Case 2: DOM element text content to template literal with innerHTML
function testCase2() {
    const activeFilters = document.getElementById('activeFilters');
    
    // Get all select elements
    const selects = document.querySelectorAll('.form-select');
    selects.forEach(select => {
        const selectedOptions = Array.from(select.selectedOptions);
        if (selectedOptions.length > 0) {
            const filterName = select.previousElementSibling.textContent.trim();
            selectedOptions.forEach(option => {
                const tag = document.createElement('span');
                tag.className = 'badge btn-secondary me-2 mb-2';
                
                // Vulnerable: option.text and filterName (textContent) flow to innerHTML
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

// Case 3: DOM querySelector textContent to template literal with innerHTML
function testCase3() {
    const membersButton = document.getElementById('membersButton');
    
    // Update to show the first remaining member
    const firstMember = document.querySelector('.dropdown-item:not(.add-member-btn)');
    if (firstMember) {
        const memberName = firstMember.querySelector('span').textContent;
        
        // Vulnerable: memberName (textContent) flows to innerHTML
        membersButton.innerHTML = `
            <div class="d-flex align-items-center">
                <div class="me-2" style="width: 20px;">
                    <i class="fas fa-user-circle text-secondary"></i>
                </div>
                <span class="text-white">${memberName}</span>
            </div>
        `;
    }
}

// Additional test cases for similar patterns
function testCase4() {
    // URL parameter variations
    const url = new URL(document.location);
    const query = url.searchParams.get('q');
    const filter = url.searchParams.get('filter');
    
    // Vulnerable: URL parameters to innerHTML
    document.getElementById('search-results').innerHTML = `<h2>Results for: ${query}</h2>`;
    document.getElementById('filter-display').innerHTML = `<span>Filter: ${filter}</span>`;
}

function testCase5() {
    // DOM element content variations
    const input = document.querySelector('input[name="search"]');
    const select = document.querySelector('select');
    const textarea = document.querySelector('textarea');
    
    if (input && select && textarea) {
        const searchValue = input.value;
        const selectText = select.options[select.selectedIndex].text;
        const textareaContent = textarea.value;
        
        // Vulnerable: various DOM element content to innerHTML
        document.getElementById('output').innerHTML = `
            <div>Search: ${searchValue}</div>
            <div>Selected: ${selectText}</div>
            <div>Content: ${textareaContent}</div>
        `;
    }
}

function testCase6() {
    // Element textContent and innerText variations
    const elements = document.querySelectorAll('.user-content');
    let html = '';
    
    elements.forEach(element => {
        const textContent = element.textContent;
        const innerText = element.innerText;
        
        // Vulnerable: textContent and innerText to innerHTML
        html += `<div>Text: ${textContent}</div>`;
        html += `<div>Inner: ${innerText}</div>`;
    });
    
    document.getElementById('combined-output').innerHTML = html;
}

function testCase7() {
    // More specific querySelector patterns
    const userSpan = document.querySelector('.user-name span');
    const titleDiv = document.querySelector('.title div');
    
    if (userSpan && titleDiv) {
        const userName = userSpan.textContent;
        const titleText = titleDiv.innerHTML;
        
        // Vulnerable: querySelector textContent and innerHTML to innerHTML
        document.getElementById('user-info').innerHTML = `
            <h3>User: ${userName}</h3>
            <p>Title: ${titleText}</p>
        `;
    }
} 