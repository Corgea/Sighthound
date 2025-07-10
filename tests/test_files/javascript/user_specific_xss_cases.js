// User's specific XSS cases

// Case 1: Search filter with URL parameter
function userCase1() {
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
    
    // Vulnerable: URL parameter flows to innerHTML
    document.getElementById('filters').innerHTML = filterTagsHtml;
}

// Case 2: Form select elements with textContent
function userCase2() {
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

// Case 3: DOM querySelector with textContent
function userCase3() {
    const membersButton = document.getElementById('membersButton');
    
    // Update to show the first remaining member
    const firstMember = document.querySelector('.dropdown-item:not(.add-member-btn)');
    if (firstMember) {
        const memberName = firstMember.querySelector('span').textContent;
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