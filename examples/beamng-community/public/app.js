// State
let currentMods = [];
let currentCategory = '';
let currentSort = 'downloads';

// Navigation
function showHome() {
    document.getElementById('home-page').classList.remove('hidden');
    document.getElementById('mods-page').classList.add('hidden');
    document.getElementById('admin-page').classList.add('hidden');
    loadStats();
    loadFeaturedMods();
}

function showMods() {
    document.getElementById('home-page').classList.add('hidden');
    document.getElementById('mods-page').classList.remove('hidden');
    document.getElementById('admin-page').classList.add('hidden');
    loadMods();
}

function showAdmin() {
    document.getElementById('home-page').classList.add('hidden');
    document.getElementById('mods-page').classList.add('hidden');
    document.getElementById('admin-page').classList.remove('hidden');
    loadSecurityStats();
    loadDbStats();
}

// Load Data
async function loadStats() {
    const res = await fetch('/api/admin/stats');
    const stats = await res.json();
    
    document.getElementById('stats-grid').innerHTML = `
        <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
            <div class="text-3xl font-bold text-blue-500">${stats.totalMods}</div>
            <div class="text-gray-400">Total Mods</div>
        </div>
        <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
            <div class="text-3xl font-bold text-green-500">${stats.totalDownloads}</div>
            <div class="text-gray-400">Downloads</div>
        </div>
        <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
            <div class="text-3xl font-bold text-purple-500">${stats.totalReviews}</div>
            <div class="text-gray-400">Reviews</div>
        </div>
        <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
            <div class="text-3xl font-bold text-orange-500">${stats.totalUsers}</div>
            <div class="text-gray-400">Users</div>
        </div>
    `;
}

async function loadFeaturedMods() {
    const res = await fetch('/api/mods?sort=rating');
    const mods = await res.json();
    
    document.getElementById('featured-mods').innerHTML = mods.slice(0, 3).map(mod => createModCard(mod)).join('');
}

async function loadMods() {
    let url = `/api/mods?sort=${currentSort}`;
    if (currentCategory) url += `&category=${currentCategory}`;
    
    const res = await fetch(url);
    currentMods = await res.json();
    renderMods();
}

function renderMods() {
    const grid = document.getElementById('mods-grid');
    if (currentMods.length === 0) {
        grid.innerHTML = '<div class="col-span-3 text-center text-gray-400 py-12">No mods found</div>';
        return;
    }
    grid.innerHTML = currentMods.map(mod => createModCard(mod)).join('');
}

function createModCard(mod) {
    const stars = '⭐'.repeat(Math.round(mod.rating));
    return `
        <div class="bg-gray-800 rounded-lg overflow-hidden border border-gray-700 hover:border-blue-500 transition cursor-pointer" onclick="showModDetail(${mod.id})">
            <div class="aspect-video bg-gradient-to-br from-blue-900 to-purple-900 flex items-center justify-center">
                <i class="fas fa-car text-6xl text-gray-600"></i>
            </div>
            <div class="p-4">
                <h3 class="font-bold text-lg mb-2">${escapeHtml(mod.name)}</h3>
                <p class="text-gray-400 text-sm mb-3 line-clamp-2">${escapeHtml(mod.description)}</p>
                <div class="flex items-center justify-between text-sm">
                    <span class="text-gray-500">
                        <i class="fas fa-download"></i> ${mod.downloads.toLocaleString()}
                    </span>
                    <span class="text-yellow-500">${stars} ${mod.rating.toFixed(1)}</span>
                </div>
                <div class="mt-2">
                    <span class="inline-block bg-gray-700 px-2 py-1 rounded text-xs">${mod.category}</span>
                </div>
            </div>
        </div>
    `;
}

async function showModDetail(modId) {
    const [modRes, reviewsRes] = await Promise.all([
        fetch(`/api/mods/${modId}`),
        fetch(`/api/mods/${modId}/reviews`)
    ]);
    
    const mod = await modRes.json();
    const reviews = await reviewsRes.json();
    
    const stars = '⭐'.repeat(Math.round(mod.rating));
    
    document.getElementById('mod-detail-content').innerHTML = `
        <div class="p-6">
            <div class="flex justify-between items-start mb-4">
                <h2 class="text-2xl font-bold">${escapeHtml(mod.name)}</h2>
                <button onclick="closeModal()" class="text-gray-400 hover:text-white">
                    <i class="fas fa-times text-xl"></i>
                </button>
            </div>
            
            <div class="aspect-video bg-gradient-to-br from-blue-900 to-purple-900 flex items-center justify-center rounded-lg mb-4">
                <i class="fas fa-car text-9xl text-gray-600"></i>
            </div>
            
            <div class="mb-4">
                <span class="text-yellow-500 text-lg">${stars} ${mod.rating.toFixed(1)}</span>
                <span class="text-gray-400 ml-4">
                    <i class="fas fa-download"></i> ${mod.downloads.toLocaleString()} downloads
                </span>
            </div>
            
            <p class="text-gray-300 mb-6">${escapeHtml(mod.description)}</p>
            
            <button onclick="downloadMod(${mod.id})" class="w-full bg-blue-600 hover:bg-blue-700 py-3 rounded-lg font-semibold transition mb-6">
                <i class="fas fa-download mr-2"></i>Download Mod
            </button>
            
            <h3 class="text-xl font-bold mb-4">Reviews (${reviews.length})</h3>
            
            <div class="mb-4">
                <textarea id="review-comment" placeholder="Write your review..." class="w-full bg-gray-900 border border-gray-700 rounded-lg p-3 mb-2 resize-none" rows="3"></textarea>
                <div class="flex items-center justify-between">
                    <select id="review-rating" class="bg-gray-900 border border-gray-700 rounded-lg px-3 py-2">
                        <option value="5">⭐⭐⭐⭐⭐ 5 Stars</option>
                        <option value="4">⭐⭐⭐⭐ 4 Stars</option>
                        <option value="3">⭐⭐⭐ 3 Stars</option>
                        <option value="2">⭐⭐ 2 Stars</option>
                        <option value="1">⭐ 1 Star</option>
                    </select>
                    <button onclick="submitReview(${mod.id})" class="bg-green-600 hover:bg-green-700 px-6 py-2 rounded-lg transition">
                        Submit Review
                    </button>
                </div>
            </div>
            
            <div id="reviews-list" class="space-y-3 max-h-64 overflow-y-auto">
                ${reviews.map(review => `
                    <div class="bg-gray-900 rounded-lg p-3">
                        <div class="flex items-center justify-between mb-2">
                            <span class="font-semibold">${escapeHtml(review.username)}</span>
                            <span class="text-yellow-500">${'⭐'.repeat(review.rating)}</span>
                        </div>
                        <p class="text-gray-300 text-sm">${escapeHtml(review.comment)}</p>
                        <span class="text-gray-500 text-xs">${new Date(review.created_at).toLocaleDateString()}</span>
                    </div>
                `).join('')}
            </div>
        </div>
    `;
    
    document.getElementById('mod-modal').classList.remove('hidden');
}

function closeModal(event) {
    if (!event || event.target.id === 'mod-modal') {
        document.getElementById('mod-modal').classList.add('hidden');
    }
}

async function downloadMod(modId) {
    const res = await fetch(`/api/mods/${modId}/download`, { method: 'POST' });
    const data = await res.json();
    
    if (data.success) {
        alert('Download started! (Demo mode - actual file download would happen here)');
        showModDetail(modId); // Refresh to show updated download count
    }
}

async function submitReview(modId) {
    const comment = document.getElementById('review-comment').value;
    const rating = document.getElementById('review-rating').value;
    
    if (comment.length < 10) {
        alert('Review must be at least 10 characters');
        return;
    }
    
    const res = await fetch(`/api/mods/${modId}/reviews`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rating: parseInt(rating), comment })
    });
    
    const data = await res.json();
    
    if (data.success) {
        alert('Review submitted!');
        showModDetail(modId); // Refresh to show new review
    } else {
        alert('Error: ' + data.error);
    }
}

// Filters
function filterByCategory(category) {
    currentCategory = category;
    loadMods();
}

function sortMods(sort) {
    currentSort = sort;
    loadMods();
}

async function searchMods(query) {
    if (query.length < 2) {
        loadMods();
        return;
    }
    
    const res = await fetch(`/api/search?q=${encodeURIComponent(query)}`);
    currentMods = await res.json();
    renderMods();
}

// Security
async function loadSecurityStats() {
    const res = await fetch('/api/admin/security');
    const stats = await res.json();
    
    document.getElementById('security-stats').innerHTML = `
        <div class="flex justify-between">
            <span class="text-gray-400">Total Requests:</span>
            <span class="font-semibold">${stats.totalRequests}</span>
        </div>
        <div class="flex justify-between">
            <span class="text-gray-400">Threats Detected:</span>
            <span class="font-semibold text-yellow-500">${stats.threatsDetected}</span>
        </div>
        <div class="flex justify-between">
            <span class="text-gray-400">Threats Blocked:</span>
            <span class="font-semibold text-red-500">${stats.threatsBlocked}</span>
        </div>
    `;
}

async function loadDbStats() {
    const res = await fetch('/api/admin/stats');
    const stats = await res.json();
    
    document.getElementById('db-stats').innerHTML = `
        <div class="flex justify-between">
            <span class="text-gray-400">Total Mods:</span>
            <span class="font-semibold">${stats.totalMods}</span>
        </div>
        <div class="flex justify-between">
            <span class="text-gray-400">Total Users:</span>
            <span class="font-semibold">${stats.totalUsers}</span>
        </div>
        <div class="flex justify-between">
            <span class="text-gray-400">Total Reviews:</span>
            <span class="font-semibold">${stats.totalReviews}</span>
        </div>
        <div class="flex justify-between">
            <span class="text-gray-400">Total Downloads:</span>
            <span class="font-semibold">${stats.totalDownloads}</span>
        </div>
    `;
}

// Attack Tests
async function testSQLInjection() {
    showAttackResult('Testing SQL Injection...');
    const res = await fetch('/api/search?q=' + encodeURIComponent("' OR '1'='1"));
    const data = await res.json();
    showAttackResult(`SQL Injection test sent!\nCheck console for Aimless Security logs.\nResponse: ${JSON.stringify(data, null, 2)}`);
}

async function testXSS() {
    showAttackResult('Testing XSS Attack...');
    console.log('🧪 Testing XSS Attack - Sending malicious payload');
    const res = await fetch('/api/mods/1/reviews', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
            rating: 5, 
            comment: '<script>alert("XSS")</script>Test review with XSS attempt' 
        })
    });
    const data = await res.json();
    console.log('📡 XSS Test Response:', data);
    console.log('📊 Response Status:', res.status);
    showAttackResult(`XSS test sent!\nStatus: ${res.status}\nResponse: ${JSON.stringify(data, null, 2)}`);
}

async function testRateLimit() {
    showAttackResult('Testing Rate Limit...\nSending 50 requests rapidly...');
    console.log('🧪 Testing Rate Limit - Sending 50 rapid requests');
    
    const promises = [];
    for (let i = 0; i < 50; i++) {
        promises.push(fetch('/api/mods').then(r => ({ status: r.status, ok: r.ok })));
    }
    
    const results = await Promise.all(promises);
    const blocked = results.filter(r => r.status === 429).length;
    const successful = results.filter(r => r.ok).length;
    
    console.log('📊 Rate Limit Test Results:', {
        total: results.length,
        successful: successful,
        blocked: blocked,
        statuses: results.map(r => r.status)
    });
    
    showAttackResult(`Rate limit test completed!\nTotal: ${results.length}\nSuccessful: ${successful}\nBlocked (429): ${blocked}`);
}

function showAttackResult(message) {
    const resultsDiv = document.getElementById('attack-results');
    resultsDiv.classList.remove('hidden');
    resultsDiv.querySelector('pre').textContent = message;
}

// Utilities
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Initialize
showHome();
