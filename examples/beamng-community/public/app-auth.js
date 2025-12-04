// Global State
let currentUser = null;
let currentMods = [];
let currentCategory = '';
let currentSort = 'downloads';
let favorites = JSON.parse(localStorage.getItem('favorites') || '[]');

// Utility function to escape HTML
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Check if user is logged in on page load
async function checkAuth() {
  try {
    const res = await fetch('/api/auth/me');
    if (res.ok) {
      currentUser = await res.json();
      updateAuthUI();
    }
  } catch (error) {
    console.log('Not logged in');
  }
  
  // Update favorites count
  updateFavoritesCount();
}

function updateFavoritesCount() {
  const badge = document.getElementById('favorites-count');
  if (badge) {
    if (favorites.length > 0) {
      badge.textContent = favorites.length;
      badge.classList.remove('hidden');
    } else {
      badge.classList.add('hidden');
    }
  }
}

// Update UI based on auth state
function updateAuthUI() {
  const authButtons = document.getElementById('auth-buttons');
  const userMenu = document.getElementById('user-menu');
  const uploadBtn = document.getElementById('upload-mod-btn');
  const adminLink = document.getElementById('admin-link');
  
  if (currentUser) {
    authButtons.classList.add('hidden');
    userMenu.classList.remove('hidden');
    if (uploadBtn) uploadBtn.classList.remove('hidden');
    
    // Show admin link only for admin users
    if (adminLink && currentUser.role === 'admin') {
      adminLink.classList.remove('hidden');
    } else if (adminLink) {
      adminLink.classList.add('hidden');
    }
    
    document.getElementById('user-avatar').src = currentUser.avatar_url || `https://api.dicebear.com/7.x/avataaars/svg?seed=${currentUser.username}`;
    document.getElementById('user-name').textContent = currentUser.username;
  } else {
    authButtons.classList.remove('hidden');
    userMenu.classList.add('hidden');
    if (uploadBtn) uploadBtn.classList.add('hidden');
    if (adminLink) adminLink.classList.add('hidden');
  }
}

// Show toast notification
function showToast(message, type = 'success') {
  const toast = document.createElement('div');
  const bgColor = type === 'success' ? 'bg-green-600' : type === 'error' ? 'bg-red-600' : 'bg-blue-600';
  const icon = type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle';
  
  toast.className = `fixed bottom-4 right-4 ${bgColor} px-6 py-4 rounded-lg shadow-2xl transform transition-all duration-300 z-50 translate-y-0 opacity-100`;
  toast.style.animation = 'slideIn 0.3s ease-out';
  toast.innerHTML = `
    <div class="flex items-center space-x-3">
      <i class="fas fa-${icon} text-xl"></i>
      <span class="font-medium">${message}</span>
    </div>
  `;
  
  // Add animation keyframes if not already added
  if (!document.getElementById('toast-animations')) {
    const style = document.createElement('style');
    style.id = 'toast-animations';
    style.textContent = `
      @keyframes slideIn {
        from { transform: translateY(100px); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
      }
      @keyframes slideOut {
        from { transform: translateY(0); opacity: 1; }
        to { transform: translateY(100px); opacity: 0; }
      }
    `;
    document.head.appendChild(style);
  }
  
  document.body.appendChild(toast);
  
  // Remove with animation
  setTimeout(() => {
    toast.style.animation = 'slideOut 0.3s ease-in';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// Show/Hide modals
function showLoginModal() {
  document.getElementById('login-modal').classList.remove('hidden');
}

function hideLoginModal() {
  document.getElementById('login-modal').classList.add('hidden');
  document.getElementById('login-form').reset();
}

function showSignupModal() {
  document.getElementById('signup-modal').classList.remove('hidden');
}

function hideSignupModal() {
  document.getElementById('signup-modal').classList.add('hidden');
  document.getElementById('signup-form').reset();
}

function showUploadModal() {
  if (!currentUser) {
    showToast('Please login to upload mods', 'error');
    showLoginModal();
    return;
  }
  document.getElementById('upload-modal').classList.remove('hidden');
}

function hideUploadModal() {
  document.getElementById('upload-modal').classList.add('hidden');
  document.getElementById('upload-form').reset();
  document.getElementById('image-preview').classList.add('hidden');
}

// Auth handlers
async function handleLogin(e) {
  e.preventDefault();
  const formData = new FormData(e.target);
  
  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: formData.get('username'),
        password: formData.get('password')
      })
    });
    
    const data = await res.json();
    
    if (res.ok) {
      currentUser = data.user;
      updateAuthUI();
      hideLoginModal();
      showToast('Welcome back, ' + currentUser.username + '! 👋');
    } else {
      showToast(data.error || 'Login failed', 'error');
    }
  } catch (error) {
    showToast('Login failed', 'error');
  }
}

async function handleSignup(e) {
  e.preventDefault();
  const formData = new FormData(e.target);
  
  const password = formData.get('password');
  const confirmPassword = formData.get('confirmPassword');
  
  if (password !== confirmPassword) {
    showToast('Passwords do not match', 'error');
    return;
  }
  
  try {
    const res = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: formData.get('username'),
        email: formData.get('email'),
        password: password
      })
    });
    
    const data = await res.json();
    
    if (res.ok) {
      currentUser = data.user;
      updateAuthUI();
      hideSignupModal();
      showToast('Welcome to the community, ' + currentUser.username + '! 🎉');
    } else {
      showToast(data.error || 'Signup failed', 'error');
    }
  } catch (error) {
    showToast('Signup failed', 'error');
  }
}

async function handleLogout() {
  try {
    await fetch('/api/auth/logout', { method: 'POST' });
    currentUser = null;
    updateAuthUI();
    showToast('Logged out successfully');
    showHome();
  } catch (error) {
    showToast('Logout failed', 'error');
  }
}

// Image preview
function handleImageSelect(e) {
  const file = e.target.files[0];
  if (file) {
    const reader = new FileReader();
    reader.onload = (e) => {
      const preview = document.getElementById('image-preview');
      preview.innerHTML = `<img src="${e.target.result}" class="w-full h-48 object-cover rounded-lg">`;
      preview.classList.remove('hidden');
    };
    reader.readAsDataURL(file);
  }
}

// Upload mod
async function handleUploadMod(e) {
  e.preventDefault();
  const formData = new FormData(e.target);
  
  try {
    const res = await fetch('/api/mods', {
      method: 'POST',
      body: formData
    });
    
    const data = await res.json();
    
    if (res.ok) {
      hideUploadModal();
      showToast('Mod uploaded successfully!');
      loadMods();
    } else {
      showToast(data.error || 'Upload failed', 'error');
    }
  } catch (error) {
    showToast('Upload failed', 'error');
  }
}

// Navigation
function showHome() {
  document.getElementById('home-page').classList.remove('hidden');
  document.getElementById('mods-page').classList.add('hidden');
  document.getElementById('admin-page').classList.add('hidden');
  document.getElementById('profile-page').classList.add('hidden');
  loadStats();
  loadFeaturedMods();
}

function showMods() {
  document.getElementById('home-page').classList.add('hidden');
  document.getElementById('mods-page').classList.remove('hidden');
  document.getElementById('admin-page').classList.add('hidden');
  document.getElementById('profile-page').classList.add('hidden');
  loadMods();
  
  // Load quick stats
  fetch('/api/stats')
    .then(res => res.json())
    .then(stats => {
      const statsHtml = `
        <div class="flex gap-4 mb-4 overflow-x-auto pb-2">
          <div class="bg-gradient-to-br from-blue-600 to-blue-700 px-6 py-3 rounded-lg flex items-center gap-3 min-w-fit shadow-lg">
            <i class="fas fa-cube text-2xl"></i>
            <div>
              <div class="text-2xl font-bold">${stats.totalMods || 0}</div>
              <div class="text-xs opacity-90">Total Mods</div>
            </div>
          </div>
          <div class="bg-gradient-to-br from-purple-600 to-purple-700 px-6 py-3 rounded-lg flex items-center gap-3 min-w-fit shadow-lg">
            <i class="fas fa-download text-2xl"></i>
            <div>
              <div class="text-2xl font-bold">${(stats.totalDownloads || 0).toLocaleString()}</div>
              <div class="text-xs opacity-90">Downloads</div>
            </div>
          </div>
          <div class="bg-gradient-to-br from-yellow-600 to-yellow-700 px-6 py-3 rounded-lg flex items-center gap-3 min-w-fit shadow-lg">
            <i class="fas fa-star text-2xl"></i>
            <div>
              <div class="text-2xl font-bold">${stats.totalReviews || 0}</div>
              <div class="text-xs opacity-90">Reviews</div>
            </div>
          </div>
          <div class="bg-gradient-to-br from-green-600 to-green-700 px-6 py-3 rounded-lg flex items-center gap-3 min-w-fit shadow-lg">
            <i class="fas fa-users text-2xl"></i>
            <div>
              <div class="text-2xl font-bold">${stats.totalUsers || 0}</div>
              <div class="text-xs opacity-90">Users</div>
            </div>
          </div>
        </div>
      `;
      const container = document.getElementById('mods-stats');
      if (container) container.innerHTML = statsHtml;
    })
    .catch(() => {});
}

function showAdmin() {
  // Check if user is admin
  if (!currentUser || currentUser.role !== 'admin') {
    showToast('Admin access required', 'error');
    return;
  }
  
  document.getElementById('home-page').classList.add('hidden');
  document.getElementById('mods-page').classList.add('hidden');
  document.getElementById('admin-page').classList.remove('hidden');
  document.getElementById('profile-page').classList.add('hidden');
  document.getElementById('favorites-page').classList.add('hidden');
  loadSecurityStats();
  loadDbStats();
}

function showFavorites() {
  document.querySelectorAll('.page').forEach(p => p.classList.add('hidden'));
  document.getElementById('favorites-page').classList.remove('hidden');
  loadFavorites();
}

async function showProfile(username) {
  const targetUsername = username || (currentUser && currentUser.username);
  if (!targetUsername) {
    showToast('User not found', 'error');
    return;
  }
  
  try {
    const res = await fetch(`/api/users/${targetUsername}`);
    const profile = await res.json();
    
    if (res.ok) {
      renderProfile(profile);
      document.getElementById('home-page').classList.add('hidden');
      document.getElementById('mods-page').classList.add('hidden');
      document.getElementById('admin-page').classList.add('hidden');
      document.getElementById('profile-page').classList.remove('hidden');
    } else {
      showToast('Profile not found', 'error');
    }
  } catch (error) {
    showToast('Failed to load profile', 'error');
  }
}

function renderProfile(profile) {
  const isOwnProfile = currentUser && currentUser.username === profile.username;
  
  document.getElementById('profile-content').innerHTML = `
    <div class="bg-gray-800 rounded-lg p-8 mb-6">
      <div class="flex items-start space-x-6">
        <img src="${profile.avatar_url}" class="w-24 h-24 rounded-full">
        <div class="flex-1">
          <h2 class="text-3xl font-bold mb-2">${escapeHtml(profile.username)}</h2>
          <p class="text-gray-400 mb-4">${escapeHtml(profile.bio || 'No bio yet')}</p>
          <div class="flex space-x-6 text-sm">
            <div>
              <span class="text-gray-400">Joined:</span>
              <span class="text-white">${new Date(profile.created_at).toLocaleDateString()}</span>
            </div>
            <div>
              <span class="text-gray-400">Mods:</span>
              <span class="text-blue-500 font-bold">${profile.stats.totalMods}</span>
            </div>
            <div>
              <span class="text-gray-400">Total Downloads:</span>
              <span class="text-green-500 font-bold">${profile.stats.totalDownloads.toLocaleString()}</span>
            </div>
            <div>
              <span class="text-gray-400">Avg Rating:</span>
              <span class="text-yellow-500 font-bold">${profile.stats.averageRating.toFixed(1)} ⭐</span>
            </div>
          </div>
        </div>
        ${isOwnProfile ? '<button onclick="editProfile()" class="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg"><i class="fas fa-edit"></i> Edit Profile</button>' : ''}
      </div>
    </div>
    
    <div class="mb-6">
      <h3 class="text-2xl font-bold mb-4">Uploaded Mods (${profile.mods.length})</h3>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
        ${profile.mods.length > 0 ? profile.mods.map(mod => createModCard(mod)).join('') : '<div class="text-gray-400">No mods uploaded yet</div>'}
      </div>
    </div>
    
    <div>
      <h3 class="text-2xl font-bold mb-4">Recent Reviews (${profile.reviews.length})</h3>
      <div class="space-y-4">
        ${profile.reviews.length > 0 ? profile.reviews.map(review => `
          <div class="bg-gray-800 rounded-lg p-4">
            <div class="flex items-center justify-between mb-2">
              <a href="#" onclick="showModDetail(${review.mod_id})" class="text-blue-400 hover:text-blue-300">
                ${escapeHtml(review.mod_name)}
              </a>
              <span class="text-yellow-500">${'⭐'.repeat(review.rating)}</span>
            </div>
            <p class="text-gray-300">${escapeHtml(review.comment)}</p>
            <span class="text-xs text-gray-500">${new Date(review.created_at).toLocaleDateString()}</span>
          </div>
        `).join('') : '<div class="text-gray-400">No reviews yet</div>'}
      </div>
    </div>
  `;
}

// Load Data
async function loadStats() {
  try {
    const res = await fetch('/api/admin/stats');
    if (!res.ok) {
      console.error('Failed to load stats');
      return;
    }
    const stats = await res.json();
    
    document.getElementById('stats-grid').innerHTML = `
      <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <div class="text-3xl font-bold text-blue-500">${stats.totalMods || 0}</div>
        <div class="text-gray-400">Total Mods</div>
      </div>
      <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <div class="text-3xl font-bold text-green-500">${(stats.totalDownloads || 0).toLocaleString()}</div>
        <div class="text-gray-400">Downloads</div>
      </div>
      <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <div class="text-3xl font-bold text-purple-500">${stats.totalReviews || 0}</div>
        <div class="text-gray-400">Reviews</div>
      </div>
      <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <div class="text-3xl font-bold text-orange-500">${stats.totalUsers || 0}</div>
        <div class="text-gray-400">Users</div>
      </div>
    `;
  } catch (error) {
    console.error('Error loading stats:', error);
  }
}

async function loadFeaturedMods() {
  const container = document.getElementById('featured-mods');
  
  // Show skeleton loading
  container.innerHTML = `
    ${[1, 2, 3].map(() => `
      <div class="bg-gray-800 rounded-lg overflow-hidden border border-gray-700 animate-pulse">
        <div class="aspect-video bg-gray-700"></div>
        <div class="p-4 space-y-3">
          <div class="h-4 bg-gray-700 rounded w-3/4"></div>
          <div class="h-3 bg-gray-700 rounded"></div>
          <div class="h-3 bg-gray-700 rounded w-5/6"></div>
        </div>
      </div>
    `).join('')}
  `;
  
  try {
    const res = await fetch('/api/mods?sort=rating');
    const mods = await res.json();
    container.innerHTML = mods.slice(0, 3).map(mod => createModCard(mod)).join('');
  } catch (error) {
    container.innerHTML = '<div class="col-span-3 text-center text-gray-400">Failed to load featured mods</div>';
  }
}

async function loadMods() {
  const grid = document.getElementById('mods-grid');
  
  // Show loading state
  grid.innerHTML = `
    <div class="col-span-3 flex justify-center items-center py-12">
      <div class="text-center">
        <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
        <p class="text-gray-400">Loading mods...</p>
      </div>
    </div>
  `;
  
  try {
    let url = `/api/mods?sort=${currentSort}`;
    if (currentCategory) url += `&category=${currentCategory}`;
    
    const res = await fetch(url);
    currentMods = await res.json();
    renderMods();
  } catch (error) {
    grid.innerHTML = `
      <div class="col-span-3 text-center py-12">
        <i class="fas fa-exclamation-triangle text-4xl text-red-500 mb-4"></i>
        <p class="text-gray-400">Failed to load mods. Please try again.</p>
      </div>
    `;
  }
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
  const imageUrl = mod.image_url || 'https://images.unsplash.com/photo-1568605117036-5fe5e7bab0b7?w=400&auto=format&fit=crop';
  const isFavorite = favorites.includes(mod.id);
  
  return `
    <div class="bg-gray-800 rounded-lg overflow-hidden border border-gray-700 hover:border-blue-500 transition-all duration-300 cursor-pointer transform hover:scale-105 hover:shadow-2xl group" onclick="showModDetail(${mod.id})">
      <div class="aspect-video bg-gradient-to-br from-blue-900 to-purple-900 overflow-hidden relative">
        <img src="${imageUrl}" class="w-full h-full object-cover transition-transform duration-500 group-hover:scale-110" onerror="this.src='https://images.unsplash.com/photo-1568605117036-5fe5e7bab0b7?w=400&auto=format&fit=crop'">
        <div class="absolute inset-0 bg-gradient-to-t from-black via-transparent to-transparent opacity-60"></div>
        <button onclick="toggleFavorite(${mod.id}, event)" class="absolute top-3 right-3 bg-gray-900 bg-opacity-75 backdrop-blur-sm w-10 h-10 rounded-full flex items-center justify-center hover:bg-red-600 hover:scale-110 transition-all z-10" data-favorite="${mod.id}">
          <i class="${isFavorite ? 'fas' : 'far'} fa-heart ${isFavorite ? 'text-red-500' : 'text-gray-300'}"></i>
        </button>
        ${mod.featured ? '<div class="absolute top-3 left-3 bg-yellow-500 px-3 py-1 rounded-full text-xs font-bold flex items-center gap-1"><i class="fas fa-star"></i> FEATURED</div>' : ''}
        <div class="absolute bottom-3 left-3 bg-gray-900 bg-opacity-75 backdrop-blur-sm px-3 py-1 rounded-full text-sm flex items-center gap-2">
          <i class="fas fa-download text-blue-400"></i>
          <span>${mod.downloads.toLocaleString()}</span>
        </div>
      </div>
      <div class="p-4">
        <h3 class="font-bold text-xl mb-2 truncate group-hover:text-blue-400 transition-colors">${escapeHtml(mod.name)}</h3>
        <p class="text-gray-400 text-sm mb-3 line-clamp-2 leading-relaxed">${escapeHtml(mod.description)}</p>
        <div class="flex items-center justify-between text-sm mb-3">
          <span class="text-yellow-500 font-semibold">${stars} ${mod.rating.toFixed(1)}</span>
          <span class="inline-block bg-gray-700 px-3 py-1 rounded-full text-xs capitalize font-medium">${mod.category}</span>
        </div>
        <div class="mt-2 pt-3 border-t border-gray-700">
          <span class="text-xs text-gray-500 hover:text-blue-400 transition flex items-center gap-1" onclick="event.stopPropagation(); showProfile('${escapeHtml(mod.username)}')">
            <i class="fas fa-user"></i>
            <span>${escapeHtml(mod.username)}</span>
          </span>
        </div>
      </div>
    </div>
  `;
}

function escapeHtml(unsafe) {
  if (!unsafe) return '';
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

async function loadSecurityStats() {
  try {
    const res = await fetch('/api/admin/security');
    if (!res.ok) {
      console.error('Failed to load security stats');
      return;
    }
    const stats = await res.json();
    
    document.getElementById('security-stats').innerHTML = `
      <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
        <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <div class="text-3xl font-bold text-blue-500">${stats.totalRequests || 0}</div>
          <div class="text-gray-400">Total Requests</div>
        </div>
        <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <div class="text-3xl font-bold text-yellow-500">${stats.threatsDetected || 0}</div>
          <div class="text-gray-400">Threats Detected</div>
        </div>
        <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <div class="text-3xl font-bold text-red-500">${stats.threatsBlocked || 0}</div>
          <div class="text-gray-400">Threats Blocked</div>
        </div>
      </div>
    `;
  } catch (error) {
    console.error('Error loading security stats:', error);
  }
}

async function loadDbStats() {
  try {
    const res = await fetch('/api/admin/stats');
    if (!res.ok) {
      console.error('Failed to load db stats');
      return;
    }
    const stats = await res.json();
    
    document.getElementById('db-stats').innerHTML = `
      <h3 class="text-xl font-bold mb-4">Top Mods</h3>
      <div class="space-y-2">
        ${(stats.topMods || []).map(mod => `
          <div class="flex items-center justify-between bg-gray-800 px-4 py-2 rounded">
            <span>${escapeHtml(mod.name)}</span>
            <span class="text-green-500">${mod.downloads.toLocaleString()} downloads</span>
          </div>
        `).join('')}
      </div>
    `;
  } catch (error) {
    console.error('Error loading db stats:', error);
  }
}

// Security test functions
async function testSQLInjection() {
  const results = document.getElementById('attack-results');
  results.classList.remove('hidden');
  results.querySelector('pre').textContent = 'Testing SQL Injection...';
  
  try {
    const res = await fetch('/api/search?q=' + encodeURIComponent("' OR '1'='1"));
    const data = await res.json();
    results.querySelector('pre').textContent = `SQL Injection Test Result:\n\nStatus: ${res.status}\nBlocked: ${res.headers.get('x-aimless-blocked') || 'No'}\nResponse: ${JSON.stringify(data, null, 2)}`;
  } catch (error) {
    results.querySelector('pre').textContent = `Error: ${error.message}`;
  }
}

async function testXSS() {
  const results = document.getElementById('attack-results');
  results.classList.remove('hidden');
  results.querySelector('pre').textContent = 'Testing XSS Attack...';
  
  try {
    const res = await fetch('/api/search?q=' + encodeURIComponent('<script>alert("XSS")</script>'));
    const data = await res.json();
    results.querySelector('pre').textContent = `XSS Test Result:\n\nStatus: ${res.status}\nBlocked: ${res.headers.get('x-aimless-blocked') || 'No'}\nResponse: ${JSON.stringify(data, null, 2)}`;
  } catch (error) {
    results.querySelector('pre').textContent = `Error: ${error.message}`;
  }
}

async function testRateLimit() {
  const results = document.getElementById('attack-results');
  results.classList.remove('hidden');
  results.querySelector('pre').textContent = 'Testing Rate Limiting (sending 50 requests)...';
  
  try {
    let blocked = 0;
    let success = 0;
    
    for (let i = 0; i < 50; i++) {
      const res = await fetch('/api/search?q=test');
      if (res.status === 429) blocked++;
      else success++;
    }
    
    results.querySelector('pre').textContent = `Rate Limit Test Result:\n\nTotal Requests: 50\nSuccessful: ${success}\nBlocked: ${blocked}\n\n${blocked > 0 ? '✓ Rate limiting is working!' : '⚠ No rate limits triggered'}`;
  } catch (error) {
    results.querySelector('pre').textContent = `Error: ${error.message}`;
  }
}

// Filter/Sort
function filterCategory(category) {
  currentCategory = category === currentCategory ? '' : category;
  loadMods();
  
  // Update button states
  document.querySelectorAll('[data-category]').forEach(btn => {
    btn.classList.toggle('bg-blue-600', btn.dataset.category === currentCategory);
    btn.classList.toggle('bg-gray-700', btn.dataset.category !== currentCategory);
  });
}

function filterByCategory(category) {
  currentCategory = category;
  loadMods();
}

function sortMods(sort) {
  currentSort = sort;
  loadMods();
}

// Search functionality
function searchMods(query) {
  if (query.length < 2) {
    loadMods(); // Reset to all mods if search is cleared
    return;
  }
  
  const grid = document.getElementById('mods-grid');
  grid.innerHTML = `
    <div class="col-span-3 flex justify-center items-center py-12">
      <div class="text-center">
        <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
        <p class="text-gray-400">Searching...</p>
      </div>
    </div>
  `;
  
  fetch(`/api/search?q=${encodeURIComponent(query)}`)
    .then(res => res.json())
    .then(results => {
      if (results.length === 0) {
        grid.innerHTML = `
          <div class="col-span-3 text-center py-12">
            <i class="fas fa-search text-4xl text-gray-500 mb-4"></i>
            <p class="text-gray-400">No mods found matching "${escapeHtml(query)}"</p>
          </div>
        `;
      } else {
        grid.innerHTML = results.map(mod => createModCard(mod)).join('');
      }
    })
    .catch(error => {
      grid.innerHTML = `
        <div class="col-span-3 text-center py-12">
          <i class="fas fa-exclamation-triangle text-4xl text-red-500 mb-4"></i>
          <p class="text-gray-400">Search failed. Please try again.</p>
        </div>
      `;
    });
}

// Mod detail modal
async function showModDetail(modId) {
  const modal = document.getElementById('mod-modal');
  const content = document.getElementById('mod-detail-content');
  
  modal.classList.remove('hidden');
  
  // Show loading
  content.innerHTML = `
    <div class="p-8 text-center">
      <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
      <p class="text-gray-400">Loading mod details...</p>
    </div>
  `;
  
  try {
    const [modRes, reviewsRes] = await Promise.all([
      fetch(`/api/mods/${modId}`),
      fetch(`/api/mods/${modId}/reviews`)
    ]);
    
    const mod = await modRes.json();
    const reviews = await reviewsRes.json();
    
    const imageUrl = mod.image_url || 'https://images.unsplash.com/photo-1568605117036-5fe5e7bab0b7?w=800&auto=format&fit=crop';
    const stars = '⭐'.repeat(Math.round(mod.rating));
    const canEdit = currentUser && (currentUser.id === mod.user_id || currentUser.role === 'admin');
    const isAdmin = currentUser && currentUser.role === 'admin';
    const isFeatured = mod.featured === 1;
    
    content.innerHTML = `
      <div class="relative">
        <button onclick="closeModModal()" class="absolute top-4 right-4 z-10 bg-gray-900 bg-opacity-75 hover:bg-opacity-100 text-white rounded-full w-10 h-10 flex items-center justify-center transition">
          <i class="fas fa-times"></i>
        </button>
        
        <div class="aspect-video bg-gradient-to-br from-blue-900 to-purple-900 overflow-hidden">
          <img src="${imageUrl}" class="w-full h-full object-cover" onerror="this.src='https://images.unsplash.com/photo-1568605117036-5fe5e7bab0b7?w=800&auto=format&fit=crop'">
        </div>
        
        <div class="p-6">
          <div class="flex items-start justify-between mb-4">
            <div class="flex-1">
              <h2 class="text-3xl font-bold mb-2">${escapeHtml(mod.name)}</h2>
              <p class="text-gray-400 mb-3">${escapeHtml(mod.description)}</p>
              <div class="flex items-center space-x-4 text-sm">
                <span class="text-yellow-500 text-lg">${stars} ${mod.rating.toFixed(1)}</span>
                <span class="text-gray-500"><i class="fas fa-download"></i> ${mod.downloads.toLocaleString()} downloads</span>
                <span class="text-gray-500 capitalize"><i class="fas fa-tag"></i> ${mod.category}</span>
              </div>
            </div>
            <div class="flex flex-wrap gap-2">
              ${isFeatured ? '<span class="bg-yellow-600 px-3 py-1 rounded-full text-sm"><i class="fas fa-star mr-1"></i>Featured</span>' : ''}
              ${isAdmin ? `
                <button onclick="toggleFeaturedMod(${mod.id}, ${isFeatured})" class="bg-yellow-600 hover:bg-yellow-700 px-4 py-2 rounded-lg transition text-sm">
                  <i class="fas fa-star"></i> ${isFeatured ? 'Unfeature' : 'Feature'}
                </button>
                <button onclick="banUser(${mod.user_id}, '${escapeHtml(mod.username)}')" class="bg-orange-600 hover:bg-orange-700 px-4 py-2 rounded-lg transition text-sm">
                  <i class="fas fa-ban"></i> Ban Author
                </button>
              ` : ''}
              ${canEdit ? `
                <button onclick="editMod(${mod.id})" class="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg transition text-sm">
                  <i class="fas fa-edit"></i> Edit
                </button>
                <button onclick="deleteMod(${mod.id})" class="bg-red-600 hover:bg-red-700 px-4 py-2 rounded-lg transition text-sm">
                  <i class="fas fa-trash"></i> Delete
                </button>
              ` : ''}
            </div>
          </div>
          
          <div class="flex items-center justify-between mb-6 pb-6 border-b border-gray-700">
            <div class="flex items-center space-x-2">
              <span class="text-gray-400">Created by</span>
              <span class="text-blue-400 hover:text-blue-300 cursor-pointer" onclick="closeModModal(); showProfile('${escapeHtml(mod.username)}')">
                <i class="fas fa-user mr-1"></i>${escapeHtml(mod.username)}
              </span>
            </div>
            ${mod.download_url ? `
              <button onclick="downloadMod(${mod.id}, '${mod.download_url}')" class="bg-green-600 hover:bg-green-700 px-6 py-3 rounded-lg font-semibold transition">
                <i class="fas fa-download mr-2"></i>Download Mod
              </button>
            ` : ''}
          </div>
          
          <div class="mb-6">
            <h3 class="text-2xl font-bold mb-4">Reviews (${reviews.length})</h3>
            ${currentUser ? `
              <div class="bg-gray-700 rounded-lg p-4 mb-4">
                <form onsubmit="submitReview(event, ${mod.id})">
                  <div class="mb-3">
                    <label class="block text-sm font-medium mb-2">Your Rating</label>
                    <select name="rating" required class="bg-gray-600 border border-gray-500 rounded px-3 py-2">
                      <option value="">Select rating...</option>
                      <option value="5">⭐⭐⭐⭐⭐ Excellent</option>
                      <option value="4">⭐⭐⭐⭐ Good</option>
                      <option value="3">⭐⭐⭐ Average</option>
                      <option value="2">⭐⭐ Poor</option>
                      <option value="1">⭐ Terrible</option>
                    </select>
                  </div>
                  <div class="mb-3">
                    <label class="block text-sm font-medium mb-2">Your Review</label>
                    <textarea name="comment" required minlength="10" rows="3" class="w-full bg-gray-600 border border-gray-500 rounded px-3 py-2" placeholder="Share your thoughts..."></textarea>
                  </div>
                  <button type="submit" class="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg transition">
                    <i class="fas fa-paper-plane mr-2"></i>Submit Review
                  </button>
                </form>
              </div>
            ` : `
              <div class="bg-gray-700 rounded-lg p-4 mb-4 text-center">
                <p class="text-gray-400">Please <a href="#" onclick="closeModModal(); showLoginModal()" class="text-blue-400 hover:text-blue-300">login</a> to leave a review</p>
              </div>
            `}
            
            <div class="space-y-3">
              ${reviews.length > 0 ? reviews.map(review => `
                <div class="bg-gray-700 rounded-lg p-4">
                  <div class="flex items-center justify-between mb-2">
                    <span class="font-semibold">${escapeHtml(review.username)}</span>
                    <div class="flex items-center gap-2">
                      <span class="text-yellow-500">${'⭐'.repeat(review.rating)}</span>
                      ${isAdmin ? `<button onclick="deleteReview(${review.id}, ${mod.id})" class="text-red-400 hover:text-red-300 text-sm"><i class="fas fa-trash"></i></button>` : ''}
                    </div>
                  </div>
                  <p class="text-gray-300">${escapeHtml(review.comment)}</p>
                  <span class="text-xs text-gray-500">${new Date(review.created_at).toLocaleDateString()}</span>
                </div>
              `).join('') : '<p class="text-gray-400 text-center py-4">No reviews yet. Be the first to share your thoughts! 😊</p>'}
            </div>
          </div>
        </div>
      </div>
    `;
  } catch (error) {
    content.innerHTML = `
      <div class="p-8 text-center">
        <i class="fas fa-exclamation-triangle text-4xl text-red-500 mb-4"></i>
        <p class="text-gray-400">Failed to load mod details</p>
        <button onclick="closeModModal()" class="mt-4 bg-gray-700 hover:bg-gray-600 px-4 py-2 rounded-lg transition">Close</button>
      </div>
    `;
  }
}

function closeModModal() {
  document.getElementById('mod-modal').classList.add('hidden');
}

async function submitReview(event, modId) {
  event.preventDefault();
  const formData = new FormData(event.target);
  
  try {
    const res = await fetch(`/api/mods/${modId}/reviews`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        rating: parseInt(formData.get('rating')),
        comment: formData.get('comment')
      })
    });
    
    const data = await res.json();
    
    if (res.ok) {
      showToast('Thanks for your review! 🎉');
      showModDetail(modId);
      loadMods(); // Refresh to show updated rating
    } else {
      showToast(data.error || 'Failed to submit review', 'error');
    }
  } catch (error) {
    showToast('Failed to submit review', 'error');
  }
}

async function downloadMod(modId, downloadUrl) {
  try {
    await fetch(`/api/mods/${modId}/download`, { method: 'POST' });
    window.open(downloadUrl, '_blank');
    showToast('Download started!');
  } catch (error) {
    showToast('Download tracking failed, but opening file...', 'error');
    window.open(downloadUrl, '_blank');
  }
}

async function deleteMod(modId) {
  if (!confirm('Are you sure you want to delete this mod? This action cannot be undone.')) {
    return;
  }
  
  try {
    const res = await fetch(`/api/mods/${modId}`, { method: 'DELETE' });
    const data = await res.json();
    
    if (res.ok) {
      showToast('Mod deleted successfully');
      closeModModal();
      loadMods();
      loadFeaturedMods();
      loadStats();
      
      // Refresh current page
      const currentPage = document.querySelector('.page:not(.hidden)');
      if (currentPage && currentPage.id === 'profile-page') {
        const username = document.getElementById('profile-username')?.textContent;
        if (username) showProfile(username);
      }
    } else {
      showToast(data.error || 'Failed to delete mod', 'error');
    }
  } catch (error) {
    showToast('Failed to delete mod', 'error');
  }
}

function editMod(modId) {
  showToast('Edit functionality coming soon!', 'info');
}

async function toggleFavorite(modId, event) {
  event?.stopPropagation();
  
  const index = favorites.indexOf(modId);
  if (index > -1) {
    favorites.splice(index, 1);
    showToast('Removed from favorites');
  } else {
    favorites.push(modId);
    showToast('Added to favorites! ⭐');
  }
  
  localStorage.setItem('favorites', JSON.stringify(favorites));
  updateFavoritesCount();
  
  // Update heart icon
  const heartIcon = document.querySelector(`[data-favorite="${modId}"]`);
  if (heartIcon) {
    const icon = heartIcon.querySelector('i');
    if (icon) {
      icon.classList.toggle('fas', favorites.includes(modId));
      icon.classList.toggle('far', !favorites.includes(modId));
      icon.classList.toggle('text-red-500', favorites.includes(modId));
      icon.classList.toggle('text-gray-300', !favorites.includes(modId));
    }
  }
  
  // Reload if on favorites page
  const favPage = document.getElementById('favorites-page');
  if (favPage && !favPage.classList.contains('hidden')) {
    loadFavorites();
  }
}

function loadFavorites() {
  if (favorites.length === 0) {
    const grid = document.getElementById('favorites-grid');
    if (grid) {
      grid.innerHTML = `
        <div class="col-span-3 text-center py-12">
          <i class="fas fa-heart text-6xl text-gray-600 mb-4"></i>
          <h3 class="text-2xl font-bold mb-2">No favorites yet</h3>
          <p class="text-gray-400 mb-4">Start exploring and save your favorite mods!</p>
          <button onclick="showMods()" class="bg-blue-600 hover:bg-blue-700 px-6 py-3 rounded-lg transition">
            <i class="fas fa-compass mr-2"></i>Browse Mods
          </button>
        </div>
      `;
    }
    return;
  }
  
  fetch(`/api/mods?ids=${favorites.join(',')}`)
    .then(res => res.json())
    .then(mods => {
      const grid = document.getElementById('favorites-grid');
      if (grid) {
        grid.innerHTML = mods.map(mod => createModCard(mod)).join('');
      }
    })
    .catch(() => {
      showToast('Failed to load favorites', 'error');
    });
}

async function toggleFeaturedMod(modId, isFeatured) {
  try {
    const res = await fetch(`/api/admin/mods/${modId}/featured`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ featured: !isFeatured })
    });
    
    const data = await res.json();
    if (res.ok) {
      showToast(`Mod ${!isFeatured ? 'featured' : 'unfeatured'} successfully`);
      showModDetail(modId);
      loadFeaturedMods();
    } else {
      showToast(data.error || 'Failed to update featured status', 'error');
    }
  } catch (error) {
    showToast('Failed to update featured status', 'error');
  }
}

async function deleteReview(reviewId, modId) {
  if (!confirm('Delete this review?')) return;
  
  try {
    const res = await fetch(`/api/admin/reviews/${reviewId}`, { method: 'DELETE' });
    const data = await res.json();
    
    if (res.ok) {
      showToast('Review deleted');
      showModDetail(modId);
    } else {
      showToast(data.error || 'Failed to delete review', 'error');
    }
  } catch (error) {
    showToast('Failed to delete review', 'error');
  }
}

async function banUser(userId, username) {
  if (!confirm(`Ban user ${username}? They won't be able to login.`)) return;
  
  try {
    const res = await fetch(`/api/admin/users/${userId}/ban`, { method: 'POST' });
    const data = await res.json();
    
    if (res.ok) {
      showToast(`${username} has been banned`);
      closeModModal();
    } else {
      showToast(data.error || 'Failed to ban user', 'error');
    }
  } catch (error) {
    showToast('Failed to ban user', 'error');
  }
}

// Initialize on load
document.addEventListener('DOMContentLoaded', () => {
  checkAuth();
  showHome();
});
