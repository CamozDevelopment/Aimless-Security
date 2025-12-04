// Initialize Firebase
let app, auth, db, storage;
let currentUser = null;
let unsubscribeAuth = null;

function initFirebase() {
  try {
    app = firebase.initializeApp(firebaseConfig);
    auth = firebase.auth();
    db = firebase.firestore();
    storage = firebase.storage();
    
    // Enable offline persistence
    db.enablePersistence().catch((err) => {
      console.warn('Persistence error:', err.code);
    });
    
    // Listen for auth state changes
    unsubscribeAuth = auth.onAuthStateChanged((user) => {
      currentUser = user;
      updateUIForAuthState(user);
    });
    
    console.log('🔥 Firebase initialized');
  } catch (error) {
    console.error('Firebase initialization error:', error);
    showToast('Firebase configuration needed. Check console.', 'error');
  }
}

// Authentication Functions
function showAuthModal() {
  document.getElementById('auth-modal').classList.remove('hidden');
}

function closeAuthModal() {
  document.getElementById('auth-modal').classList.add('hidden');
  document.getElementById('auth-error').classList.add('hidden');
}

function switchAuthTab(tab) {
  const signinTab = document.getElementById('signin-tab');
  const signupTab = document.getElementById('signup-tab');
  const signinForm = document.getElementById('signin-form');
  const signupForm = document.getElementById('signup-form');
  
  if (tab === 'signin') {
    signinTab.classList.add('bg-blue-600');
    signinTab.classList.remove('bg-gray-700');
    signupTab.classList.add('bg-gray-700');
    signupTab.classList.remove('bg-blue-600');
    signinForm.classList.remove('hidden');
    signupForm.classList.add('hidden');
  } else {
    signupTab.classList.add('bg-blue-600');
    signupTab.classList.remove('bg-gray-700');
    signinTab.classList.add('bg-gray-700');
    signinTab.classList.remove('bg-blue-600');
    signupForm.classList.remove('hidden');
    signinForm.classList.add('hidden');
  }
}

async function signInWithEmail() {
  const email = document.getElementById('signin-email').value;
  const password = document.getElementById('signin-password').value;
  
  try {
    await auth.signInWithEmailAndPassword(email, password);
    closeAuthModal();
    showToast('Welcome back!', 'success');
  } catch (error) {
    showAuthError(error.message);
  }
}

async function signUpWithEmail() {
  const username = document.getElementById('signup-username').value;
  const email = document.getElementById('signup-email').value;
  const password = document.getElementById('signup-password').value;
  
  if (!username || username.length < 3) {
    showAuthError('Username must be at least 3 characters');
    return;
  }
  
  try {
    const userCredential = await auth.createUserWithEmailAndPassword(email, password);
    
    // Update profile with username
    await userCredential.user.updateProfile({
      displayName: username
    });
    
    // Create user document in Firestore
    await db.collection('users').doc(userCredential.user.uid).set({
      username: username,
      email: email,
      createdAt: firebase.firestore.FieldValue.serverTimestamp(),
      photoURL: userCredential.user.photoURL || `https://ui-avatars.com/api/?name=${encodeURIComponent(username)}&background=667eea&color=fff`,
      modCount: 0,
      reviewCount: 0
    });
    
    closeAuthModal();
    showToast(`Welcome, ${username}!`, 'success');
  } catch (error) {
    showAuthError(error.message);
  }
}

async function signInWithGoogle() {
  const provider = new firebase.auth.GoogleAuthProvider();
  
  try {
    const result = await auth.signInWithPopup(provider);
    
    // Create or update user document
    const userDoc = await db.collection('users').doc(result.user.uid).get();
    if (!userDoc.exists) {
      await db.collection('users').doc(result.user.uid).set({
        username: result.user.displayName,
        email: result.user.email,
        createdAt: firebase.firestore.FieldValue.serverTimestamp(),
        photoURL: result.user.photoURL,
        modCount: 0,
        reviewCount: 0
      });
    }
    
    closeAuthModal();
    showToast(`Welcome, ${result.user.displayName}!`, 'success');
  } catch (error) {
    showAuthError(error.message);
  }
}

async function signOut() {
  try {
    await auth.signOut();
    showToast('Signed out successfully', 'success');
    showHome();
  } catch (error) {
    showToast('Error signing out', 'error');
  }
}

function showAuthError(message) {
  const errorDiv = document.getElementById('auth-error');
  errorDiv.textContent = message;
  errorDiv.classList.remove('hidden');
}

function updateUIForAuthState(user) {
  const loggedOut = document.getElementById('user-menu-logged-out');
  const loggedIn = document.getElementById('user-menu-logged-in');
  
  if (user) {
    loggedOut.classList.add('hidden');
    loggedIn.classList.remove('hidden');
    
    document.getElementById('user-display-name').textContent = user.displayName || 'User';
    document.getElementById('user-avatar').src = user.photoURL || `https://ui-avatars.com/api/?name=${encodeURIComponent(user.displayName || 'User')}&background=667eea&color=fff`;
  } else {
    loggedOut.classList.remove('hidden');
    loggedIn.classList.add('hidden');
  }
}

function toggleUserDropdown() {
  const dropdown = document.getElementById('user-dropdown');
  dropdown.classList.toggle('hidden');
}

// Close dropdown when clicking outside
document.addEventListener('click', (e) => {
  const dropdown = document.getElementById('user-dropdown');
  const button = document.getElementById('user-dropdown-btn');
  
  if (dropdown && button && !dropdown.contains(e.target) && !button.contains(e.target)) {
    dropdown.classList.add('hidden');
  }
});

// Toast Notifications
function showToast(message, type = 'success') {
  const toast = document.getElementById('toast');
  const icon = document.getElementById('toast-icon');
  const messageEl = document.getElementById('toast-message');
  
  messageEl.textContent = message;
  
  if (type === 'success') {
    icon.className = 'fas fa-check-circle text-green-500 text-xl';
  } else if (type === 'error') {
    icon.className = 'fas fa-times-circle text-red-500 text-xl';
  } else if (type === 'info') {
    icon.className = 'fas fa-info-circle text-blue-500 text-xl';
  }
  
  toast.style.transform = 'translateX(0)';
  
  setTimeout(() => {
    toast.style.transform = 'translateX(150%)';
  }, 3000);
}

// Navigation
function showHome() {
  renderHomePage();
}

function showMods() {
  renderModsPage();
}

function showAdmin() {
  renderAdminPage();
}

function showProfile() {
  if (!currentUser) {
    showAuthModal();
    return;
  }
  renderProfilePage();
}

function showMyMods() {
  if (!currentUser) {
    showAuthModal();
    return;
  }
  renderMyModsPage();
}

// Render Pages
function renderHomePage() {
  const content = document.getElementById('app-content');
  content.innerHTML = `
    <!-- Hero Section -->
    <div class="relative bg-gradient-to-r from-blue-900 via-purple-900 to-blue-900 rounded-2xl p-12 mb-12 overflow-hidden">
      <div class="absolute inset-0 bg-black opacity-50"></div>
      <div class="absolute inset-0">
        <div class="absolute top-10 left-10 w-32 h-32 bg-blue-500 rounded-full mix-blend-multiply filter blur-xl opacity-70 animate-pulse"></div>
        <div class="absolute top-10 right-10 w-32 h-32 bg-purple-500 rounded-full mix-blend-multiply filter blur-xl opacity-70 animate-pulse" style="animation-delay: 1s"></div>
        <div class="absolute bottom-10 left-1/2 w-32 h-32 bg-pink-500 rounded-full mix-blend-multiply filter blur-xl opacity-70 animate-pulse" style="animation-delay: 2s"></div>
      </div>
      <div class="relative text-center">
        <div class="inline-block mb-4">
          <i class="fas fa-car text-6xl text-blue-400"></i>
        </div>
        <h2 class="text-6xl font-bold mb-4 bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
          BeamNG Mods Community
        </h2>
        <p class="text-xl text-gray-300 mb-2">
          Download the best vehicles, maps, and gameplay mods
        </p>
        <p class="text-sm text-gray-400 mb-8">
          <i class="fas fa-shield-alt text-green-500"></i> Protected by Aimless Security v1.3.4 | <i class="fas fa-database text-blue-500"></i> Powered by Firebase
        </p>
        <div class="flex justify-center space-x-4">
          <button onclick="showMods()" class="bg-blue-600 hover:bg-blue-700 px-8 py-4 rounded-lg font-semibold transition transform hover:scale-105">
            <i class="fas fa-download mr-2"></i>Browse Mods
          </button>
          ${currentUser ? `
            <button onclick="showUploadModal()" class="bg-green-600 hover:bg-green-700 px-8 py-4 rounded-lg font-semibold transition transform hover:scale-105">
              <i class="fas fa-upload mr-2"></i>Upload Mod
            </button>
          ` : ''}
        </div>
      </div>
    </div>

    <!-- Stats -->
    <div id="home-stats" class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-12">
      <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <div class="skeleton h-12 w-20 rounded mb-2"></div>
        <div class="skeleton h-4 w-24 rounded"></div>
      </div>
      <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <div class="skeleton h-12 w-20 rounded mb-2"></div>
        <div class="skeleton h-4 w-24 rounded"></div>
      </div>
      <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <div class="skeleton h-12 w-20 rounded mb-2"></div>
        <div class="skeleton h-4 w-24 rounded"></div>
      </div>
      <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <div class="skeleton h-12 w-20 rounded mb-2"></div>
        <div class="skeleton h-4 w-24 rounded"></div>
      </div>
    </div>

    <!-- Featured Mods -->
    <div class="mb-8">
      <h3 class="text-2xl font-bold mb-6">
        <i class="fas fa-star text-yellow-500 mr-2"></i>Featured Mods
      </h3>
      <div id="featured-mods" class="grid grid-cols-1 md:grid-cols-3 gap-6">
        ${createSkeletonCards(3)}
      </div>
    </div>
  `;
  
  loadHomeStats();
  loadFeaturedMods();
}

function renderModsPage() {
  const content = document.getElementById('app-content');
  content.innerHTML = `
    <div class="mb-8">
      <h2 class="text-3xl font-bold mb-6">
        <i class="fas fa-download mr-2"></i>Browse Mods
      </h2>
      
      <!-- Filters -->
      <div class="flex flex-wrap gap-4 mb-6">
        <select id="category-filter" onchange="filterMods()" class="bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 focus:outline-none focus:border-blue-500">
          <option value="">All Categories</option>
          <option value="vehicle">Vehicles</option>
          <option value="map">Maps</option>
          <option value="gameplay">Gameplay</option>
        </select>
        
        <select id="sort-filter" onchange="filterMods()" class="bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 focus:outline-none focus:border-blue-500">
          <option value="downloads">Most Downloaded</option>
          <option value="rating">Highest Rated</option>
          <option value="newest">Newest</option>
        </select>
        
        <input type="text" id="search-input" placeholder="Search mods..." onkeyup="searchMods()" class="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 focus:outline-none focus:border-blue-500" />
      </div>
      
      <!-- Mods Grid -->
      <div id="mods-grid" class="grid grid-cols-1 md:grid-cols-3 gap-6">
        ${createSkeletonCards(9)}
      </div>
    </div>
  `;
  
  loadMods();
}

function renderAdminPage() {
  const content = document.getElementById('app-content');
  content.innerHTML = `
    <div class="mb-8">
      <h2 class="text-3xl font-bold mb-6">
        <i class="fas fa-shield-alt mr-2"></i>Security Dashboard
      </h2>
      
      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <!-- Security Stats -->
        <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <h3 class="text-xl font-bold mb-4">
            <i class="fas fa-chart-line text-blue-500 mr-2"></i>Security Analytics
          </h3>
          <div id="security-stats" class="space-y-3">
            <div class="skeleton h-6 w-full rounded"></div>
            <div class="skeleton h-6 w-full rounded"></div>
            <div class="skeleton h-6 w-full rounded"></div>
          </div>
        </div>
        
        <!-- Database Stats -->
        <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
          <h3 class="text-xl font-bold mb-4">
            <i class="fas fa-database text-green-500 mr-2"></i>Database Stats
          </h3>
          <div id="db-stats" class="space-y-3">
            <div class="skeleton h-6 w-full rounded"></div>
            <div class="skeleton h-6 w-full rounded"></div>
            <div class="skeleton h-6 w-full rounded"></div>
          </div>
        </div>
      </div>
      
      <!-- Attack Testing -->
      <div class="bg-gray-800 rounded-lg p-6 border border-gray-700 mt-6">
        <h3 class="text-xl font-bold mb-4">
          <i class="fas fa-bug text-red-500 mr-2"></i>Security Testing
        </h3>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <button onclick="testSQLInjection()" class="bg-purple-600 hover:bg-purple-700 py-3 rounded-lg font-semibold transition">
            <i class="fas fa-database mr-2"></i>Test SQL Injection
          </button>
          <button onclick="testXSS()" class="bg-orange-600 hover:bg-orange-700 py-3 rounded-lg font-semibold transition">
            <i class="fas fa-code mr-2"></i>Test XSS Attack
          </button>
          <button onclick="testRateLimit()" class="bg-red-600 hover:bg-red-700 py-3 rounded-lg font-semibold transition">
            <i class="fas fa-tachometer-alt mr-2"></i>Test Rate Limiting
          </button>
        </div>
        <div id="attack-results" class="mt-4 bg-gray-900 rounded-lg p-4 hidden">
          <pre class="text-sm text-gray-300 whitespace-pre-wrap"></pre>
        </div>
      </div>
    </div>
  `;
  
  loadSecurityStats();
  loadDbStats();
}

// Helper functions
function createSkeletonCards(count) {
  let html = '';
  for (let i = 0; i < count; i++) {
    html += `
      <div class="bg-gray-800 rounded-lg overflow-hidden border border-gray-700">
        <div class="skeleton aspect-video"></div>
        <div class="p-4">
          <div class="skeleton h-6 w-3/4 rounded mb-2"></div>
          <div class="skeleton h-4 w-full rounded mb-2"></div>
          <div class="skeleton h-4 w-2/3 rounded"></div>
        </div>
      </div>
    `;
  }
  return html;
}

// Load data functions
async function loadHomeStats() {
  try {
    const modsSnapshot = await db.collection('mods').get();
    const usersSnapshot = await db.collection('users').get();
    
    let totalDownloads = 0;
    let totalReviews = 0;
    
    modsSnapshot.forEach(doc => {
      const data = doc.data();
      totalDownloads += data.downloads || 0;
    });
    
    const reviewsSnapshot = await db.collection('reviews').get();
    totalReviews = reviewsSnapshot.size;
    
    document.getElementById('home-stats').innerHTML = `
      <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <div class="text-3xl font-bold text-blue-500">${modsSnapshot.size}</div>
        <div class="text-gray-400">Total Mods</div>
      </div>
      <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <div class="text-3xl font-bold text-green-500">${totalDownloads.toLocaleString()}</div>
        <div class="text-gray-400">Downloads</div>
      </div>
      <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <div class="text-3xl font-bold text-purple-500">${totalReviews}</div>
        <div class="text-gray-400">Reviews</div>
      </div>
      <div class="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <div class="text-3xl font-bold text-orange-500">${usersSnapshot.size}</div>
        <div class="text-gray-400">Users</div>
      </div>
    `;
  } catch (error) {
    console.error('Error loading stats:', error);
  }
}

async function loadFeaturedMods() {
  try {
    const modsSnapshot = await db.collection('mods')
      .orderBy('rating', 'desc')
      .limit(3)
      .get();
    
    const modsHTML = modsSnapshot.docs.map(doc => {
      const mod = doc.data();
      return createModCard({...mod, id: doc.id});
    }).join('');
    
    document.getElementById('featured-mods').innerHTML = modsHTML || '<p class="col-span-3 text-center text-gray-400">No mods yet. Be the first to upload!</p>';
  } catch (error) {
    console.error('Error loading featured mods:', error);
  }
}

async function loadMods() {
  try {
    const modsSnapshot = await db.collection('mods')
      .orderBy('downloads', 'desc')
      .get();
    
    const modsHTML = modsSnapshot.docs.map(doc => {
      const mod = doc.data();
      return createModCard({...mod, id: doc.id});
    }).join('');
    
    document.getElementById('mods-grid').innerHTML = modsHTML || '<p class="col-span-3 text-center text-gray-400">No mods found.</p>';
  } catch (error) {
    console.error('Error loading mods:', error);
    document.getElementById('mods-grid').innerHTML = '<p class="col-span-3 text-center text-red-400">Error loading mods. Please try again.</p>';
  }
}

function createModCard(mod) {
  const stars = '⭐'.repeat(Math.round(mod.rating || 0));
  return `
    <div class="bg-gray-800 rounded-lg overflow-hidden border border-gray-700 hover:border-blue-500 transition cursor-pointer animate-slide-in" onclick="showModDetail('${mod.id}')">
      <div class="aspect-video bg-gradient-to-br from-blue-900 to-purple-900 flex items-center justify-center">
        ${mod.imageUrl ? 
          `<img src="${mod.imageUrl}" class="w-full h-full object-cover" />` :
          `<i class="fas fa-car text-6xl text-gray-600"></i>`
        }
      </div>
      <div class="p-4">
        <h3 class="font-bold text-lg mb-2">${escapeHtml(mod.name)}</h3>
        <p class="text-gray-400 text-sm mb-3 line-clamp-2">${escapeHtml(mod.description)}</p>
        <div class="flex items-center justify-between text-sm">
          <span class="text-gray-500">
            <i class="fas fa-download"></i> ${(mod.downloads || 0).toLocaleString()}
          </span>
          <span class="text-yellow-500">${stars} ${(mod.rating || 0).toFixed(1)}</span>
        </div>
        <div class="mt-2">
          <span class="inline-block bg-gray-700 px-2 py-1 rounded text-xs">${mod.category}</span>
        </div>
      </div>
    </div>
  `;
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

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
  try {
    const modsSnapshot = await db.collection('mods').get();
    const usersSnapshot = await db.collection('users').get();
    const reviewsSnapshot = await db.collection('reviews').get();
    
    let totalDownloads = 0;
    modsSnapshot.forEach(doc => {
      totalDownloads += doc.data().downloads || 0;
    });
    
    document.getElementById('db-stats').innerHTML = `
      <div class="flex justify-between">
        <span class="text-gray-400">Total Mods:</span>
        <span class="font-semibold">${modsSnapshot.size}</span>
      </div>
      <div class="flex justify-between">
        <span class="text-gray-400">Total Users:</span>
        <span class="font-semibold">${usersSnapshot.size}</span>
      </div>
      <div class="flex justify-between">
        <span class="text-gray-400">Total Reviews:</span>
        <span class="font-semibold">${reviewsSnapshot.size}</span>
      </div>
      <div class="flex justify-between">
        <span class="text-gray-400">Total Downloads:</span>
        <span class="font-semibold">${totalDownloads.toLocaleString()}</span>
      </div>
    `;
  } catch (error) {
    console.error('Error loading DB stats:', error);
  }
}

// Attack testing (same as before)
async function testSQLInjection() {
  showAttackResult('Testing SQL Injection...');
  console.log('🧪 Testing SQL Injection');
  const res = await fetch('/api/search?q=' + encodeURIComponent("' OR '1'='1"));
  const data = await res.json();
  console.log('📡 SQL Test Response:', data);
  showAttackResult(`SQL Injection test sent!\nStatus: ${res.status}\nResponse: ${JSON.stringify(data, null, 2)}`);
}

async function testXSS() {
  showAttackResult('Testing XSS Attack...');
  console.log('🧪 Testing XSS Attack');
  // Test will go through Firebase
  showToast('XSS testing with Firebase - check Firestore security rules!', 'info');
}

async function testRateLimit() {
  showAttackResult('Testing Rate Limit...\nSending 50 rapid requests...');
  console.log('🧪 Testing Rate Limit - Sending 50 rapid requests');
  
  const promises = [];
  for (let i = 0; i < 50; i++) {
    promises.push(fetch('/api/mods').then(r => ({ status: r.status, ok: r.ok })));
  }
  
  const results = await Promise.all(promises);
  const blocked = results.filter(r => r.status === 403 || r.status === 429).length;
  const successful = results.filter(r => r.ok).length;
  
  console.log('📊 Rate Limit Test Results:', {
    total: results.length,
    successful: successful,
    blocked: blocked
  });
  
  showAttackResult(`Rate limit test completed!\nTotal: ${results.length}\nSuccessful: ${successful}\nBlocked: ${blocked}`);
}

function showAttackResult(message) {
  const resultsDiv = document.getElementById('attack-results');
  resultsDiv.classList.remove('hidden');
  resultsDiv.querySelector('pre').textContent = message;
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  initFirebase();
  showHome();
});
