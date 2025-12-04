const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const SQLiteStore = require('connect-sqlite3')(session);
const multer = require('multer');
const { Aimless } = require('aimless-security');
const { requireAuth, optionalAuth, requireAdmin } = require('./middleware/auth');

// Multer configuration for image uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'public', 'uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|gif|webp/;
    const ext = allowed.test(path.extname(file.originalname).toLowerCase());
    const mime = allowed.test(file.mimetype);
    
    if (ext && mime) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'));
    }
  }
});

const app = express();
const db = new sqlite3.Database(path.join(__dirname, 'beamng.db'), (err) => {
  if (err) {
    console.error('❌ Error connecting to database:', err);
    process.exit(1);
  }
  console.log('✅ Connected to database');
});

// Promisify database methods
const dbAll = (query, params = []) => {
  return new Promise((resolve, reject) => {
    db.all(query, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
};

const dbGet = (query, params = []) => {
  return new Promise((resolve, reject) => {
    db.get(query, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
};

const dbRun = (query, params = []) => {
  return new Promise((resolve, reject) => {
    db.run(query, params, function(err) {
      if (err) reject(err);
      else resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
};

// Aimless Security - Full Protection with Loading Screen
const aimless = new Aimless({
  rasp: {
    enabled: true,
    blockMode: true,  // Set to false to allow auth while monitoring
    injectionProtection: true,
    xssProtection: true,
    csrfProtection: false,
    anomalyDetection: true,  // Disable to prevent false positives on auth
    
    loadingScreen: {
      enabled: true,
      message: 'Securing BeamNG Community...',
      minDuration: 1000,
      useHosted: false  // Use inline for local development
    },
    
    webhooks: {
      enabled: true,
      url: 'https://discord.com/api/webhooks/1445587073040912495/Hh3X0Zj5v-fwPe_oz8ln-beJpmzd9Dnk-ZTzymZNqtqqIq7h5ATS8bkF4WjePya5GfEL',
      events: ['threat', 'block', 'rateLimit']
    },
    
    requestFingerprinting: {
      enabled: true,
      blockAutomatedTraffic: false
    },
    
    rateLimiting: {
      enabled: true,
      maxRequests: 100,  // Increased for normal usage
      windowMs: 60000,   // 1 minute
      dynamicThrottling: true
    },
    
    analytics: {
      enabled: true,
      retention: 30
    }
  },
  logging: {
    enabled: true,
    level: 'info'
  }
});

// Apply Aimless loading screen FIRST (before anything else)
app.use(aimless.loading());

// Body parsers - MUST come before security middleware to parse request bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Apply Aimless security middleware AFTER body parsers, but SKIP for auth routes
app.use((req, res, next) => {
  const authPaths = ['/api/auth/login', '/api/auth/register', '/api/auth/logout', '/api/auth/me', '/api/auth/profile'];
  if (authPaths.includes(req.path)) {
    return next(); // Skip Aimless for auth routes
  }
  aimless.middleware()(req, res, next);
});

// Static files (exclude index.html, we serve it manually)
app.use(express.static('public', { 
  index: false  // Don't serve index.html automatically
}));

app.use(session({
  store: new SQLiteStore({
    db: 'sessions.db',
    dir: __dirname
  }),
  secret: 'beamng-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: false, // Set to true with HTTPS
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  }
}));

// Log threats
app.use((req, res, next) => {
  if (req.aimless && req.aimless.threats.length > 0) {
    const threatInfo = {
      ip: req.ip,
      path: req.path,
      method: req.method,
      blocked: req.aimless.blocked || false,
      threats: req.aimless.threats.map(t => ({
        type: t.type,
        severity: t.severity,
        payload: t.payload,
        details: t.details
      }))
    };
    
    if (req.aimless.blocked) {
      console.log('🚨 THREAT DETECTED AND BLOCKED:', threatInfo);
    } else {
      console.log('⚠️  THREAT DETECTED (monitoring):', threatInfo);
    }
  }
  next();
});

// ============================================
// AUTHENTICATION ROUTES
// ============================================

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // Validation
    if (!username || username.length < 3) {
      return res.status(400).json({ error: 'Username must be at least 3 characters' });
    }
    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Valid email required' });
    }
    if (!password || password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    // Check if user exists
    const existing = await dbGet('SELECT id FROM users WHERE username = ? OR email = ?', [username, email]);
    if (existing) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create user
    const result = await dbRun(
      'INSERT INTO users (username, email, password, avatar_url) VALUES (?, ?, ?, ?)',
      [username, email, hashedPassword, `https://api.dicebear.com/7.x/avataaars/svg?seed=${username}`]
    );
    
    // Create session
    req.session.userId = result.lastID;
    req.session.username = username;
    req.session.role = 'user';
    
    res.json({ 
      success: true,
      user: {
        id: result.lastID,
        username,
        email,
        role: 'user'
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    
    // Find user
    const user = await dbGet(
      'SELECT id, username, email, password, role, avatar_url, banned FROM users WHERE username = ? OR email = ?',
      [username, username]
    );
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check if banned
    if (user.banned === 1) {
      return res.status(403).json({ error: 'Your account has been banned. Please contact support.' });
    }
    
    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Create session
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.role = user.role;
    
    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        avatarUrl: user.avatar_url
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.json({ success: true });
  });
});

// Get current user
app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const user = await dbGet(
      'SELECT id, username, email, role, avatar_url, bio, created_at FROM users WHERE id = ?',
      [req.session.userId]
    );
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json(user);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

// Update profile
app.put('/api/auth/profile', requireAuth, async (req, res) => {
  try {
    const { bio, avatarUrl } = req.body;
    
    await dbRun(
      'UPDATE users SET bio = ?, avatar_url = ? WHERE id = ?',
      [bio || '', avatarUrl || null, req.session.userId]
    );
    
    res.json({ success: true });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// ============================================
// USER ROUTES
// ============================================

// Get user profile
app.get('/api/users/:username', async (req, res) => {
  try {
    const user = await dbGet(
      'SELECT id, username, avatar_url, bio, created_at FROM users WHERE username = ?',
      [req.params.username]
    );
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Get user's mods
    const mods = await dbAll(
      'SELECT id, name, category, downloads, rating, created_at FROM mods WHERE user_id = ? ORDER BY created_at DESC',
      [user.id]
    );
    
    // Get user's reviews
    const reviews = await dbAll(
      'SELECT reviews.*, mods.name as mod_name FROM reviews JOIN mods ON reviews.mod_id = mods.id WHERE reviews.user_id = ? ORDER BY reviews.created_at DESC LIMIT 10',
      [user.id]
    );
    
    res.json({
      ...user,
      mods,
      reviews,
      stats: {
        totalMods: mods.length,
        totalDownloads: mods.reduce((sum, mod) => sum + mod.downloads, 0),
        averageRating: mods.length > 0 ? mods.reduce((sum, mod) => sum + mod.rating, 0) / mods.length : 0
      }
    });
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({ error: 'Failed to fetch user profile' });
  }
});

// ============================================
// API ROUTES
// ============================================

// Search mods (dedicated endpoint)
app.get('/api/search', async (req, res) => {
  try {
    const { q } = req.query;
    
    if (!q || q.length < 2) {
      return res.json([]);
    }
    
    const mods = await dbAll(`
      SELECT mods.*, users.username 
      FROM mods 
      JOIN users ON mods.user_id = users.id 
      WHERE name LIKE ? OR description LIKE ? OR category LIKE ?
      ORDER BY downloads DESC 
      LIMIT 20
    `, [`%${q}%`, `%${q}%`, `%${q}%`]);
    
    res.json(mods);
  } catch (error) {
    console.error('Error searching mods:', error);
    res.status(500).json({ error: 'Search failed' });
  }
});

// Get all mods
app.get('/api/mods', async (req, res) => {
  try {
    const { category, search, sort = 'downloads', ids } = req.query;
    
    let query = 'SELECT mods.*, users.username FROM mods JOIN users ON mods.user_id = users.id WHERE 1=1';
    const params = [];
    
    if (ids) {
      const idList = ids.split(',').filter(id => !isNaN(id));
      if (idList.length > 0) {
        query += ` AND mods.id IN (${idList.map(() => '?').join(',')})`;
        params.push(...idList);
      }
    }
    
    if (category) {
      query += ' AND category = ?';
      params.push(category);
    }
    
    if (search) {
      query += ' AND (name LIKE ? OR description LIKE ?)';
      params.push(`%${search}%`, `%${search}%`);
    }
    
    query += ` ORDER BY ${sort === 'rating' ? 'rating' : 'downloads'} DESC LIMIT 50`;
    
    const mods = await dbAll(query, params);
    res.json(mods);
  } catch (error) {
    console.error('Error fetching mods:', error);
    res.status(500).json({ error: 'Failed to fetch mods' });
  }
});

// Get single mod
app.get('/api/mods/:id', async (req, res) => {
  try {
    const mod = await dbGet(`
      SELECT mods.*, users.username 
      FROM mods 
      JOIN users ON mods.user_id = users.id 
      WHERE mods.id = ?
    `, [req.params.id]);
    
    if (!mod) {
      return res.status(404).json({ error: 'Mod not found' });
    }
    
    res.json(mod);
  } catch (error) {
    console.error('Error fetching mod:', error);
    res.status(500).json({ error: 'Failed to fetch mod' });
  }
});

// Get mod reviews
app.get('/api/mods/:id/reviews', async (req, res) => {
  try {
    const reviews = await dbAll(`
      SELECT reviews.*, users.username 
      FROM reviews 
      JOIN users ON reviews.user_id = users.id 
      WHERE mod_id = ? 
      ORDER BY created_at DESC
    `, [req.params.id]);
    
    res.json(reviews);
  } catch (error) {
    console.error('Error fetching reviews:', error);
    res.status(500).json({ error: 'Failed to fetch reviews' });
  }
});

// Submit review (Protected by Aimless and requires auth)
app.post('/api/mods/:id/reviews', requireAuth, async (req, res) => {
  try {
    const { rating, comment } = req.body;
    const modId = req.params.id;
    
    // Simple validation
    if (!rating || rating < 1 || rating > 5) {
      return res.status(400).json({ error: 'Rating must be between 1-5' });
    }
    
    if (!comment || comment.length < 10) {
      return res.status(400).json({ error: 'Comment must be at least 10 characters' });
    }
    
    // Check if user already reviewed this mod
    const existing = await dbGet(
      'SELECT id FROM reviews WHERE mod_id = ? AND user_id = ?',
      [modId, req.session.userId]
    );
    
    if (existing) {
      return res.status(400).json({ error: 'You already reviewed this mod' });
    }
    
    // Insert review
    const result = await dbRun(`
      INSERT INTO reviews (mod_id, user_id, rating, comment) 
      VALUES (?, ?, ?, ?)
    `, [modId, req.session.userId, rating, comment]);
    
    // Update mod rating
    const avgRow = await dbGet(`
      SELECT AVG(rating) as avg FROM reviews WHERE mod_id = ?
    `, [modId]);
    
    await dbRun('UPDATE mods SET rating = ? WHERE id = ?', [avgRow.avg, modId]);
    
    res.json({ 
      success: true, 
      reviewId: result.lastID,
      newRating: avgRow.avg 
    });
  } catch (error) {
    console.error('Error submitting review:', error);
    res.status(500).json({ error: 'Failed to submit review' });
  }
});

// Track download
app.post('/api/mods/:id/download', async (req, res) => {
  try {
    const modId = req.params.id;
    const ip = req.ip;
    
    // Log download
    await dbRun('INSERT INTO downloads (mod_id, user_ip) VALUES (?, ?)', [modId, ip]);
    
    // Increment download counter
    await dbRun('UPDATE mods SET downloads = downloads + 1 WHERE id = ?', [modId]);
    
    const mod = await dbGet('SELECT download_url FROM mods WHERE id = ?', [modId]);
    
    res.json({ 
      success: true, 
      downloadUrl: mod.download_url 
    });
  } catch (error) {
    console.error('Error tracking download:', error);
    res.status(500).json({ error: 'Failed to process download' });
  }
});

// Get categories
app.get('/api/categories', async (req, res) => {
  try {
    const categories = await dbAll(`
      SELECT category, COUNT(*) as count 
      FROM mods 
      GROUP BY category
    `);
    
    res.json(categories);
  } catch (error) {
    console.error('Error fetching categories:', error);
    res.status(500).json({ error: 'Failed to fetch categories' });
  }
});

// Search mods
app.get('/api/search', async (req, res) => {
  try {
    const { q } = req.query;
    
    if (!q || q.length < 2) {
      return res.json([]);
    }
    
    const results = await dbAll(`
      SELECT id, name, category, downloads, rating 
      FROM mods 
      WHERE name LIKE ? OR description LIKE ? 
      LIMIT 10
    `, [`%${q}%`, `%${q}%`]);
    
    res.json(results);
  } catch (error) {
    console.error('Error searching mods:', error);
    res.status(500).json({ error: 'Failed to search mods' });
  }
});

// Upload mod
app.post('/api/mods', requireAuth, upload.single('image'), async (req, res) => {
  try {
    const { name, description, category, downloadUrl } = req.body;
    
    // Validation
    if (!name || name.length < 3) {
      return res.status(400).json({ error: 'Mod name must be at least 3 characters' });
    }
    if (!description || description.length < 20) {
      return res.status(400).json({ error: 'Description must be at least 20 characters' });
    }
    if (!['vehicle', 'map', 'gameplay'].includes(category)) {
      return res.status(400).json({ error: 'Invalid category' });
    }
    
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;
    
    const result = await dbRun(`
      INSERT INTO mods (user_id, name, description, category, download_url, image_url)
      VALUES (?, ?, ?, ?, ?, ?)
    `, [req.session.userId, name, description, category, downloadUrl, imageUrl]);
    
    res.json({
      success: true,
      modId: result.lastID,
      imageUrl
    });
  } catch (error) {
    console.error('Error uploading mod:', error);
    res.status(500).json({ error: 'Failed to upload mod' });
  }
});

// Update mod (owner or admin only)
app.put('/api/mods/:id', requireAuth, upload.single('image'), async (req, res) => {
  try {
    const modId = req.params.id;
    const { name, description, category, downloadUrl } = req.body;
    
    // Check ownership
    const mod = await dbGet('SELECT user_id FROM mods WHERE id = ?', [modId]);
    if (!mod) {
      return res.status(404).json({ error: 'Mod not found' });
    }
    if (mod.user_id !== req.session.userId && req.session.role !== 'admin') {
      return res.status(403).json({ error: 'Permission denied' });
    }
    
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : undefined;
    
    let query = 'UPDATE mods SET name = ?, description = ?, category = ?, download_url = ?';
    const params = [name, description, category, downloadUrl];
    
    if (imageUrl) {
      query += ', image_url = ?';
      params.push(imageUrl);
    }
    
    query += ' WHERE id = ?';
    params.push(modId);
    
    await dbRun(query, params);
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error updating mod:', error);
    res.status(500).json({ error: 'Failed to update mod' });
  }
});

// Delete mod (owner or admin only)
app.delete('/api/mods/:id', requireAuth, async (req, res) => {
  try {
    const modId = req.params.id;
    
    // Check ownership
    const mod = await dbGet('SELECT user_id, image_url FROM mods WHERE id = ?', [modId]);
    if (!mod) {
      return res.status(404).json({ error: 'Mod not found' });
    }
    if (mod.user_id !== req.session.userId && req.session.role !== 'admin') {
      return res.status(403).json({ error: 'Permission denied' });
    }
    
    // Delete associated reviews
    await dbRun('DELETE FROM reviews WHERE mod_id = ?', [modId]);
    
    // Delete associated downloads
    await dbRun('DELETE FROM downloads WHERE mod_id = ?', [modId]);
    
    // Delete mod
    await dbRun('DELETE FROM mods WHERE id = ?', [modId]);
    
    // Delete image file if exists
    if (mod.image_url && mod.image_url.startsWith('/uploads/')) {
      const imagePath = path.join(__dirname, 'public', mod.image_url);
      if (fs.existsSync(imagePath)) {
        fs.unlinkSync(imagePath);
      }
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting mod:', error);
    res.status(500).json({ error: 'Failed to delete mod' });
  }
});

// Admin: Security Analytics (remove requireAdmin for testing)
app.get('/api/admin/security', async (req, res) => {
  try {
    const analytics = aimless.getAnalytics();
    res.json({
      totalRequests: analytics.totalRequests || 0,
      threatsDetected: analytics.threatsDetected || 0,
      threatsBlocked: analytics.threatsBlocked || 0,
      topAttackTypes: analytics.topAttackTypes || [],
      topAttackIPs: analytics.topAttackIPs || []
    });
  } catch (error) {
    console.error('Error fetching security analytics:', error);
    res.status(500).json({ error: 'Failed to fetch analytics' });
  }
});

// Admin: Database Stats (remove requireAdmin for testing)
app.get('/api/admin/stats', async (req, res) => {
  try {
    const stats = {
      totalMods: (await dbGet('SELECT COUNT(*) as count FROM mods')).count,
      totalUsers: (await dbGet('SELECT COUNT(*) as count FROM users')).count,
      totalReviews: (await dbGet('SELECT COUNT(*) as count FROM reviews')).count,
      totalDownloads: (await dbGet('SELECT SUM(downloads) as total FROM mods')).total || 0,
      topMods: await dbAll('SELECT name, downloads FROM mods ORDER BY downloads DESC LIMIT 5')
    };
    
    res.json(stats);
  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// ============================================
// ADMIN ENDPOINTS
// ============================================

// Feature/Unfeature mod
app.post('/api/admin/mods/:id/featured', requireAdmin, async (req, res) => {
  try {
    const { featured } = req.body;
    await dbRun('UPDATE mods SET featured = ? WHERE id = ?', [featured ? 1 : 0, req.params.id]);
    res.json({ success: true });
  } catch (error) {
    console.error('Error updating featured status:', error);
    res.status(500).json({ error: 'Failed to update featured status' });
  }
});

// Delete review (admin)
app.delete('/api/admin/reviews/:id', requireAdmin, async (req, res) => {
  try {
    const review = await dbGet('SELECT mod_id FROM reviews WHERE id = ?', [req.params.id]);
    if (!review) {
      return res.status(404).json({ error: 'Review not found' });
    }
    
    await dbRun('DELETE FROM reviews WHERE id = ?', [req.params.id]);
    
    // Recalculate mod rating
    const avgRating = await dbGet('SELECT AVG(rating) as avg FROM reviews WHERE mod_id = ?', [review.mod_id]);
    await dbRun('UPDATE mods SET rating = ? WHERE id = ?', [avgRating.avg || 0, review.mod_id]);
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting review:', error);
    res.status(500).json({ error: 'Failed to delete review' });
  }
});

// Ban user
app.post('/api/admin/users/:id/ban', requireAdmin, async (req, res) => {
  try {
    await dbRun('UPDATE users SET banned = 1 WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (error) {
    console.error('Error banning user:', error);
    res.status(500).json({ error: 'Failed to ban user' });
  }
});

// ============================================
// HTML ROUTES
// ============================================

// Serve index.html for all other routes (SPA)
// Use res.send() instead of res.sendFile() so loading screen middleware works
app.get('*', (req, res) => {
  const indexPath = path.join(__dirname, 'public', 'index.html');
  const html = fs.readFileSync(indexPath, 'utf-8');
  res.send(html);
});

// ============================================
// START SERVER
// ============================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('');
  console.log('============================================');
  console.log('🚗 BeamNG Community Site');
  console.log('============================================');
  console.log(`🌐 Server: http://localhost:${PORT}`);
  console.log(`📊 Analytics: http://localhost:${PORT}/admin`);
  console.log(`🛡️  Aimless Security: MONITOR MODE (logging only)`);
  console.log('');
  console.log('📝 To enable blocking: Set blockMode: true in server.js');
  console.log('============================================');
  console.log('');
});

// Graceful shutdown
process.on('SIGINT', () => {
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err);
    } else {
      console.log('\n✅ Database connection closed');
    }
    process.exit(0);
  });
});
