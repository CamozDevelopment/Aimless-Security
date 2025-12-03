const express = require('express');
const session = require('express-session');
const path = require('path');
const Database = require('better-sqlite3');
const { Aimless } = require('aimless-sdk');

const app = express();
const db = new Database(path.join(__dirname, 'beamng.db'));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Session
app.use(session({
  secret: 'beamng-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // Set to true with HTTPS
}));

// Aimless Security - MONITOR MODE with Loading Screen
const aimless = new Aimless({
  rasp: {
    enabled: true,
    blockMode: false,  // Monitor mode - logs only, doesn't block yet
    
    loadingScreen: {
      enabled: true,
      message: 'Securing BeamNG Community...',
      minDuration: 1000
    },
    
    webhooks: {
      enabled: false,  // Set to true and add your Discord webhook
      url: 'https://discord.com/api/webhooks/YOUR/WEBHOOK/URL',
      events: ['threat', 'block']
    },
    
    requestFingerprinting: {
      enabled: true,
      blockAutomatedTraffic: false  // Set to true to block bots
    },
    
    rateLimiting: {
      enabled: true,
      maxRequests: 100,
      windowMs: 60000,
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

app.use(aimless.loading());
app.use(aimless.middleware());

// Log threats (since we're in monitor mode)
app.use((req, res, next) => {
  if (req.aimless && req.aimless.threats.length > 0) {
    console.log('🚨 THREAT DETECTED (not blocked):', {
      ip: req.ip,
      path: req.path,
      threats: req.aimless.threats.map(t => ({
        type: t.type,
        severity: t.severity,
        payload: t.payload
      }))
    });
  }
  next();
});

// ============================================
// API ROUTES
// ============================================

// Get all mods
app.get('/api/mods', (req, res) => {
  const { category, search, sort = 'downloads' } = req.query;
  
  let query = 'SELECT mods.*, users.username FROM mods JOIN users ON mods.user_id = users.id WHERE 1=1';
  const params = [];
  
  if (category) {
    query += ' AND category = ?';
    params.push(category);
  }
  
  if (search) {
    query += ' AND (name LIKE ? OR description LIKE ?)';
    params.push(`%${search}%`, `%${search}%`);
  }
  
  query += ` ORDER BY ${sort === 'rating' ? 'rating' : 'downloads'} DESC LIMIT 50`;
  
  const mods = db.prepare(query).all(...params);
  res.json(mods);
});

// Get single mod
app.get('/api/mods/:id', (req, res) => {
  const mod = db.prepare(`
    SELECT mods.*, users.username 
    FROM mods 
    JOIN users ON mods.user_id = users.id 
    WHERE mods.id = ?
  `).get(req.params.id);
  
  if (!mod) {
    return res.status(404).json({ error: 'Mod not found' });
  }
  
  res.json(mod);
});

// Get mod reviews
app.get('/api/mods/:id/reviews', (req, res) => {
  const reviews = db.prepare(`
    SELECT reviews.*, users.username 
    FROM reviews 
    JOIN users ON reviews.user_id = users.id 
    WHERE mod_id = ? 
    ORDER BY created_at DESC
  `).all(req.params.id);
  
  res.json(reviews);
});

// Submit review (Protected by Aimless)
app.post('/api/mods/:id/reviews', (req, res) => {
  const { rating, comment } = req.body;
  const modId = req.params.id;
  
  // Simple validation
  if (!rating || rating < 1 || rating > 5) {
    return res.status(400).json({ error: 'Rating must be between 1-5' });
  }
  
  if (!comment || comment.length < 10) {
    return res.status(400).json({ error: 'Comment must be at least 10 characters' });
  }
  
  try {
    // Insert review (using default user for demo)
    const result = db.prepare(`
      INSERT INTO reviews (mod_id, user_id, rating, comment) 
      VALUES (?, ?, ?, ?)
    `).run(modId, 1, rating, comment);
    
    // Update mod rating
    const avgRating = db.prepare(`
      SELECT AVG(rating) as avg FROM reviews WHERE mod_id = ?
    `).get(modId).avg;
    
    db.prepare('UPDATE mods SET rating = ? WHERE id = ?').run(avgRating, modId);
    
    res.json({ 
      success: true, 
      reviewId: result.lastInsertRowid,
      newRating: avgRating 
    });
  } catch (error) {
    console.error('Error submitting review:', error);
    res.status(500).json({ error: 'Failed to submit review' });
  }
});

// Track download
app.post('/api/mods/:id/download', (req, res) => {
  const modId = req.params.id;
  const ip = req.ip;
  
  try {
    // Log download
    db.prepare('INSERT INTO downloads (mod_id, user_ip) VALUES (?, ?)').run(modId, ip);
    
    // Increment download counter
    db.prepare('UPDATE mods SET downloads = downloads + 1 WHERE id = ?').run(modId);
    
    const mod = db.prepare('SELECT download_url FROM mods WHERE id = ?').get(modId);
    
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
app.get('/api/categories', (req, res) => {
  const categories = db.prepare(`
    SELECT category, COUNT(*) as count 
    FROM mods 
    GROUP BY category
  `).all();
  
  res.json(categories);
});

// Search mods
app.get('/api/search', (req, res) => {
  const { q } = req.query;
  
  if (!q || q.length < 2) {
    return res.json([]);
  }
  
  const results = db.prepare(`
    SELECT id, name, category, downloads, rating 
    FROM mods 
    WHERE name LIKE ? OR description LIKE ? 
    LIMIT 10
  `).all(`%${q}%`, `%${q}%`);
  
  res.json(results);
});

// Admin: Security Analytics
app.get('/api/admin/security', (req, res) => {
  const analytics = aimless.getAnalytics();
  res.json({
    totalRequests: analytics.totalRequests,
    threatsDetected: analytics.threatsDetected,
    threatsBlocked: analytics.threatsBlocked,
    topAttackTypes: analytics.topAttackTypes,
    topAttackIPs: analytics.topAttackIPs
  });
});

// Admin: Database Stats
app.get('/api/admin/stats', (req, res) => {
  const stats = {
    totalMods: db.prepare('SELECT COUNT(*) as count FROM mods').get().count,
    totalUsers: db.prepare('SELECT COUNT(*) as count FROM users').get().count,
    totalReviews: db.prepare('SELECT COUNT(*) as count FROM reviews').get().count,
    totalDownloads: db.prepare('SELECT SUM(downloads) as total FROM mods').get().total,
    topMods: db.prepare('SELECT name, downloads FROM mods ORDER BY downloads DESC LIMIT 5').all()
  };
  
  res.json(stats);
});

// ============================================
// HTML ROUTES
// ============================================

// Serve index.html for all other routes (SPA)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
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
