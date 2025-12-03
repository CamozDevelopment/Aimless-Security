const express = require('express');
const session = require('express-session');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const { Aimless } = require('aimless-sdk');

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
    blockMode: true,
    injectionProtection: true,
    xssProtection: true,
    csrfProtection: false,
    anomalyDetection: true,
    
    loadingScreen: {
      enabled: true,
      message: 'Securing BeamNG Community...',
      minDuration: 1000,
      hostedUrl: 'https://aimless.qzz.io/security/loading.html',
      useHosted: true
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
      maxRequests: 20,  // Lower for testing
      windowMs: 10000,   // 10 seconds
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

// Apply Aimless security middleware AFTER body parsers
app.use(aimless.middleware());

// Static files and session
app.use(express.static('public'));
app.use(session({
  secret: 'beamng-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // Set to true with HTTPS
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
// API ROUTES
// ============================================

// Get all mods
app.get('/api/mods', async (req, res) => {
  try {
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

// Submit review (Protected by Aimless)
app.post('/api/mods/:id/reviews', async (req, res) => {
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
    
    // Insert review (using default user for demo)
    const result = await dbRun(`
      INSERT INTO reviews (mod_id, user_id, rating, comment) 
      VALUES (?, ?, ?, ?)
    `, [modId, 1, rating, comment]);
    
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
