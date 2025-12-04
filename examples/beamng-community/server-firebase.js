const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const { Aimless } = require('aimless-security');
const { db, auth } = require('./config/firebase-admin');
require('dotenv').config();

const app = express();

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
      useHosted: false
    },
    
    webhooks: {
      enabled: !!process.env.DISCORD_WEBHOOK_URL,
      url: process.env.DISCORD_WEBHOOK_URL || '',
      events: ['threat', 'block', 'rateLimit']
    },
    
    requestFingerprinting: {
      enabled: true,
      blockAutomatedTraffic: false
    },
    
    rateLimiting: {
      enabled: true,
      maxRequests: 20,
      windowMs: 10000,
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

// Apply Aimless loading screen FIRST
app.use(aimless.loading());

// CORS for Firebase
app.use(cors());

// Body parsers - MUST come before security middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Apply Aimless security middleware AFTER body parsers
app.use(aimless.middleware());

// Static files (exclude index-firebase.html, we serve it manually)
app.use(express.static('public', { index: false }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'beamng-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production' }
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
// API ROUTES (Firebase-powered)
// ============================================

// Search endpoint (for SQL injection testing)
app.get('/api/search', async (req, res) => {
  try {
    const { q } = req.query;
    
    if (!q || q.length < 2) {
      return res.json([]);
    }
    
    // Firebase Firestore search (limited)
    const modsSnapshot = await db.collection('mods')
      .orderBy('name')
      .limit(10)
      .get();
    
    const results = modsSnapshot.docs
      .map(doc => ({ id: doc.id, ...doc.data() }))
      .filter(mod => 
        mod.name.toLowerCase().includes(q.toLowerCase()) ||
        mod.description.toLowerCase().includes(q.toLowerCase())
      );
    
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

// Test endpoint for rate limiting
app.get('/api/mods', (req, res) => {
  res.json({ message: 'Rate limit test endpoint' });
});

// ============================================
// HTML ROUTES
// ============================================

// Serve index-firebase.html for all routes
app.get('*', (req, res) => {
  const indexPath = path.join(__dirname, 'public', 'index-firebase.html');
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
  console.log('🚗 BeamNG Community Site (Firebase Edition)');
  console.log('============================================');
  console.log(`🌐 Server: http://localhost:${PORT}`);
  console.log(`📊 Analytics: http://localhost:${PORT}/admin`);
  console.log(`🛡️  Aimless Security: ENABLED (Block Mode)`);
  console.log(`🔥 Firebase: Connected to ${process.env.FIREBASE_ADMIN_PROJECT_ID || 'PROJECT'}`);
  console.log('');
  console.log('📝 Configure Firebase credentials in .env file');
  console.log('============================================');
  console.log('');
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n✅ Server shutting down gracefully');
  process.exit(0);
});
