const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const db = new sqlite3.Database(path.join(__dirname, 'beamng.db'), (err) => {
  if (err) {
    console.error('Error opening database:', err);
    process.exit(1);
  }
  console.log('📂 Connected to database');
});

// Run all queries in series
db.serialize(() => {
  // Create tables
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      avatar_url TEXT,
      bio TEXT,
      role TEXT DEFAULT 'user',
      banned INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS mods (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      category TEXT DEFAULT 'vehicle',
      download_url TEXT,
      image_url TEXT,
      downloads INTEGER DEFAULT 0,
      rating REAL DEFAULT 0,
      featured INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      mod_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      rating INTEGER CHECK(rating >= 1 AND rating <= 5),
      comment TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (mod_id) REFERENCES mods(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS downloads (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      mod_id INTEGER NOT NULL,
      user_ip TEXT,
      downloaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (mod_id) REFERENCES mods(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS sessions (
      sid TEXT PRIMARY KEY,
      sess TEXT NOT NULL,
      expired INTEGER NOT NULL
    )
  `);

  console.log('✅ Tables created');

  // Check if data already exists
  const existingUsers = db.prepare('SELECT COUNT(*) as count FROM users').get();
  const existingMods = db.prepare('SELECT COUNT(*) as count FROM mods').get();
  
  if (existingUsers.count > 0 || existingMods.count > 0) {
    console.log('⚠️  Database already has data - skipping sample data insertion');
    console.log(`   Found ${existingUsers.count} users and ${existingMods.count} mods`);
    console.log('📊 Database tables verified!');
    db.close();
    process.exit(0);
    return;
  }

  // Insert sample users (password: "password123" for all)
  const bcrypt = require('bcrypt');
  const hashedPassword = bcrypt.hashSync('password123', 10);
  
  db.run('INSERT OR IGNORE INTO users (username, email, password, role, bio, avatar_url) VALUES (?, ?, ?, ?, ?, ?)', 
    ['admin', 'admin@beamng.local', hashedPassword, 'admin', 'Site administrator', 'https://api.dicebear.com/7.x/avataaars/svg?seed=admin']);
  
  db.run('INSERT OR IGNORE INTO users (username, email, password, bio, avatar_url) VALUES (?, ?, ?, ?, ?)', 
    ['modder123', 'modder@beamng.local', hashedPassword, 'BeamNG modding enthusiast', 'https://api.dicebear.com/7.x/avataaars/svg?seed=modder123']);

  // Insert sample mods
  db.run(`
    INSERT OR IGNORE INTO mods (user_id, name, description, category, download_url, downloads, rating) 
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `, [
    1,
    'Super Sport Coupe',
    'High-performance sports car with detailed interior and realistic physics',
    'vehicle',
    'https://example.com/downloads/sports-coupe.zip',
    1234,
    4.8
  ]);

  db.run(`
    INSERT OR IGNORE INTO mods (user_id, name, description, category, download_url, downloads, rating) 
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `, [
    2,
    'Mountain Rally Track',
    'Challenging mountain rally course with tight corners and jumps',
    'map',
    'https://example.com/downloads/mountain-rally.zip',
    856,
    4.5
  ]);

  db.run(`
    INSERT OR IGNORE INTO mods (user_id, name, description, category, download_url, downloads, rating) 
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `, [
    1,
    'Realistic Traffic AI',
    'Improved AI traffic behavior and density controls',
    'gameplay',
    'https://example.com/downloads/traffic-ai.zip',
    2341,
    4.9
  ], (err) => {
    if (err) {
      console.error('Error inserting sample data:', err);
    } else {
      console.log('✅ Sample data added');
      console.log('📊 Database initialized successfully!');
    }
    
    db.close((err) => {
      if (err) {
        console.error('Error closing database:', err);
      }
      process.exit(0);
    });
  });
});
