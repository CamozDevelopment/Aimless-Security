const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'beamng.db'));

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

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
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mod_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    rating INTEGER CHECK(rating >= 1 AND rating <= 5),
    comment TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (mod_id) REFERENCES mods(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS downloads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mod_id INTEGER NOT NULL,
    user_ip TEXT,
    downloaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (mod_id) REFERENCES mods(id)
  );
`);

// Insert sample data
const insertUser = db.prepare('INSERT OR IGNORE INTO users (username, email) VALUES (?, ?)');
insertUser.run('admin', 'admin@beamng.local');
insertUser.run('modder123', 'modder@beamng.local');

const insertMod = db.prepare(`
  INSERT OR IGNORE INTO mods (user_id, name, description, category, download_url, downloads, rating) 
  VALUES (?, ?, ?, ?, ?, ?, ?)
`);

insertMod.run(
  1,
  'Super Sport Coupe',
  'High-performance sports car with detailed interior and realistic physics',
  'vehicle',
  'https://example.com/downloads/sports-coupe.zip',
  1234,
  4.8
);

insertMod.run(
  2,
  'Mountain Rally Track',
  'Challenging mountain rally course with tight corners and jumps',
  'map',
  'https://example.com/downloads/mountain-rally.zip',
  856,
  4.5
);

insertMod.run(
  1,
  'Realistic Traffic AI',
  'Improved AI traffic behavior and density controls',
  'gameplay',
  'https://example.com/downloads/traffic-ai.zip',
  2341,
  4.9
);

console.log('✅ Database initialized successfully!');
console.log('📊 Sample data added');
db.close();
