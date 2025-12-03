# BeamNG Mods Community Site

A full-featured BeamNG.drive mods community site with Aimless Security protection.

## Features

✅ **Browse & Search Mods** - Filter by category, sort by downloads/rating  
✅ **Mod Reviews** - Rate and review mods (1-5 stars)  
✅ **Download Tracking** - Track downloads and popular mods  
✅ **Security Dashboard** - Real-time security analytics  
✅ **SQLite Database** - No external database needed  
✅ **Aimless Security** - Protection against SQL injection, XSS, bots, rate limiting  

## Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. Initialize Database

```bash
npm run init-db
```

### 3. Start Server

```bash
npm start
```

### 4. Open Browser

Navigate to: **http://localhost:3000**

## Project Structure

```
beamng-community/
├── server.js           # Express server with Aimless Security
├── init-db.js          # Database initialization script
├── package.json        # Dependencies
├── beamng.db          # SQLite database (created after init-db)
└── public/
    ├── index.html     # Frontend HTML
    └── app.js         # Frontend JavaScript
```

## Security Features

### Aimless Security is configured in MONITOR MODE:

- ✅ **SQL Injection Protection** - Detects and logs SQL injection attempts
- ✅ **XSS Protection** - Sanitizes user input in reviews/comments
- ✅ **Bot Detection** - Identifies automated traffic
- ✅ **Rate Limiting** - Prevents abuse (100 requests/minute)
- ✅ **Loading Screen** - Shows security check on page load
- ✅ **Analytics** - Track threats and attacks in real-time

**Current Mode:** `blockMode: false` (Monitor only - logs but doesn't block)

### To Enable Blocking:

Edit `server.js` and change:
```javascript
blockMode: false  // Change to true
```

## Test Security Features

Visit the **Security** tab in the app and click:

- **SQL Injection** - Tests `' OR '1'='1` attack
- **XSS Attack** - Tests `<script>` injection
- **Rate Limit** - Sends 50 rapid requests

All tests will be logged but NOT blocked (monitor mode).

## API Endpoints

### Mods
- `GET /api/mods` - Get all mods (with filters)
- `GET /api/mods/:id` - Get single mod
- `GET /api/mods/:id/reviews` - Get mod reviews
- `POST /api/mods/:id/reviews` - Submit review
- `POST /api/mods/:id/download` - Track download

### Admin
- `GET /api/admin/security` - Security analytics
- `GET /api/admin/stats` - Database stats

## Database Schema

### Tables:
- **users** - User accounts
- **mods** - Mod listings
- **reviews** - User reviews (rating + comment)
- **downloads** - Download tracking

## Enable Webhooks

To get Discord notifications when attacks happen:

1. Create a Discord webhook
2. Edit `server.js`:
```javascript
webhooks: {
  enabled: true,
  url: 'https://discord.com/api/webhooks/YOUR/WEBHOOK/URL',
  events: ['threat', 'block']
}
```

## Deploy to Production

### Railway.app (Recommended)

```bash
# Install Railway CLI
npm i -g @railway/cli

# Login
railway login

# Initialize project
railway init

# Deploy
railway up
```

### Environment Variables

Set these in production:
```
NODE_ENV=production
PORT=3000
SESSION_SECRET=your-secret-key-here
```

## Security Best Practices

1. **Start in Monitor Mode** - Run for 24-48 hours
2. **Check Logs** - Review detected threats
3. **Enable Blocking** - Set `blockMode: true` when ready
4. **Add Webhooks** - Get instant attack notifications
5. **Monitor Analytics** - Check `/admin` dashboard regularly

## Tech Stack

- **Backend:** Express.js + Node.js
- **Database:** SQLite (better-sqlite3)
- **Security:** Aimless SDK v1.3.4
- **Frontend:** HTML + Tailwind CSS + Vanilla JS
- **Session:** express-session

## License

MIT

---

**Protected by Aimless Security** 🛡️
