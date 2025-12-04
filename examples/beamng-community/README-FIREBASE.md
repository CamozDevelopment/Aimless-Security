# BeamNG Mods Community - Firebase Edition

A modern, fully-featured community platform for BeamNG.drive mods, powered by Firebase and protected by Aimless Security.

## ✨ Features

### 🔐 Authentication
- Email/Password signup and login
- Google Sign-In
- User profiles with avatars
- Protected routes

### 🗄️ Firebase Integration
- **Firestore** for real-time database
- **Firebase Authentication** for secure user management
- **Firebase Storage** for mod images and files
- Offline persistence support

### 🛡️ Security (Aimless Security v1.3.4)
- SQL Injection protection
- XSS attack prevention
- CSRF protection
- Rate limiting
- Bot detection
- Real-time threat monitoring
- Discord webhook notifications
- Loading screen during security checks

### 🎨 Modern UI/UX
- Tailwind CSS styling
- Smooth animations
- Skeleton loaders
- Toast notifications
- Responsive design
- Dark theme

### 📦 Mod Management
- Upload mods with images
- Categories (Vehicles, Maps, Gameplay)
- Ratings and reviews
- Download tracking
- Search and filtering
- Real-time updates

## 🚀 Quick Start

### 1. Firebase Setup

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Create a new project
3. Enable **Authentication** (Email/Password and Google)
4. Enable **Firestore Database**
5. Enable **Storage**
6. Create a service account:
   - Project Settings → Service Accounts
   - Generate new private key
   - Save the JSON file

### 2. Configuration

1. Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

2. Fill in your Firebase credentials in `.env`:
```env
FIREBASE_API_KEY=your_api_key
FIREBASE_AUTH_DOMAIN=your_project.firebaseapp.com
FIREBASE_PROJECT_ID=your_project_id
FIREBASE_STORAGE_BUCKET=your_project.appspot.com
FIREBASE_MESSAGING_SENDER_ID=123456789
FIREBASE_APP_ID=1:123456789:web:abc123

# From service account JSON
FIREBASE_ADMIN_PROJECT_ID=your_project_id
FIREBASE_ADMIN_CLIENT_EMAIL=firebase-adminsdk@your_project.iam.gserviceaccount.com
FIREBASE_ADMIN_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"

# Optional
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR/WEBHOOK
```

3. Update `config/firebase.js` with your frontend config:
```javascript
const firebaseConfig = {
  apiKey: "YOUR_API_KEY",
  authDomain: "YOUR_PROJECT.firebaseapp.com",
  projectId: "YOUR_PROJECT_ID",
  storageBucket: "YOUR_PROJECT.appspot.com",
  messagingSenderId: "YOUR_SENDER_ID",
  appId: "YOUR_APP_ID"
};
```

### 3. Firestore Security Rules

Add these rules in Firebase Console → Firestore → Rules:

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Users collection
    match /users/{userId} {
      allow read: if true;
      allow create: if request.auth != null && request.auth.uid == userId;
      allow update: if request.auth != null && request.auth.uid == userId;
      allow delete: if request.auth != null && request.auth.uid == userId;
    }
    
    // Mods collection
    match /mods/{modId} {
      allow read: if true;
      allow create: if request.auth != null 
        && request.resource.data.name is string
        && request.resource.data.description is string
        && request.resource.data.category in ['vehicle', 'map', 'gameplay'];
      allow update: if request.auth != null 
        && (request.auth.uid == resource.data.userId 
            || get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'admin');
      allow delete: if request.auth != null 
        && (request.auth.uid == resource.data.userId 
            || get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'admin');
    }
    
    // Reviews collection
    match /reviews/{reviewId} {
      allow read: if true;
      allow create: if request.auth != null
        && request.resource.data.rating >= 1 
        && request.resource.data.rating <= 5
        && request.resource.data.comment.size() >= 10
        && request.resource.data.comment.size() <= 500;
      allow update, delete: if request.auth != null && request.auth.uid == resource.data.userId;
    }
    
    // Downloads collection
    match /downloads/{downloadId} {
      allow read: if request.auth != null;
      allow create: if request.auth != null;
    }
  }
}
```

### 4. Storage Security Rules

Firebase Console → Storage → Rules:

```javascript
rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /mods/{modId}/{allPaths=**} {
      allow read: if true;
      allow write: if request.auth != null
        && request.resource.size < 10 * 1024 * 1024  // 10MB limit
        && request.resource.contentType.matches('image/.*');
    }
  }
}
```

### 5. Install and Run

```bash
npm install
npm run firebase  # Runs server-firebase.js
```

Visit `http://localhost:3000`

## 📁 Project Structure

```
beamng-community/
├── config/
│   ├── firebase.js           # Frontend Firebase config
│   └── firebase-admin.js     # Backend Firebase Admin SDK
├── public/
│   ├── index-firebase.html   # Main HTML with Firebase
│   └── firebase-app.js       # Frontend JavaScript
├── .env                       # Environment variables (create from .env.example)
├── .env.example              # Template for environment variables
├── server-firebase.js        # Express server with Firebase
└── package.json
```

## 🎮 Usage

### For Users

1. **Sign Up/Sign In**: Click "Sign In" in the header
2. **Browse Mods**: Navigate to "Mods" to see all available mods
3. **Upload Mods**: Sign in, then click "Upload Mod" (coming soon)
4. **Rate & Review**: Click on a mod to leave reviews

### For Developers

#### Adding Sample Data

```javascript
// In Firebase Console or using Admin SDK
await db.collection('mods').add({
  name: 'Super Sport Coupe',
  description: 'High-performance sports car',
  category: 'vehicle',
  userId: 'user_id',
  username: 'modder123',
  downloads: 0,
  rating: 0,
  imageUrl: 'https://example.com/image.jpg',
  createdAt: firebase.firestore.FieldValue.serverTimestamp()
});
```

#### Real-time Listeners

```javascript
// Listen for new mods
db.collection('mods')
  .orderBy('createdAt', 'desc')
  .limit(10)
  .onSnapshot(snapshot => {
    snapshot.docChanges().forEach(change => {
      if (change.type === 'added') {
        console.log('New mod:', change.doc.data());
      }
    });
  });
```

## 🔒 Security Features

### Aimless Security Protection

- **SQL Injection**: Protects against database injection attacks
- **XSS**: Prevents cross-site scripting attacks
- **Rate Limiting**: 100 requests per minute
- **Threat Logging**: All threats logged to console
- **Webhooks**: Optional Discord notifications
- **Loading Screen**: Shows security check during page load
- **Auth Route Skip**: Authentication endpoints bypass security to prevent false positives

**Important:** When using authentication, apply Aimless conditionally:

```javascript
app.use(aimless.loading());

// Skip Aimless for auth routes
app.use((req, res, next) => {
  const authPaths = ['/api/auth/login', '/api/auth/register', '/api/auth/logout'];
  if (authPaths.includes(req.path)) return next();
  aimless.middleware()(req, res, next);
});
```

### Testing Security

Navigate to **Security** dashboard and use the test buttons:
- Test SQL Injection
- Test XSS Attack
- Test Rate Limiting

## 🎨 Customization

### Changing Theme Colors

Edit `index-firebase.html` Tailwind classes:
- Blue: `bg-blue-600` → `bg-purple-600`
- Gradients: `from-blue-900 via-purple-900 to-blue-900`

### Adding New Mod Categories

1. Update Firestore rules (allow new category)
2. Add option in `index-firebase.html` category filter
3. Update validation in upload form

## 📊 Analytics

- Total mods, users, downloads, reviews
- Security analytics (threats detected, blocked)
- Real-time updates via Firestore listeners

## 🐛 Troubleshooting

### Firebase Not Connecting
- Check `.env` file has correct credentials
- Verify `config/firebase.js` matches Firebase Console
- Check browser console for errors

### Authentication Errors
- Enable Email/Password in Firebase Console → Authentication → Sign-in method
- Enable Google provider if using Google Sign-In
- Check CORS settings

### Security Rules Failing
- Test rules in Firebase Console → Firestore → Rules Playground
- Check user is authenticated before writing
- Verify data structure matches rules

## 📝 License

MIT License - See main repository for details

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 🔗 Links

- [Aimless Security](https://github.com/CamozDevelopment/Aimless-Security)
- [Firebase Documentation](https://firebase.google.com/docs)
- [BeamNG.drive](https://www.beamng.com/)

---

Built with ❤️ using Firebase, Express.js, and Aimless Security
