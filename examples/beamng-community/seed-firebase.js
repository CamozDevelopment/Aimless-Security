require('dotenv').config();
const { db, admin } = require('./config/firebase-admin');

const sampleMods = [
  {
    name: 'ETK K-Series Racing Edition',
    description: 'High-performance racing variant of the ETK K-Series with improved aerodynamics, lightweight carbon fiber body panels, and a tuned turbocharged engine producing 600+ horsepower. Features adjustable suspension, racing slicks, and full roll cage.',
    category: 'vehicle',
    userId: 'demo_user_1',
    username: 'SpeedDemon92',
    downloads: 15234,
    rating: 4.8,
    reviewCount: 127,
    version: '2.1.0',
    fileSize: '45.2 MB',
    imageUrl: 'https://images.unsplash.com/photo-1544829099-b9a0c07fad1a?w=800&auto=format&fit=crop',
    tags: ['racing', 'tuned', 'performance', 'etk'],
    compatibility: ['0.30', '0.31'],
    changelog: 'v2.1.0: Added new liveries, improved handling, fixed minor bugs'
  },
  {
    name: 'Jungle Off-Road Map',
    description: 'Explore dense tropical jungle terrain with challenging off-road trails, river crossings, and hidden ruins. This massive 16km² map features varying elevation, mud pits, rock crawling sections, and scenic waterfalls perfect for adventure driving.',
    category: 'map',
    userId: 'demo_user_2',
    username: 'TerrainMaster',
    downloads: 28901,
    rating: 4.9,
    reviewCount: 312,
    version: '1.5.2',
    fileSize: '892 MB',
    imageUrl: 'https://images.unsplash.com/photo-1511497584788-876760111969?w=800&auto=format&fit=crop',
    tags: ['off-road', 'jungle', 'adventure', 'trails'],
    compatibility: ['0.30', '0.31'],
    changelog: 'v1.5.2: Performance optimizations, new hidden areas, improved vegetation'
  },
  {
    name: 'Realistic Damage Physics',
    description: 'Overhaul mod that implements ultra-realistic vehicle damage physics. Every collision affects vehicle performance realistically - bent frames affect handling, damaged radiators cause overheating, and broken suspension components make the car nearly undrivable.',
    category: 'gameplay',
    userId: 'demo_user_3',
    username: 'PhysicsWizard',
    downloads: 42567,
    rating: 4.7,
    reviewCount: 523,
    version: '3.0.1',
    fileSize: '12.8 MB',
    imageUrl: 'https://images.unsplash.com/photo-1568605117036-5fe5e7bab0b7?w=800&auto=format&fit=crop',
    tags: ['physics', 'realism', 'damage', 'simulation'],
    compatibility: ['0.30', '0.31'],
    changelog: 'v3.0.1: Fixed crash issue, improved engine damage modeling'
  },
  {
    name: 'Hirochi Sunburst Drift Build',
    description: 'Purpose-built drift machine based on the Hirochi Sunburst. Features welded differential, angle kit, hydraulic handbrake, and a turbocharged inline-4 engine tuned for instant throttle response. Comes with 5 custom liveries.',
    category: 'vehicle',
    userId: 'demo_user_1',
    username: 'SpeedDemon92',
    downloads: 19823,
    rating: 4.6,
    reviewCount: 198,
    version: '1.8.0',
    fileSize: '38.4 MB',
    imageUrl: 'https://images.unsplash.com/photo-1552519507-da3b142c6e3d?w=800&auto=format&fit=crop',
    tags: ['drift', 'tuned', 'hirochi', 'jdm'],
    compatibility: ['0.30', '0.31'],
    changelog: 'v1.8.0: New liveries added, improved steering angle'
  },
  {
    name: 'Industrial District Racetrack',
    description: 'Street circuit through an abandoned industrial zone featuring tight corners, long straights, and technical chicanes. Perfect for both racing and drifting. Includes night lighting, grandstands, and multiple track layouts (2.4km, 3.8km, 5.1km).',
    category: 'map',
    userId: 'demo_user_4',
    username: 'CircuitBuilder',
    downloads: 33456,
    rating: 4.8,
    reviewCount: 267,
    version: '2.3.0',
    fileSize: '624 MB',
    imageUrl: 'https://images.unsplash.com/photo-1558618666-fcd25c85cd64?w=800&auto=format&fit=crop',
    tags: ['racing', 'street', 'circuit', 'drift'],
    compatibility: ['0.30', '0.31'],
    changelog: 'v2.3.0: Added night lighting, new track layout variant'
  },
  {
    name: 'Advanced Traffic AI',
    description: 'Completely rewritten traffic AI that makes NPC vehicles behave realistically. They obey speed limits, use turn signals, react to emergency vehicles, and even get frustrated in traffic jams. Includes adjustable aggression levels and traffic density.',
    category: 'gameplay',
    userId: 'demo_user_5',
    username: 'CodeCrafter',
    downloads: 38912,
    rating: 4.5,
    reviewCount: 445,
    version: '4.2.1',
    fileSize: '8.7 MB',
    imageUrl: 'https://images.unsplash.com/photo-1449965408869-eaa3f722e40d?w=800&auto=format&fit=crop',
    tags: ['ai', 'traffic', 'realism', 'npc'],
    compatibility: ['0.30', '0.31'],
    changelog: 'v4.2.1: Improved intersection behavior, reduced CPU usage'
  },
  {
    name: 'D-Series Monster Truck',
    description: 'Lifted D-Series pickup with massive 54-inch tires, heavy-duty suspension with 24 inches of travel, and a supercharged V8 engine. Perfect for crushing cars and climbing over obstacles. Includes light bar and custom paint options.',
    category: 'vehicle',
    userId: 'demo_user_6',
    username: 'MudSlinger',
    downloads: 21445,
    rating: 4.7,
    reviewCount: 156,
    version: '1.4.0',
    fileSize: '52.3 MB',
    imageUrl: 'https://images.unsplash.com/photo-1533473359331-0135ef1b58bf?w=800&auto=format&fit=crop',
    tags: ['monster-truck', 'lifted', 'd-series', 'extreme'],
    compatibility: ['0.30', '0.31'],
    changelog: 'v1.4.0: New tire options, improved suspension physics'
  },
  {
    name: 'Mountain Pass Touge',
    description: 'Narrow mountain road with hairpin turns, elevation changes, and stunning vistas. Based on famous Japanese touge roads, this map is perfect for spirited driving and drift battles. Features day/night cycle and dynamic weather.',
    category: 'map',
    userId: 'demo_user_2',
    username: 'TerrainMaster',
    downloads: 44567,
    rating: 4.9,
    reviewCount: 389,
    version: '2.0.5',
    fileSize: '756 MB',
    imageUrl: 'https://images.unsplash.com/photo-1506905925346-21bda4d32df4?w=800&auto=format&fit=crop',
    tags: ['touge', 'mountain', 'drift', 'scenic'],
    compatibility: ['0.30', '0.31'],
    changelog: 'v2.0.5: Weather system improvements, visual enhancements'
  },
  {
    name: 'Cinematic Camera Suite',
    description: 'Professional camera tools for creating stunning videos and screenshots. Includes smooth camera paths, customizable FOV, motion blur controls, depth of field, and replay recording. Perfect for content creators.',
    category: 'gameplay',
    userId: 'demo_user_7',
    username: 'CinematicPro',
    downloads: 17823,
    rating: 4.6,
    reviewCount: 134,
    version: '2.7.0',
    fileSize: '4.2 MB',
    imageUrl: 'https://images.unsplash.com/photo-1485846234645-a62644f84728?w=800&auto=format&fit=crop',
    tags: ['camera', 'cinematic', 'tools', 'video'],
    compatibility: ['0.30', '0.31'],
    changelog: 'v2.7.0: Added new camera presets, improved smoothing'
  },
  {
    name: 'Gavril Grand Marshal Police Interceptor',
    description: 'Fully equipped police interceptor based on the Gavril Grand Marshal. Features working emergency lights, siren, push bar, spotlight, laptop, and radio. Includes realistic police liveries from various departments.',
    category: 'vehicle',
    userId: 'demo_user_8',
    username: 'LawEnforcer',
    downloads: 25678,
    rating: 4.8,
    reviewCount: 201,
    version: '1.9.2',
    fileSize: '41.7 MB',
    imageUrl: 'https://images.unsplash.com/photo-1590031905350-cf57c8c9b127?w=800&auto=format&fit=crop',
    tags: ['police', 'emergency', 'gavril', 'roleplay'],
    compatibility: ['0.30', '0.31'],
    changelog: 'v1.9.2: New liveries, improved light patterns'
  },
  {
    name: 'Desert Racing Stadium',
    description: 'Short-course off-road racing stadium with jumps, berms, and whoops sections. Host competitive races or practice your trophy truck driving. Includes grandstands, pit areas, and spectator zones. Multiple track configurations available.',
    category: 'map',
    userId: 'demo_user_4',
    username: 'CircuitBuilder',
    downloads: 18934,
    rating: 4.5,
    reviewCount: 143,
    version: '1.2.0',
    fileSize: '445 MB',
    imageUrl: 'https://images.unsplash.com/photo-1547036967-23d11aacaee0?w=800&auto=format&fit=crop',
    tags: ['desert', 'racing', 'stadium', 'off-road'],
    compatibility: ['0.30', '0.31'],
    changelog: 'v1.2.0: Added new track variant, improved terrain'
  },
  {
    name: 'Vehicle Customization Expanded',
    description: 'Massive expansion of vehicle customization options. Adds hundreds of new parts, paint options, wheels, body kits, interior modifications, and performance upgrades. Compatible with all vanilla vehicles.',
    category: 'gameplay',
    userId: 'demo_user_3',
    username: 'PhysicsWizard',
    downloads: 51234,
    rating: 4.9,
    reviewCount: 612,
    version: '5.1.3',
    fileSize: '156 MB',
    imageUrl: 'https://images.unsplash.com/photo-1503376780353-7e6692767b70?w=800&auto=format&fit=crop',
    tags: ['customization', 'parts', 'tuning', 'expansion'],
    compatibility: ['0.30', '0.31'],
    changelog: 'v5.1.3: Added 50+ new wheels, more body kits, bug fixes'
  }
];

const sampleUsers = [
  {
    uid: 'demo_user_1',
    displayName: 'SpeedDemon92',
    email: 'speeddemon@example.com',
    photoURL: 'https://i.pravatar.cc/150?u=speeddemon92',
    role: 'user',
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    modsUploaded: 2,
    bio: 'Car enthusiast and mod creator. Love building high-performance vehicles!'
  },
  {
    uid: 'demo_user_2',
    displayName: 'TerrainMaster',
    email: 'terrain@example.com',
    photoURL: 'https://i.pravatar.cc/150?u=terrainmaster',
    role: 'user',
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    modsUploaded: 2,
    bio: 'Map designer specializing in realistic terrain and environments.'
  },
  {
    uid: 'demo_user_3',
    displayName: 'PhysicsWizard',
    email: 'physics@example.com',
    photoURL: 'https://i.pravatar.cc/150?u=physicswizard',
    role: 'user',
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    modsUploaded: 2,
    bio: 'Physics programmer making BeamNG more realistic one mod at a time.'
  },
  {
    uid: 'demo_user_4',
    displayName: 'CircuitBuilder',
    email: 'circuit@example.com',
    photoURL: 'https://i.pravatar.cc/150?u=circuitbuilder',
    role: 'user',
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    modsUploaded: 2,
    bio: 'Professional track designer with a passion for racing circuits.'
  },
  {
    uid: 'demo_user_5',
    displayName: 'CodeCrafter',
    email: 'code@example.com',
    photoURL: 'https://i.pravatar.cc/150?u=codecrafter',
    role: 'user',
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    modsUploaded: 1,
    bio: 'Software developer improving game AI and mechanics.'
  },
  {
    uid: 'demo_user_6',
    displayName: 'MudSlinger',
    email: 'mud@example.com',
    photoURL: 'https://i.pravatar.cc/150?u=mudslinger',
    role: 'user',
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    modsUploaded: 1,
    bio: 'Off-road enthusiast creating extreme lifted vehicles.'
  },
  {
    uid: 'demo_user_7',
    displayName: 'CinematicPro',
    email: 'cinematic@example.com',
    photoURL: 'https://i.pravatar.cc/150?u=cinematicpro',
    role: 'user',
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    modsUploaded: 1,
    bio: 'Content creator building tools for beautiful screenshots and videos.'
  },
  {
    uid: 'demo_user_8',
    displayName: 'LawEnforcer',
    email: 'law@example.com',
    photoURL: 'https://i.pravatar.cc/150?u=lawenforcer',
    role: 'user',
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    modsUploaded: 1,
    bio: 'Emergency vehicle modder and roleplay enthusiast.'
  }
];

async function seedDatabase() {
  console.log('🌱 Starting database seeding...\n');

  try {
    // Seed users
    console.log('👥 Creating sample users...');
    for (const user of sampleUsers) {
      await db.collection('users').doc(user.uid).set(user);
      console.log(`   ✓ Created user: ${user.displayName}`);
    }
    console.log(`✅ Created ${sampleUsers.length} users\n`);

    // Seed mods
    console.log('📦 Creating sample mods...');
    for (const mod of sampleMods) {
      const modData = {
        ...mod,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      };
      await db.collection('mods').add(modData);
      console.log(`   ✓ Created mod: ${mod.name}`);
    }
    console.log(`✅ Created ${sampleMods.length} mods\n`);

    // Seed some sample reviews
    console.log('⭐ Creating sample reviews...');
    const modSnapshots = await db.collection('mods').limit(5).get();
    let reviewCount = 0;

    for (const modDoc of modSnapshots.docs) {
      const sampleReviews = [
        {
          userId: 'demo_user_1',
          username: 'SpeedDemon92',
          userAvatar: 'https://i.pravatar.cc/150?u=speeddemon92',
          modId: modDoc.id,
          rating: 5,
          comment: 'Absolutely amazing! This mod exceeded all my expectations. Highly recommended!',
          createdAt: admin.firestore.FieldValue.serverTimestamp()
        },
        {
          userId: 'demo_user_2',
          username: 'TerrainMaster',
          userAvatar: 'https://i.pravatar.cc/150?u=terrainmaster',
          modId: modDoc.id,
          rating: 4,
          comment: 'Great work overall. Could use some minor improvements but still really solid.',
          createdAt: admin.firestore.FieldValue.serverTimestamp()
        },
        {
          userId: 'demo_user_3',
          username: 'PhysicsWizard',
          userAvatar: 'https://i.pravatar.cc/150?u=physicswizard',
          modId: modDoc.id,
          rating: 5,
          comment: 'The attention to detail is incredible. This is how mods should be made!',
          createdAt: admin.firestore.FieldValue.serverTimestamp()
        }
      ];

      for (const review of sampleReviews) {
        await db.collection('reviews').add(review);
        reviewCount++;
      }
    }
    console.log(`✅ Created ${reviewCount} reviews\n`);

    console.log('🎉 Database seeding completed successfully!\n');
    console.log('📊 Summary:');
    console.log(`   - Users: ${sampleUsers.length}`);
    console.log(`   - Mods: ${sampleMods.length}`);
    console.log(`   - Reviews: ${reviewCount}`);
    console.log('\n✨ Your Firebase database is now populated with sample data!');
    
  } catch (error) {
    console.error('❌ Error seeding database:', error);
    process.exit(1);
  }

  process.exit(0);
}

// Run the seeding
seedDatabase();
