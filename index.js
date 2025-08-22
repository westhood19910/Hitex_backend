// 1. IMPORTS

// Add this line at the absolute top of your file
require('dotenv').config();

// 1. IMPORTS
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const MongoStore = require('connect-mongo');

// 2. ENVIRONMENT & INITIAL SETUP
const app = express();
const port = process.env.PORT || 3000;
const uri = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://hitex-editex.vercel.app';
const BACKEND_URL = process.env.BACKEND_URL || 'https://hitex-backend-server.onrender.com';

// 3. MONGODB CLIENT SETUP
const client = new MongoClient(uri, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
});
let usersCollection, manuscriptsCollection;

// Multer Configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, '/opt/render/project/src/uploads'),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});
const upload = multer({ storage: storage });

// 4. MIDDLEWARE SETUP
app.use(helmet());
app.use(cors({ origin: FRONTEND_URL, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ client: client, dbName: 'HitexDB', collectionName: 'sessions' }),
  cookie: { 
    secure: process.env.NODE_ENV === 'production', 
    httpOnly: true, 
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
  }
}));
app.use(passport.initialize());
app.use(passport.session());
app.use('/uploads', express.static('/opt/render/project/src/uploads'));

// 5. PASSPORT CONFIGURATION
passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: `${BACKEND_URL}/auth/google/callback`
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await usersCollection.findOne({ googleId: profile.id });
      if (user) return done(null, user);
      
      const existingUser = await usersCollection.findOne({ email: profile.emails[0].value });
      if (existingUser) {
        await usersCollection.updateOne({ _id: existingUser._id }, { $set: { googleId: profile.id } });
        user = await usersCollection.findOne({ _id: existingUser._id });
        return done(null, user);
      }
      
      const newUser = { googleId: profile.id, fullName: profile.displayName, email: profile.emails[0].value, role: 'author', createdAt: new Date() };
      const result = await usersCollection.insertOne(newUser);
      user = await usersCollection.findOne({ _id: result.insertedId });
      return done(null, user);
    } catch (error) {
      return done(error, null);
    }
  }
));
passport.serializeUser((user, done) => done(null, user._id.toString()));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await usersCollection.findOne({ _id: new ObjectId(id) });
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

// Authentication Middlewares
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.status(401).send({ message: 'Token required.' });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).send({ message: 'Token is invalid or expired.' });
        req.user = user;
        next();
    });
};
const authenticateAdmin = (req, res, next) => {
    // ... same as before
};

// 6. API ROUTES
async function startServer() {
    try {
        await client.connect();
        console.log("Successfully connected to MongoDB!");
        usersCollection = client.db("HitexDB").collection("users");
        manuscriptsCollection = client.db("HitexDB").collection("manuscripts");

        // --- HEALTH CHECK ROUTE ---
        app.get('/', (req, res) => {
            res.send('Hello, your server is running and connected to MongoDB!');
        });

        // --- AUTH ROUTES ---
        app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
        app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: `${FRONTEND_URL}/login?error=auth_failed` }), (req, res) => {
            const user = req.user;
            const token = jwt.sign({ id: user._id, email: user.email, role: user.role || 'author' }, JWT_SECRET, { expiresIn: '8h' });
            const userJson = encodeURIComponent(JSON.stringify(user));
            res.redirect(`${FRONTEND_URL}/auth-success.html?token=${token}&user=${userJson}`);
        });
        
        app.post('/register', async (req, res) => { /* ... same as before ... */ });
        app.post('/login', async (req, res) => { /* ... same as before ... */ });
        
        // --- USER & MANUSCRIPT ROUTES ---
        app.get('/profile', authenticateToken, async (req, res) => { /* ... same as before ... */ });
        app.post('/profile/update', authenticateToken, async (req, res) => { /* ... same as before ... */ });

        // REPLACE your existing '/submit-manuscript' route with this corrected version

        app.post('/submit-manuscript', authenticateToken, upload.single('manuscriptFile'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'A manuscript file is required.' });
        }

        const {
            wordCount, serviceType, salutation, firstName, lastName,
            email, mobile, howHeard, docType, subjectArea,
            langStyle, formatting, instructions, editScope, startWork
        } = req.body;

        const manuscriptData = {
            userId: new ObjectId(req.user.id),
            status: 'New',
            uploadDate: new Date(),
            originalName: req.file.originalname,
            fileName: req.file.filename,
            filePath: `/uploads/${req.file.filename}`, // <-- THE CORRECTION IS HERE
            wordCount, serviceType, docType, subjectArea, langStyle, formatting,
            instructions, editScope, startWork,
            submitterInfo: {
                salutation, firstName, lastName, email, mobile
            },
            howHeard
        };
        
        const result = await manuscriptsCollection.insertOne(manuscriptData);
        res.status(201).json({ message: 'Manuscript submitted successfully!', manuscriptId: result.insertedId });

    } catch (error) {
        console.error("Submission error:", error);
        res.status(500).json({ error: 'Error submitting manuscript.' });
    }
});

        // --- EDITOR & ADMIN ROUTES ---
        app.get('/editor/my-jobs', authenticateToken, async (req, res) => { /* ... same as before ... */ });
        app.post('/admin/login', (req, res) => { /* ... same as before ... */ });
        app.get('/admin/dashboard', authenticateAdmin, async (req, res) => { /* ... same as before ... */ });
        app.get('/admin/editors', authenticateAdmin, async (req, res) => { /* ... same as before ... */ });
        app.post('/admin/assign-job/:manuscriptId', authenticateAdmin, async (req, res) => { /* ... same as before ... */ });

        app.listen(port, () => {
            console.log(`Server running on port ${port}`);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

startServer();