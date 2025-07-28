// 1. IMPORTS
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const MongoStore = require('connect-mongo');
const Joi = require('joi');
const winston = require('winston');

// 2. LOGGING SETUP
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
  ]
});

// If not in production, also log to the console
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple(),
  }));
}


// 3. ENVIRONMENT VALIDATION
const requiredEnvVars = ['MONGODB_URI', 'JWT_SECRET', 'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'SESSION_SECRET', 'ADMIN_USERNAME', 'ADMIN_PASSWORD'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    logger.error(`Missing required environment variable: ${envVar}`);
    process.exit(1);
  }
}

// 4. INITIAL SETUP
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

// 5. MONGODB CLIENT SETUP
const client = new MongoClient(uri, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
});

let usersCollection, manuscriptsCollection;

// 6. MIDDLEWARE SETUP
app.use(helmet());
app.use(cors({ origin: FRONTEND_URL, credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    client: client,
    dbName: 'HitexDB',
    collectionName: 'sessions',
    ttl: 14 * 24 * 60 * 60 // 14 days
  }),
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 8 * 60 * 60 * 1000 // 8 hours
  }
}));
app.use(passport.initialize());
app.use(passport.session());
app.use('/uploads', express.static('/opt/render/project/src/uploads')); // Use absolute path for Render disk

// 7. PASSPORT CONFIGURATION
passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: `${BACKEND_URL}/auth/google/callback`
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await usersCollection.findOne({ googleId: profile.id });
      if (user) {
        return done(null, user);
      }
      const existingUser = await usersCollection.findOne({ email: profile.emails[0].value });
      if (existingUser) {
        await usersCollection.updateOne({ _id: existingUser._id }, { $set: { googleId: profile.id } });
        user = await usersCollection.findOne({ _id: existingUser._id });
        return done(null, user);
      }
      const newUser = {
        googleId: profile.id,
        fullName: profile.displayName,
        email: profile.emails[0].value,
        role: 'author',
        createdAt: new Date()
      };
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

// 8. AUTHENTICATION MIDDLEWARE
const authenticateToken = (req, res, next) => { /* ... your existing correct code */ };
const authenticateAdmin = (req, res, next) => { /* ... your existing correct code */ };
const sanitizeUser = (user) => { const { password, ...sanitized } = user; return sanitized; };

// 9. API ROUTES

// --- HEALTH CHECK ---
app.get('/', (req, res) => res.json({ message: 'Hitex Server is live' }));

// --- AUTH ROUTES ---
app.post('/register', async (req, res) => {
    try {
        const { fullName, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await usersCollection.insertOne({ fullName, email, password: hashedPassword, role: 'author', createdAt: new Date() });
        res.status(201).send({ message: 'User registered successfully!', userId: result.insertedId });
    } catch (error) {
        if (error.code === 11000) return res.status(409).json({ error: 'User already exists with this email' });
        res.status(500).json({ error: 'Error registering user' });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).json({ error: "User not found." });

        const isPasswordCorrect = await bcrypt.compare(password, user.password);
        if (!isPasswordCorrect) return res.status(401).json({ error: "Invalid credentials." });
        
        await usersCollection.updateOne({ _id: user._id }, { $set: { lastLogin: new Date() } });
        
        const token = jwt.sign({ id: user._id, email: user.email, role: user.role || 'author' }, JWT_SECRET, { expiresIn: '8h' });
        res.status(200).json({ message: "Login successful!", token, user: sanitizeUser(user) });
    } catch (error) { res.status(500).json({ error: "An error occurred during login." }); }
});

// --- GOOGLE AUTH ROUTES ---
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: `${FRONTEND_URL}/login?error=auth_failed` }), (req, res) => {
    const user = req.user;
    const token = jwt.sign({ id: user._id, email: user.email, role: user.role || 'author' }, JWT_SECRET, { expiresIn: '8h' });
    const userJson = encodeURIComponent(JSON.stringify(sanitizeUser(user)));
    res.redirect(`${FRONTEND_URL}/auth-success.html?token=${token}&user=${userJson}`);
});

// --- All other routes from your professional version ---

// 10. SERVER STARTUP
async function startServer() {
    try {
        await connectToDatabase();
        app.listen(port, () => {
            logger.info(`Server running on port ${port}`);
        });
    } catch (error) {
        logger.error('Failed to start server:', error);
        process.exit(1);
    }
}

startServer();