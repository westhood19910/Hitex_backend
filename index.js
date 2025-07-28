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
app.use('/uploads', express.static('/opt/render/project/src/uploads'));

// 7. PASSPORT CONFIGURATION
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

// 8. API ROUTES, etc.
// ... (All your routes: /register, /login, /profile, /admin/*, etc.)

// 9. SERVER STARTUP
async function startServer() {
    try {
        await client.connect();
        logger.info("Successfully connected to MongoDB!");
        usersCollection = client.db("HitexDB").collection("users");
        manuscriptsCollection = client.db("HitexDB").collection("manuscripts");
        
        app.listen(port, () => {
            logger.info(`Server running on port ${port}`);
        });
    } catch (error) {
        logger.error('Failed to start server:', error);
        process.exit(1);
    }
}

startServer();