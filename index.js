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
  cookie: { secure: true, httpOnly: true, sameSite: 'none' }
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

        // ... (all your other routes like /login, /register, etc. would go here) ...

        app.listen(port, () => {
            console.log(`Server running on port ${port}`);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

startServer();