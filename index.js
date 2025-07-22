// 1. IMPORTS
const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');

// 2. INITIAL SETUP
const app = express();
const port = 3000;
const uri = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET || 'a-default-session-secret';

// Multer Config
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});
const upload = multer({ storage: storage });

// MongoDB Client Setup
const client = new MongoClient(uri, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true }
});

async function run() {
  try {
    await client.connect();
    console.log("Successfully connected to MongoDB!");

    const database = client.db("HitexDB");
    const usersCollection = database.collection("users");
    const manuscriptsCollection = database.collection("manuscripts");

    // 3. MIDDLEWARE
    app.use(cors());
    app.use(express.json());
    
    // --- SESSION & PASSPORT MIDDLEWARE ---
    app.use(session({ secret: SESSION_SECRET, resave: false, saveUninitialized: true, cookie: { secure: 'auto' } }));
    app.use(passport.initialize());
    app.use(passport.session());

    app.use(express.urlencoded({ extended: true }));
    app.use('/uploads', express.static('uploads'));

    // --- PASSPORT.JS CONFIGURATION ---
    passport.use(new GoogleStrategy({
        clientID: GOOGLE_CLIENT_ID,
        clientSecret: GOOGLE_CLIENT_SECRET,
        callbackURL: "https://hitex-backend-server.onrender.com/auth/google/callback"
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          let user = await usersCollection.findOne({ googleId: profile.id });
          if (user) {
            return done(null, user);
          } else {
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
          }
        } catch (error) {
          return done(error, null);
        }
      }
    ));
    passport.serializeUser((user, done) => { done(null, user._id); });
    passport.deserializeUser(async (id, done) => {
        const user = await usersCollection.findOne({ _id: new ObjectId(id) });
        done(null, user);
    });
    
    // --- Your Existing Authentication Middlewares ---
    const authenticateToken = (req, res, next) => {
      // ... (your existing code is correct)
    };
    const authenticateAdmin = (req, res, next) => {
      // ... (your existing code is correct)
    };

    // 4. API ROUTES

    // --- GOOGLE AUTHENTICATION ROUTES ---
    app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

    app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: 'https://hitex-editex.vercel.app/login.html' }),
        (req, res) => {
            const user = req.user;
            const token = jwt.sign({ id: user._id, email: user.email, role: user.role || 'author' }, JWT_SECRET, { expiresIn: '8h' });
            const userJson = encodeURIComponent(JSON.stringify({ id: user._id, email: user.email, fullName: user.displayName, role: user.role }));
            res.redirect(`https://hitex-editex.vercel.app/auth-success.html?token=${token}&user=${userJson}`);
        }
    );
    
    // --- ALL YOUR OTHER EXISTING ROUTES ---
    app.get('/', (req, res) => {
      res.send('Hello, your server is running and connected to MongoDB!');
    });

    app.post('/register', async (req, res) => {
        try {
            const { fullName, email, password } = req.body;
            const existingUser = await usersCollection.findOne({ email });
            if (existingUser) return res.status(400).send({ message: 'User with this email already exists.' });
            const hashedPassword = await bcrypt.hash(password, 10);
            const result = await usersCollection.insertOne({ fullName, email, password: hashedPassword, role: 'author', createdAt: new Date() });
            res.status(201).send({ message: 'User registered successfully!', userId: result.insertedId });
        } catch (error) { res.status(500).send({ message: 'Error registering user' }); }
    });

    app.post('/login', async (req, res) => {
        try {
            const { email, password } = req.body;
            const user = await usersCollection.findOne({ email });
            if (!user) return res.status(404).send({ message: "User not found." });
            const isPasswordCorrect = await bcrypt.compare(password, user.password);
            if (!isPasswordCorrect) return res.status(400).send({ message: "Invalid credentials." });
            await usersCollection.updateOne({ _id: user._id }, { $set: { lastLogin: new Date() } });
            const token = jwt.sign({ id: user._id, email: user.email, role: user.role || 'author' }, JWT_SECRET, { expiresIn: '8h' });
            res.status(200).send({ message: "Login successful!", token, user: { id: user._id, email: user.email, fullName: user.fullName, role: user.role || 'author' } });
        } catch (error) { res.status(500).send({ message: "An error occurred during login." }); }
    });

    app.get('/profile', authenticateToken, async (req, res) => {
        try {
            const userProfile = await usersCollection.findOne({ _id: new ObjectId(req.user.id) }, { projection: { password: 0 } });
            if (!userProfile) return res.status(404).send({ message: 'User profile not found.' });
            res.status(200).json(userProfile);
        } catch (error) { res.status(500).send({ message: 'Error fetching user profile.' }); }
    });

    app.post('/profile/update', authenticateToken, async (req, res) => {
        try {
            const { fullName, jobTitle, institution } = req.body;
            const result = await usersCollection.updateOne({ _id: new ObjectId(req.user.id) }, { $set: { fullName, jobTitle, institution } });
            if (result.matchedCount === 0) return res.status(404).send({ message: 'User not found.' });
            res.status(200).send({ message: 'Profile updated successfully!' });
        } catch (error) { res.status(500).send({ message: 'Error updating profile.' }); }
    });
    
    app.post('/submit-manuscript', authenticateToken, upload.single('manuscriptFile'), async (req, res) => {
      try {
        if (!req.file) return res.status(400).send({ message: 'No file was uploaded.' });
        const { wordCount, serviceType, deadline } = req.body;
        const result = await manuscriptsCollection.insertOne({ userId: new ObjectId(req.user.id), status: 'New', wordCount, serviceType, deadline, originalName: req.file.originalname, fileName: req.file.filename, filePath: req.file.path, uploadDate: new Date() });
        res.status(201).send({ message: 'Manuscript submitted successfully!', manuscriptId: result.insertedId });
      } catch (error) { res.status(500).send({ message: 'Error submitting manuscript.' }); }
    });

    app.get('/editor/my-jobs', authenticateToken, async (req, res) => {
        try {
            const editorId = new ObjectId(req.user.id);
            const assignedJobs = await manuscriptsCollection.find({ assignedEditorId: editorId }).sort({ uploadDate: -1 }).toArray();
            res.status(200).json(assignedJobs);
        } catch (error) { res.status(500).send({ message: "Error fetching assigned jobs." }); }
    });
    
    app.post('/admin/login', (req, res) => {
      const { username, password } = req.body;
      if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        const token = jwt.sign({ username, role: 'admin' }, JWT_SECRET, { expiresIn: '8h' });
        res.status(200).send({ message: "Admin login successful!", token });
      } else {
        res.status(401).send({ message: "Invalid admin credentials." });
      }
    });

    app.get('/admin/dashboard', authenticateAdmin, async (req, res) => {
      try {
        const manuscripts = await manuscriptsCollection.find({}).sort({ uploadDate: -1 }).toArray();
        res.status(200).json(manuscripts);
      } catch (error) { res.status(500).send({ message: "Failed to fetch manuscripts." }); }
    });

    app.get('/admin/editors', authenticateAdmin, async (req, res) => {
        try {
            const editors = await usersCollection.find({ role: 'editor' }, { projection: { fullName: 1, _id: 1 } }).toArray();
            res.status(200).json(editors);
        } catch (error) { res.status(500).send({ message: "Failed to fetch editors." }); }
    });

    app.post('/admin/assign-job/:manuscriptId', authenticateAdmin, async (req, res) => {
        try {
            const { manuscriptId } = req.params;
            const { editorId, jobCode, jobType, serviceType, editableWords, effectiveEditableWords, targetJournal, languageRequirements, assignmentStartDate, assignmentReturnDate } = req.body;
            const updateFields = { assignedEditorId: new ObjectId(editorId), status: 'Assigned', jobCode, jobType, serviceType, editableWords, effectiveEditableWords, targetJournal, languageRequirements, assignmentStartDate: new Date(assignmentStartDate), assignmentReturnDate: new Date(assignmentReturnDate) };
            const result = await manuscriptsCollection.updateOne({ _id: new ObjectId(manuscriptId) }, { $set: updateFields });
            if (result.matchedCount === 0) return res.status(404).send({ message: "Manuscript not found." });
            res.status(200).send({ message: `Job assigned successfully to editor ${editorId}` });
        } catch (error) { res.status(500).send({ message: "Error assigning job." }); }
    });

    // 5. START SERVER
    app.listen(port, () => {
        console.log(`Server is listening at http://localhost:${port}`);
    });

  } catch (err) {
    console.error("FATAL: Failed to connect to MongoDB. Server is not starting.", err);
    process.exit(1);
  }
}
run();