// 1. IMPORTS
const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');

// 2. INITIAL SETUP
const app = express();
const port = 3000;
const uri = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'a-default-secret-key-that-is-long-and-random';

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
    // Connect the client to the MongoDB server
    await client.connect();
    console.log("Successfully connected to MongoDB!");

    const database = client.db("HitexDB");
    const usersCollection = database.collection("users");
    const manuscriptsCollection = database.collection("manuscripts");

    // 3. MIDDLEWARE SETUP
    app.use(cors());
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    app.use('/uploads', express.static('uploads'));

    // Authentication Middleware
    const authenticateToken = (req, res, next) => {
      const authHeader = req.headers['authorization'];
      const token = authHeader && authHeader.split(' ')[1];
      if (token == null) return res.sendStatus(401);
      jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
      });
    };

    // Admin-only Authentication Middleware
    const authenticateAdmin = (req, res, next) => {
      const authHeader = req.headers['authorization'];
      const token = authHeader && authHeader.split(' ')[1];
      if (token == null) return res.sendStatus(401);
      jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err || user.role !== 'admin') {
          return res.status(403).send({ message: "Admin access required." });
        }
        req.user = user;
        next();
      });
    };


    // 4. API ROUTES
    
    // --- Default Route ---
    app.get('/', (req, res) => {
      res.send('Hello, your server is running and connected to MongoDB!');
    });

    // ... All your other routes (/register, /login, /submit-manuscript, /admin/login, /admin/dashboard) go here ...
    // They are correct as they were in the previous complete file.
    app.post('/register', async (req, res) => { /* ... */ });
    app.post('/login', async (req, res) => { /* ... */ });
    app.post('/admin/login', (req, res) => { /* ... */ });
    app.get('/admin/dashboard', authenticateAdmin, async (req, res) => { /* ... */ });
    app.post('/submit-manuscript', authenticateToken, upload.single('manuscriptFile'), async (req, res) => { /* ... */ });
    

    // 5. START THE SERVER (MOVED INSIDE THE `try` BLOCK)
    app.listen(port, () => {
        console.log(`Server is listening at http://localhost:${port}`);
    });

  } catch (err) {
    console.error("FATAL: Failed to connect to MongoDB. Server is not starting.", err);
    process.exit(1);
  }
}

// Call the main function to start everything
run();