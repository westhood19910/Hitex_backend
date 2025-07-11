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

// Admin credentials from environment variables for security
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'password';


// ... (Multer Config and MongoDB Client Setup remain the same) ...
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});
const upload = multer({ storage: storage });
const client = new MongoClient(uri, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true }
});


// --- Main Asynchronous Function ---
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
    app.use(express.urlencoded({ extended: true }));
    app.use('/uploads', express.static('uploads'));

    // --- Authentication Middlewares ---
    const authenticateToken = (req, res, next) => { /* ... same as before ... */ };

    // === NEW: Admin-only Authentication Middleware ===
    const authenticateAdmin = (req, res, next) => {
      const authHeader = req.headers['authorization'];
      const token = authHeader && authHeader.split(' ')[1];
      if (token == null) return res.sendStatus(401);

      jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err || user.role !== 'admin') { // <-- Check for admin role
          return res.status(403).send({ message: "Admin access required." });
        }
        req.user = user;
        next();
      });
    };

    // 4. API ROUTES

    // ... (Default, Register, and Login routes remain the same) ...
    app.get('/', (req, res) => { /* ... */ });
    app.post('/register', async (req, res) => { /* ... */ });
    app.post('/login', async (req, res) => { /* ... */ });
    app.post('/submit-manuscript', authenticateToken, upload.single('manuscriptFile'), async (req, res) => { /* ... */ });


    // === NEW: ADMIN ROUTES ===

    // --- Admin Login Route ---
    app.post('/admin/login', (req, res) => {
      const { username, password } = req.body;
      if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        // Credentials are correct, issue an admin token
        const token = jwt.sign(
          { username: username, role: 'admin' }, // The payload now includes a role
          JWT_SECRET,
          { expiresIn: '1h' }
        );
        res.status(200).send({ message: "Admin login successful!", token: token });
      } else {
        res.status(401).send({ message: "Invalid admin credentials." });
      }
    });

    // --- Admin Dashboard Data Route (Protected) ---
    app.get('/admin/dashboard', authenticateAdmin, async (req, res) => {
      try {
        // Fetch all manuscripts and sort by most recent
        const manuscripts = await manuscriptsCollection.find({}).sort({ uploadDate: -1 }).toArray();
        res.status(200).json(manuscripts);
      } catch (error) {
        res.status(500).send({ message: "Failed to fetch manuscripts." });
      }
    });


  } catch (err) { /* ... */ }
}
run();

// 5. START SERVER
app.listen(port, () => { /* ... */ });