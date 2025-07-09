// 1. IMPORTS
const express = require('express');
const cors = require('cors'); // We will use cors
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');

// 2. SETUP
const app = express();
const port = 3000;
const uri = process.env.MONGODB_URI;
const JWT_SECRET = 'a-secret-key-for-jwt-that-should-be-long-and-random';

// ... multer config ...
const storage = multer.diskStorage({
  destination: function (req, file, cb) { cb(null, 'uploads/'); },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});
const upload = multer({ storage: storage });

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
    app.use(cors()); // Use CORS
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    app.use('/uploads', express.static('uploads'));

    // ... your authenticateToken middleware ...
    const authenticateToken = (req, res, next) => { /* ... same as before ... */ };

    // 4. ROUTES

    // === NEW, SIMPLE TEST ROUTE ===
    app.post('/test-route', (req, res) => {
      console.log("'/test-route' was successfully hit!");
      res.status(200).send({ message: "Test successful! The server is reachable." });
    });

    // ... all your other routes (/register, /login, /submit-manuscript) remain here ...
    app.get('/', (req, res) => { res.send('Hello, your server is running and connected to MongoDB!'); });
    app.post('/register', async (req, res) => { /* ... same as before ... */ });
    app.post('/login', async (req, res) => { /* ... same as before ... */ });
    app.post('/submit-manuscript', authenticateToken, upload.single('manuscriptFile'), async (req, res) => { /* ... same as before ... */ });

  } catch (err) { console.error("Failed to connect to MongoDB", err); }
}
run().catch(console.dir);

// 5. START SERVER
app.listen(port, () => {
  console.log(`Server is listening at http://localhost:${port}`);
});