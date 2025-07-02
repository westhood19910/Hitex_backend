// 1. IMPORTS
const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');

// 2. SETUP
const app = express();
const port = 3000;
const uri = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'a-default-secret-key-that-is-long';

// --- Multer Configuration for File Uploads ---
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
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
    app.use(cors());
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));

    // --- Authentication Middleware ---
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

    // 4. ROUTES
    app.get('/', (req, res) => res.send('Server is live and connected to MongoDB!'));

    app.post('/register', async (req, res) => {
        // Your existing registration code...
    });

    app.post('/login', async (req, res) => {
        // Your existing login code with the lastLogin update...
    });

    // --- MANUSCRIPT SUBMISSION ROUTE ---
    app.post('/submit-manuscript', authenticateToken, upload.single('manuscriptFile'), async (req, res) => {
      try {
        if (!req.file) {
          return res.status(400).send({ message: 'No file was uploaded.' });
        }

        const { wordCount, serviceType, fullName, email, documentType, deadline, message } = req.body;
        const userId = req.user.id; 

        const newManuscript = {
          userId: new ObjectId(userId),
          wordCount,
          serviceType,
          originalName: req.file.originalname,
          fileName: req.file.filename,
          filePath: req.file.path,
          uploadDate: new Date(),
          // Include other form details
          authorName: fullName,
          authorEmail: email,
          docType: documentType,
          requestedDeadline: deadline,
          projectDetails: message
        };

        const result = await manuscriptsCollection.insertOne(newManuscript);
        res.status(201).send({ message: 'Manuscript submitted successfully!', manuscriptId: result.insertedId });

      } catch (error) {
        console.error("Failed to submit manuscript:", error);
        res.status(500).send({ message: 'Error submitting manuscript' });
      }
    });

  } catch (err) {
    console.error("Failed to connect to MongoDB", err);
  }
}
run();

// 5. START SERVER
app.listen(port, () => {
  console.log(`Server is listening at http://localhost:${port}`);
});