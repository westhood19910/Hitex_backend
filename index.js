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
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'password';

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

// Main Asynchronous Function
async function run() {
  try {
    await client.connect();
    console.log("Successfully connected to MongoDB!");

    const database = client.db("HitexDB");
    const usersCollection = database.collection("users");
    const manuscriptsCollection = database.collection("manuscripts");

    // 3. MIDDLEWARE SETUP
    console.log("Setting up middleware with explicit CORS options...");
    app.use(cors({
      origin: "*",
      methods: "GET,POST,PUT,DELETE,OPTIONS",
      allowedHeaders: "Content-Type,Authorization"
    }));
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    app.use('/uploads', express.static('uploads'));
    console.log("Middleware setup complete.");

    // Authentication Middlewares
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
    app.get('/', (req, res) => {
      res.send('Hello, your server is running and connected to MongoDB!');
    });

    app.post('/register', async (req, res) => {
      try {
        const { fullName, email, password, manuscriptType } = req.body;
        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) return res.status(400).send({ message: 'User with this email already exists.' });
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await usersCollection.insertOne({ fullName, email, password: hashedPassword, manuscriptType, createdAt: new Date() });
        res.status(201).send({ message: 'User registered successfully!', userId: result.insertedId });
      } catch (error) { res.status(500).send({ message: 'Error registering user' }); }
    });

    app.post('/login', async (req, res) => {
      try {
        const { email, password } = req.body;
        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).send({ message: "User not found." });
        const isPasswordCorrect = await bcrypt.compare(password, user.password);
        if (!isPasswordCorrect) return res.status(400).send({ message: "Invalid password." });
        await usersCollection.updateOne({ _id: user._id }, { $set: { lastLogin: new Date() } });
        const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
        res.status(200).send({ message: "Login successful!", token, user: { id: user._id, email: user.email, fullName: user.fullName } });
      } catch (error) { res.status(500).send({ message: "An error occurred during login." }); }
    });

    app.post('/submit-manuscript', authenticateToken, upload.single('manuscriptFile'), async (req, res) => {
      try {
        if (!req.file) return res.status(400).send({ message: 'No file was uploaded.' });
        const { wordCount, serviceType } = req.body;
        const result = await manuscriptsCollection.insertOne({ userId: new ObjectId(req.user.id), wordCount, serviceType, originalName: req.file.originalname, fileName: req.file.filename, filePath: req.file.path, uploadDate: new Date() });
        res.status(201).send({ message: 'Manuscript submitted successfully!', manuscriptId: result.insertedId });
      } catch (error) { res.status(500).send({ message: 'Error submitting manuscript' }); }
    });

    app.post('/admin/login', (req, res) => {
      const { username, password } = req.body;
      if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        const token = jwt.sign({ username: username, role: 'admin' }, JWT_SECRET, { expiresIn: '1h' });
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

    // 5. START THE SERVER
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