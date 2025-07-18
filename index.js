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
const JWT_SECRET = process.env.JWT_SECRET || 'a-very-secure-and-long-random-string';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'password';

// Multer Configuration for File Uploads
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

// Main Asynchronous Function to connect to DB and start the server
async function run() {
  try {
    await client.connect();
    console.log("Successfully connected to MongoDB!");

    // Define database and collections
    const database = client.db("HitexDB");
    const usersCollection = database.collection("users");
    const manuscriptsCollection = database.collection("manuscripts");

    // 3. MIDDLEWARE SETUP
    app.use(cors({
        origin: "*",
        methods: "GET,POST,PUT,DELETE,OPTIONS",
        allowedHeaders: "Content-Type,Authorization"
    }));
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    app.use('/uploads', express.static('uploads'));

    // --- Authentication Middlewares ---
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
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        if (token == null) return res.status(401).send({ message: 'Token required.' });

        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err || user.role !== 'admin') {
                return res.status(403).send({ message: "Admin access required." });
            }
            req.user = user;
            next();
        });
    };

    // 4. API ROUTES

    // --- General Route ---
    app.get('/', (req, res) => {
      res.send('Hello, your server is running and connected to MongoDB!');
    });

    // --- User & Editor Authentication Routes ---
    app.post('/register', async (req, res) => {
        try {
            const { fullName, email, password } = req.body;
            if (!fullName || !email || !password) return res.status(400).send({ message: 'All fields are required.' });
            
            const existingUser = await usersCollection.findOne({ email });
            if (existingUser) return res.status(400).send({ message: 'User with this email already exists.' });
            
            const hashedPassword = await bcrypt.hash(password, 10);
            // New users default to the 'author' role. Editors must be assigned manually by an admin.
            const newUser = { fullName, email, password: hashedPassword, role: 'author', createdAt: new Date() };
            const result = await usersCollection.insertOne(newUser);
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
            
            // Create a token that includes the user's role
            const token = jwt.sign({ id: user._id, email: user.email, role: user.role || 'author' }, JWT_SECRET, { expiresIn: '8h' });
            
            // Send back the user's info, including their role
            res.status(200).send({
                message: "Login successful!",
                token: token,
                user: {
                    id: user._id,
                    email: user.email,
                    fullName: user.fullName,
                    role: user.role || 'author' // <-- The crucial role field
                }
            });
        } catch (error) { res.status(500).send({ message: "An error occurred during login." }); }
    });

    // --- Protected User/Editor Routes ---
    app.get('/profile', authenticateToken, async (req, res) => {
        // ... (This route is correct as-is)
    });

    app.post('/profile/update', authenticateToken, async (req, res) => {
        // ... (This route is correct as-is)
    });
    
    app.post('/submit-manuscript', authenticateToken, upload.single('manuscriptFile'), async (req, res) => {
      // ... (This route is correct as-is)
    });

    app.get('/editor/my-jobs', authenticateToken, async (req, res) => {
        // ... (This route is correct as-is)
    });
    
    // --- Admin Routes ---
    app.post('/admin/login', (req, res) => {
        // ... (This route is correct as-is)
    });

    app.get('/admin/dashboard', authenticateAdmin, async (req, res) => {
        // ... (This route is correct as-is)
    });

    app.get('/admin/editors', authenticateAdmin, async (req, res) => {
        // ... (This route is correct as-is)
    });

    app.post('/admin/assign-job/:manuscriptId', authenticateAdmin, async (req, res) => {
        // ... (This route is correct as-is)
    });

    // 5. START THE SERVER (Inside the try block for stability)
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