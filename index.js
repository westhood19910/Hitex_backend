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

    const database = client.db("HitexDB");
    const usersCollection = database.collection("users");
    const manuscriptsCollection = database.collection("manuscripts");

    // 3. MIDDLEWARE SETUP
    // This explicit CORS setup handles complex, authenticated requests.
    app.options('*', cors()); // Enable pre-flight for all routes
    app.use(cors()); // Use CORS for all other requests
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
            
            const token = jwt.sign({ id: user._id, email: user.email, role: user.role || 'author' }, JWT_SECRET, { expiresIn: '8h' });
            
            res.status(200).send({
                message: "Login successful!",
                token: token,
                user: {
                    id: user._id,
                    email: user.email,
                    fullName: user.fullName,
                    role: user.role || 'author'
                }
            });
        } catch (error) { res.status(500).send({ message: "An error occurred during login." }); }
    });

    // --- Protected User/Editor Routes ---
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
        const manuscriptData = {
            userId: new ObjectId(req.user.id),
            status: 'New', wordCount, serviceType, deadline,
            originalName: req.file.originalname,
            fileName: req.file.filename,
            filePath: req.file.path,
            uploadDate: new Date()
        };
        const result = await manuscriptsCollection.insertOne(manuscriptData);
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
    
    // --- Admin Routes ---
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
            if (!ObjectId.isValid(manuscriptId) || !ObjectId.isValid(editorId)) {
                return res.status(400).send({ message: "Invalid Manuscript or Editor ID." });
            }
            const updateFields = { assignedEditorId: new ObjectId(editorId), status: 'Assigned', jobCode, jobType, serviceType, editableWords, effectiveEditableWords, targetJournal, languageRequirements, assignmentStartDate: new Date(assignmentStartDate), assignmentReturnDate: new Date(assignmentReturnDate) };
            const result = await manuscriptsCollection.updateOne({ _id: new ObjectId(manuscriptId) }, { $set: updateFields });
            if (result.matchedCount === 0) return res.status(404).send({ message: "Manuscript not found." });
            res.status(200).send({ message: `Job assigned successfully to editor ${editorId}` });
        } catch (error) { res.status(500).send({ message: "Error assigning job." }); }
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