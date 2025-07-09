// 1. IMPORTS (All at the top)
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
const uri = process.env.MONGODB_URI; // Your secret URI from Render's environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'a-default-secret-key-that-is-long-and-random'; // Use an environment variable for this too

// --- Multer Configuration for File Uploads ---
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/'); // The 'uploads' folder on your server
  },
  filename: function (req, file, cb) {
    // Create a unique filename to avoid overwriting files
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});
const upload = multer({ storage: storage });

// --- MongoDB Client Setup ---
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

// --- Main Asynchronous Function ---
// We define our routes inside this function after the database connection is established.
async function run() {
  try {
    // Connect the client to the MongoDB server
    await client.connect();
    console.log("Successfully connected to MongoDB!");

    // Define database and collections
    const database = client.db("HitexDB");
    const usersCollection = database.collection("users");
    const manuscriptsCollection = database.collection("manuscripts");

    // 3. MIDDLEWARE SETUP
    app.use(cors());
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    // This makes the 'uploads' folder public so files can be accessed
    app.use('/uploads', express.static('uploads'));

    // --- Authentication Middleware ---
    // This function checks for a valid JWT on protected routes
    const authenticateToken = (req, res, next) => {
      const authHeader = req.headers['authorization'];
      const token = authHeader && authHeader.split(' ')[1]; // Format is "Bearer TOKEN"

      if (token == null) {
        return res.status(401).send({ message: 'Authentication token is required.' });
      }

      jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
          return res.status(403).send({ message: 'Token is invalid or has expired.' });
        }
        req.user = user; // Add the decoded user payload to the request object
        next(); // Proceed to the route handler
      });
    };

    // 4. API ROUTES

    // --- Default Route ---
    app.get('/', (req, res) => {
      res.send('Hello, your server is running and connected to MongoDB!');
    });

    // --- Registration Route ---
    app.post('/register', async (req, res) => {
      try {
        const { fullName, email, password, manuscriptType } = req.body;
        const existingUser = await usersCollection.findOne({ email: email });
        if (existingUser) {
          return res.status(400).send({ message: 'User with this email already exists.' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
          fullName, email, password: hashedPassword, manuscriptType, createdAt: new Date()
        };
        const result = await usersCollection.insertOne(newUser);
        res.status(201).send({ message: 'User registered successfully!', userId: result.insertedId });
      } catch (error) {
        console.error("Registration Error:", error);
        res.status(500).send({ message: 'Error registering user' });
      }
    });

    // --- Login Route (with Debugging) ---
    app.post('/login', async (req, res) => {
      console.log("--- New Login Attempt Started ---");
      try {
        const { email, password } = req.body;
        console.log(`Step 1: Received login for email: ${email}`);

        console.log("Step 2: Finding user in database...");
        const user = await usersCollection.findOne({ email: email });
        if (!user) {
          console.log("Step 2 FAILED: User not found in database.");
          return res.status(404).send({ message: "User not found." });
        }
        console.log("Step 2 SUCCESS: User found.");

        console.log("Step 3: Comparing passwords...");
        const isPasswordCorrect = await bcrypt.compare(password, user.password);
        if (!isPasswordCorrect) {
          console.log("Step 3 FAILED: Passwords do not match.");
          return res.status(400).send({ message: "Invalid password." });
        }
        console.log("Step 3 SUCCESS: Password is correct.");

        console.log("Step 4: Updating lastLogin timestamp...");
        await usersCollection.updateOne({ _id: user._id }, { $set: { lastLogin: new Date() } });
        console.log("Step 4 SUCCESS: lastLogin timestamp updated.");

        console.log("Step 5: Creating login token (JWT)...");
        const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
        console.log("Step 5 SUCCESS: Token created.");

        console.log("--- Login attempt successful! Sending response. ---");
        res.status(200).send({
          message: "Login successful!",
          token: token,
          user: { id: user._id, email: user.email, fullName: user.fullName }
        });

      } catch (error) {
        console.error("--- LOGIN ROUTE CRASHED WITH AN ERROR ---", error);
        res.status(500).send({ message: "An error occurred on the server during login." });
      }
    });

    // --- Manuscript Submission Route (Protected) ---
    app.post('/submit-manuscript', authenticateToken, upload.single('manuscriptFile'), async (req, res) => {
      try {
        if (!req.file) {
          return res.status(400).send({ message: 'No file was uploaded.' });
        }
        const { wordCount, serviceType } = req.body;
        const userId = req.user.id; // Get user ID from the authenticated token
        const newManuscript = {
          userId: new ObjectId(userId),
          wordCount, serviceType,
          originalName: req.file.originalname,
          fileName: req.file.filename,
          filePath: req.file.path,
          uploadDate: new Date()
        };
        const result = await manuscriptsCollection.insertOne(newManuscript);
        res.status(201).send({ message: 'Manuscript submitted successfully!', manuscriptId: result.insertedId });
      } catch (error) {
        console.error("Failed to submit manuscript:", error);
        res.status(500).send({ message: 'Error submitting manuscript' });
      }
    });

  } catch (err) {
    console.error("FATAL: Failed to connect to MongoDB. Server is not starting.", err);
    process.exit(1); // Exit the process if DB connection fails
  }
}

// Call the main function to connect to the DB and set up routes
run();

// 5. START THE SERVER (This should be last)
app.listen(port, () => {
  console.log(`Server is listening at http://localhost:${port}`);
});