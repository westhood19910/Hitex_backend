// 1. IMPORTS
const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion } = require('mongodb');
const bcrypt = require('bcryptjs'); // <-- Add this for password hashing
const jwt = require('jsonwebtoken'); // <-- Add this for login tokens

// 2. SETUP
const app = express();
const port = 3000;
const uri = process.env.MONGODB_URI; // Your secret URI from Render's environment variables

// A secret key for signing JWTs. In a real app, this should also be an environment variable.
const JWT_SECRET = 'a-secret-key-for-jwt-that-should-be-long-and-random';

const client = new MongoClient(uri, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true }
});

async function run() {
  try {
    await client.connect();
    console.log("Successfully connected to MongoDB!");

    const database = client.db("HitexDB");
    const usersCollection = database.collection("users");

    // 3. MIDDLEWARE
    app.use(cors());
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));

    // 4. ROUTES
    app.get('/', (req, res) => {
      res.send('Hello, your server is running and connected to MongoDB!');
    });

    // --- UPDATED REGISTRATION ROUTE ---
    app.post('/register', async (req, res) => {
      try {
        const { fullName, email, password, manuscriptType } = req.body;

        const existingUser = await usersCollection.findOne({ email: email });
        if (existingUser) {
          return res.status(400).send({ message: 'User with this email already exists.' });
        }

        // Hash the password before storing it
        const hashedPassword = await bcrypt.hash(password, 10); // 10 is the salt rounds

        const newUser = {
          fullName,
          email,
          password: hashedPassword, // <-- Store the hashed password
          manuscriptType,
          createdAt: new Date()
        };

        const result = await usersCollection.insertOne(newUser);
        res.status(201).send({ message: 'User registered successfully!', userId: result.insertedId });
      } catch (error) {
        res.status(500).send({ message: 'Error registering user' });
      }
    });

    // --- NEW LOGIN ROUTE ---
    app.post('/login', async (req, res) => {
      try {
        const { email, password } = req.body;

        // 1. Find the user by their email
        const user = await usersCollection.findOne({ email: email });
        if (!user) {
          return res.status(404).send({ message: "User not found." });
        }

        // 2. Compare the submitted password with the stored hashed password
        const isPasswordCorrect = await bcrypt.compare(password, user.password);
        if (!isPasswordCorrect) {
          return res.status(400).send({ message: "Invalid password." });
        }
              await usersCollection.updateOne(
           { _id: user._id }, // Filter to find the correct user
           { $set: { lastLogin: new Date() } } // The update to apply
                 );
        // 3. If password is correct, create a JSON Web Token (JWT)
        const token = jwt.sign(
          { id: user._id, email: user.email }, // Payload: data to include in the token
          JWT_SECRET,                          // The secret key
          { expiresIn: '1h' }                  // Token expiration time
        );

        // 4. Send the token back to the front-end
        res.status(200).send({
          message: "Login successful!",
          token: token,
          user: {
            id: user._id,
            email: user.email,
            fullName: user.fullName
          }
        });

      } catch (error) {
        res.status(500).send({ message: "An error occurred during login." });
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