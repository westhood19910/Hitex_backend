// 1. IMPORTS (All at the top)
const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion } = require('mongodb');

// 2. SETUP
const app = express();
const port = 3000;

// !! IMPORTANT: The @ in your password has been replaced with %40
const uri = "mongodb+srv://Hitex-DB:Coconuttt%4019910@cluster0.ezrt0al.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";

// Create a new MongoClient
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

// This function will connect to the DB and set up the routes
async function run() {
  try {
    // Connect the client to the server
    await client.connect();
    console.log("Successfully connected to MongoDB!");

    // Define the database and collection
    const database = client.db("HitexDB"); // You can name your database anything
    const usersCollection = database.collection("users"); // Collection to store user data

    // 3. MIDDLEWARE
    app.use(cors());
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));

    // 4. ROUTES

    app.get('/', (req, res) => {
      res.send('Hello, your server is running and connected to MongoDB!');
    });

    // The route that now SAVES data to the database
    app.post('/register', async (req, res) => { // <-- Note this is now an async function
      try {
        const userData = req.body;
        console.log('Received registration data:', userData);

        // Check if user already exists
        const existingUser = await usersCollection.findOne({ email: userData.email });
        if (existingUser) {
          return res.status(400).send({ message: 'User with this email already exists.' });
        }

        // Insert the new user data into the 'users' collection
        const result = await usersCollection.insertOne(userData);
        console.log(`A document was inserted with the _id: ${result.insertedId}`);

        // Send a success response
        res.status(201).send({ message: 'User registered successfully!', userId: result.insertedId });

      } catch (error) {
        console.error("Failed to register user:", error);
        res.status(500).send({ message: 'Error registering user' });
      }
    });

  } catch (err) {
    console.error("Failed to connect to MongoDB", err);
  }
}

// Call the run function to start the connection and set up routes
run();

// 5. START SERVER (This should be last)
app.listen(port, () => {
  console.log(`Server is listening at http://localhost:${port}`);
});