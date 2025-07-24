// 1. IMPORTS
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const MongoStore = require('connect-mongo');
const Joi = require('joi');
const winston = require('winston');

// 2. LOGGING SETUP
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

// 3. ENVIRONMENT VALIDATION
const requiredEnvVars = [
  'MONGODB_URI',
  'JWT_SECRET',
  'GOOGLE_CLIENT_ID',
  'GOOGLE_CLIENT_SECRET',
  'SESSION_SECRET',
  'ADMIN_USERNAME',
  'ADMIN_PASSWORD'
];

for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    logger.error(`Missing required environment variable: ${envVar}`);
    process.exit(1);
  }
}

// 4. INITIAL SETUP
const app = express();
const port = process.env.PORT || 3000;
const uri = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const NODE_ENV = process.env.NODE_ENV || 'development';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://hitex-editex.vercel.app';
const BACKEND_URL = process.env.BACKEND_URL || 'https://hitex-backend-server.onrender.com';

// 5. VALIDATION SCHEMAS
const schemas = {
  register: Joi.object({
    fullName: Joi.string().min(2).max(100).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(8).max(128).required(),
    role: Joi.string().valid('author', 'editor').default('author')
  }),
  login: Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
  }),
  profileUpdate: Joi.object({
    fullName: Joi.string().min(2).max(100),
    bio: Joi.string().max(500),
    expertise: Joi.array().items(Joi.string().max(50)),
    phone: Joi.string().pattern(/^[+]?[1-9][\d\s\-\(\)]{7,15}$/)
  }),
  manuscriptSubmission: Joi.object({
    title: Joi.string().min(5).max(200).required(),
    abstract: Joi.string().min(50).max(2000).required(),
    keywords: Joi.array().items(Joi.string().max(50)).min(1).max(10).required(),
    category: Joi.string().valid('research', 'review', 'case-study', 'editorial', 'other').required(),
    urgency: Joi.string().valid('low', 'medium', 'high').default('medium'),
    specialInstructions: Joi.string().max(1000)
  }),
  adminLogin: Joi.object({
    username: Joi.string().required(),
    password: Joi.string().required()
  })
};

// 6. RATE LIMITING
const createRateLimiter = (windowMs, max, message) => rateLimit({
  windowMs,
  max,
  message: { error: message },
  standardHeaders: true,
  legacyHeaders: false
});

const authLimiter = createRateLimiter(15 * 60 * 1000, 5, 'Too many authentication attempts');
const generalLimiter = createRateLimiter(15 * 60 * 1000, 100, 'Too many requests');

// 7. FILE UPLOAD CONFIGURATION
const createUploadDir = async () => {
  try {
    await fs.mkdir('uploads', { recursive: true });
    await fs.mkdir('logs', { recursive: true });
  } catch (error) {
    logger.error('Failed to create directories:', error);
  }
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const sanitizedOriginalName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
    cb(null, file.fieldname + '-' + uniqueSuffix + '-' + sanitizedOriginalName);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['.pdf', '.doc', '.docx', '.txt'];
  const fileExt = path.extname(file.originalname).toLowerCase();
  
  if (allowedTypes.includes(fileExt)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only PDF, DOC, DOCX, and TXT files are allowed.'), false);
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
    files: 1
  }
});

// 8. MONGODB CLIENT SETUP
const client = new MongoClient(uri, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
  maxPoolSize: 10,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
});

let database, usersCollection, manuscriptsCollection;

async function connectToDatabase() {
  try {
    await client.connect();
    await client.db("admin").command({ ping: 1 });
    logger.info("Successfully connected to MongoDB!");

    database = client.db("HitexDB");
    usersCollection = database.collection("users");
    manuscriptsCollection = database.collection("manuscripts");

    // Create indexes for better performance
    await usersCollection.createIndex({ email: 1 }, { unique: true });
    await usersCollection.createIndex({ googleId: 1 }, { unique: true, sparse: true });
    await manuscriptsCollection.createIndex({ authorId: 1 });
    await manuscriptsCollection.createIndex({ editorId: 1 });
    await manuscriptsCollection.createIndex({ status: 1 });
    await manuscriptsCollection.createIndex({ createdAt: -1 });

    logger.info("Database indexes created successfully");
  } catch (error) {
    logger.error("Failed to connect to MongoDB:", error);
    process.exit(1);
  }
}

// 9. MIDDLEWARE SETUP
app.use(helmet({
  crossOriginEmbedderPolicy: false,
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

app.use(cors({
  origin: [FRONTEND_URL, 'http://localhost:3000', 'http://localhost:5000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(generalLimiter);
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Session configuration
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    client: client,
    dbName: 'HitexDB',
    collectionName: 'sessions'
  }),
  cookie: {
    secure: NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 8 * 60 * 60 * 1000 // 8 hours
  }
}));

app.use(passport.initialize());
app.use(passport.session());
app.use('/uploads', express.static('uploads'));

// 10. PASSPORT CONFIGURATION
passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: `${BACKEND_URL}/auth/google/callback`
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await usersCollection.findOne({ googleId: profile.id });
      if (user) {
        return done(null, user);
      }
      
      // Check if user exists with same email
      const existingUser = await usersCollection.findOne({ email: profile.emails[0].value });
      if (existingUser) {
        // Link Google account to existing user
        await usersCollection.updateOne(
          { _id: existingUser._id },
          { $set: { googleId: profile.id } }
        );
        const updatedUser = await usersCollection.findOne({ _id: existingUser._id });
        return done(null, updatedUser);
      }

      const newUser = {
        googleId: profile.id,
        fullName: profile.displayName,
        email: profile.emails[0].value,
        role: 'author',
        isEmailVerified: true,
        createdAt: new Date(),
        updatedAt: new Date()
      };
      
      const result = await usersCollection.insertOne(newUser);
      user = await usersCollection.findOne({ _id: result.insertedId });
      logger.info(`New user created via Google OAuth: ${user.email}`);
      return done(null, user);
    } catch (error) {
      logger.error('Google OAuth error:', error);
      return done(error, null);
    }
  }
));

passport.serializeUser((user, done) => done(null, user._id.toString()));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await usersCollection.findOne({ _id: new ObjectId(id) });
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

// 11. AUTHENTICATION MIDDLEWARE
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }
  
  jwt.verify(token, JWT_SECRET, async (err, decoded) => {
    if (err) {
      logger.warn(`Invalid token attempt: ${err.message}`);
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    
    try {
      const user = await usersCollection.findOne({ _id: new ObjectId(decoded.id) });
      if (!user) {
        return res.status(403).json({ error: 'User not found' });
      }
      req.user = user;
      next();
    } catch (error) {
      logger.error('Token authentication error:', error);
      res.status(500).json({ error: 'Authentication error' });
    }
  });
};

const authenticateAdmin = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Admin token required' });
  }
  
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err || decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    req.user = decoded;
    next();
  });
};

const requireRole = (roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return res.status(403).json({ error: 'Insufficient permissions' });
  }
  next();
};

// 12. UTILITY FUNCTIONS
const generateToken = (user) => {
  return jwt.sign(
    { 
      id: user._id, 
      email: user.email, 
      role: user.role,
      fullName: user.fullName
    },
    JWT_SECRET,
    { expiresIn: '8h' }
  );
};

const sanitizeUser = (user) => {
  const { password, ...sanitized } = user;
  return sanitized;
};

// 13. API ROUTES

// Health check
app.get('/', (req, res) => {
  res.json({ 
    message: 'Hitex Backend Server is running',
    timestamp: new Date().toISOString(),
    environment: NODE_ENV
  });
});

// Google Auth Routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: `${FRONTEND_URL}/login.html?error=auth_failed` }),
  (req, res) => {
    try {
      const user = req.user;
      const token = generateToken(user);
      const userJson = encodeURIComponent(JSON.stringify(sanitizeUser(user)));
      res.redirect(`${FRONTEND_URL}/auth-success.html?token=${token}&user=${userJson}`);
    } catch (error) {
      logger.error('Google callback error:', error);
      res.redirect(`${FRONTEND_URL}/login.html?error=callback_failed`);
    }
  }
);

// User Registration
app.post('/register', authLimiter, async (req, res) => {
  try {
    const { error, value } = schemas.register.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { fullName, email, password, role } = value;

    // Check if user already exists
    const existingUser = await usersCollection.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ error: 'User already exists with this email' });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user
    const newUser = {
      fullName,
      email,
      password: hashedPassword,
      role,
      isEmailVerified: false,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const result = await usersCollection.insertOne(newUser);
    const user = await usersCollection.findOne({ _id: result.insertedId });
    
    const token = generateToken(user);
    logger.info(`New user registered: ${email}`);

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: sanitizeUser(user)
    });
  } catch (error) {
    logger.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error during registration' });
  }
});

// User Login
app.post('/login', authLimiter, async (req, res) => {
  try {
    const { error, value } = schemas.login.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { email, password } = value;

    // Find user
    const user = await usersCollection.findOne({ email });
    if (!user || !user.password) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = generateToken(user);
    logger.info(`User logged in: ${email}`);

    res.json({
      message: 'Login successful',
      token,
      user: sanitizeUser(user)
    });
  } catch (error) {
    logger.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error during login' });
  }
});

// Get User Profile
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await usersCollection.findOne({ _id: req.user._id });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ user: sanitizeUser(user) });
  } catch (error) {
    logger.error('Profile fetch error:', error);
    res.status(500).json({ error: 'Error fetching profile' });
  }
});

// Update User Profile
app.post('/profile/update', authenticateToken, async (req, res) => {
  try {
    const { error, value } = schemas.profileUpdate.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const updateData = { ...value, updatedAt: new Date() };
    
    const result = await usersCollection.updateOne(
      { _id: req.user._id },
      { $set: updateData }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const updatedUser = await usersCollection.findOne({ _id: req.user._id });
    logger.info(`Profile updated for user: ${req.user.email}`);

    res.json({
      message: 'Profile updated successfully',
      user: sanitizeUser(updatedUser)
    });
  } catch (error) {
    logger.error('Profile update error:', error);
    res.status(500).json({ error: 'Error updating profile' });
  }
});

// Submit Manuscript
app.post('/submit-manuscript', authenticateToken, requireRole(['author']), upload.single('manuscriptFile'), async (req, res) => {
  try {
    const { error, value } = schemas.manuscriptSubmission.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'Manuscript file is required' });
    }

    const manuscript = {
      ...value,
      authorId: req.user._id,
      authorName: req.user.fullName,
      authorEmail: req.user.email,
      fileName: req.file.filename,
      originalFileName: req.file.originalname,
      fileSize: req.file.size,
      filePath: req.file.path,
      status: 'submitted',
      submissionDate: new Date(),
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const result = await manuscriptsCollection.insertOne(manuscript);
    const savedManuscript = await manuscriptsCollection.findOne({ _id: result.insertedId });

    logger.info(`Manuscript submitted by ${req.user.email}: ${value.title}`);

    res.status(201).json({
      message: 'Manuscript submitted successfully',
      manuscript: savedManuscript
    });
  } catch (error) {
    logger.error('Manuscript submission error:', error);
    // Clean up uploaded file if database operation failed
    if (req.file) {
      fs.unlink(req.file.path).catch(err => logger.error('File cleanup error:', err));
    }
    res.status(500).json({ error: 'Error submitting manuscript' });
  }
});

// Get Author's Manuscripts
app.get('/my-manuscripts', authenticateToken, requireRole(['author']), async (req, res) => {
  try {
    const manuscripts = await manuscriptsCollection
      .find({ authorId: req.user._id })
      .sort({ createdAt: -1 })
      .toArray();

    res.json({ manuscripts });
  } catch (error) {
    logger.error('Fetch manuscripts error:', error);
    res.status(500).json({ error: 'Error fetching manuscripts' });
  }
});

// Get Editor's Assigned Jobs
app.get('/editor/my-jobs', authenticateToken, requireRole(['editor']), async (req, res) => {
  try {
    const jobs = await manuscriptsCollection
      .find({ editorId: req.user._id })
      .sort({ assignedDate: -1 })
      .toArray();

    res.json({ jobs });
  } catch (error) {
    logger.error('Fetch editor jobs error:', error);
    res.status(500).json({ error: 'Error fetching assigned jobs' });
  }
});

// Update Manuscript Status (Editor)
app.post('/editor/update-status/:manuscriptId', authenticateToken, requireRole(['editor']), async (req, res) => {
  try {
    const { manuscriptId } = req.params;
    const { status, comments } = req.body;

    if (!ObjectId.isValid(manuscriptId)) {
      return res.status(400).json({ error: 'Invalid manuscript ID' });
    }

    const allowedStatuses = ['in-progress', 'completed', 'needs-revision'];
    if (!allowedStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const updateData = {
      status,
      updatedAt: new Date()
    };

    if (comments) {
      updateData.editorComments = comments;
    }

    if (status === 'completed') {
      updateData.completedDate = new Date();
    }

    const result = await manuscriptsCollection.updateOne(
      { _id: new ObjectId(manuscriptId), editorId: req.user._id },
      { $set: updateData }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ error: 'Manuscript not found or not assigned to you' });
    }

    const updatedManuscript = await manuscriptsCollection.findOne({ _id: new ObjectId(manuscriptId) });
    logger.info(`Manuscript status updated by ${req.user.email}: ${manuscriptId} -> ${status}`);

    res.json({
      message: 'Manuscript status updated successfully',
      manuscript: updatedManuscript
    });
  } catch (error) {
    logger.error('Status update error:', error);
    res.status(500).json({ error: 'Error updating manuscript status' });
  }
});

// Admin Login
app.post('/admin/login', authLimiter, async (req, res) => {
  try {
    const { error, value } = schemas.adminLogin.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { username, password } = value;

    if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD) {
      return res.status(401).json({ error: 'Invalid admin credentials' });
    }

    const token = jwt.sign(
      { id: 'admin', username, role: 'admin' },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    logger.info('Admin logged in');

    res.json({
      message: 'Admin login successful',
      token,
      user: { username, role: 'admin' }
    });
  } catch (error) {
    logger.error('Admin login error:', error);
    res.status(500).json({ error: 'Internal server error during admin login' });
  }
});

// Admin Dashboard
app.get('/admin/dashboard', authenticateAdmin, async (req, res) => {
  try {
    const totalManuscripts = await manuscriptsCollection.countDocuments();
    const submittedManuscripts = await manuscriptsCollection.countDocuments({ status: 'submitted' });
    const inProgressManuscripts = await manuscriptsCollection.countDocuments({ status: 'in-progress' });
    const completedManuscripts = await manuscriptsCollection.countDocuments({ status: 'completed' });
    
    const totalUsers = await usersCollection.countDocuments();
    const totalAuthors = await usersCollection.countDocuments({ role: 'author' });
    const totalEditors = await usersCollection.countDocuments({ role: 'editor' });

    const recentManuscripts = await manuscriptsCollection
      .find({})
      .sort({ createdAt: -1 })
      .limit(10)
      .toArray();

    res.json({
      stats: {
        totalManuscripts,
        submittedManuscripts,
        inProgressManuscripts,
        completedManuscripts,
        totalUsers,
        totalAuthors,
        totalEditors
      },
      recentManuscripts
    });
  } catch (error) {
    logger.error('Admin dashboard error:', error);
    res.status(500).json({ error: 'Error fetching dashboard data' });
  }
});

// Get All Manuscripts (Admin)
app.get('/admin/manuscripts', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, status, search } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    let filter = {};
    if (status) filter.status = status;
    if (search) {
      filter.$or = [
        { title: { $regex: search, $options: 'i' } },
        { authorName: { $regex: search, $options: 'i' } },
        { authorEmail: { $regex: search, $options: 'i' } }
      ];
    }

    const manuscripts = await manuscriptsCollection
      .find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .toArray();

    const total = await manuscriptsCollection.countDocuments(filter);

    res.json({
      manuscripts,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    logger.error('Admin manuscripts fetch error:', error);
    res.status(500).json({ error: 'Error fetching manuscripts' });
  }
});

// Get All Editors (Admin)
app.get('/admin/editors', authenticateAdmin, async (req, res) => {
  try {
    const editors = await usersCollection
      .find({ role: 'editor' })
      .sort({ fullName: 1 })
      .toArray();

    const editorsWithStats = await Promise.all(editors.map(async (editor) => {
      const assignedJobs = await manuscriptsCollection.countDocuments({ editorId: editor._id });
      const completedJobs = await manuscriptsCollection.countDocuments({ 
        editorId: editor._id, 
        status: 'completed' 
      });
      
      return {
        ...sanitizeUser(editor),
        assignedJobs,
        completedJobs
      };
    }));

    res.json({ editors: editorsWithStats });
  } catch (error) {
    logger.error('Admin editors fetch error:', error);
    res.status(500).json({ error: 'Error fetching editors' });
  }
});

// Assign Manuscript to Editor (Admin)
app.post('/admin/assign-job/:manuscriptId', authenticateAdmin, async (req, res) => {
  try {
    const { manuscriptId } = req.params;
    const { editorId } = req.body;

    if (!ObjectId.isValid(manuscriptId) || !ObjectId.isValid(editorId)) {
      return res.status(400).json({ error: 'Invalid manuscript or editor ID' });
    }

    // Verify editor exists
    const editor = await usersCollection.findOne({ 
      _id: new ObjectId(editorId), 
      role: 'editor' 
    });
    
    if (!editor) {
      return res.status(404).json({ error: 'Editor not found' });
    }

    // Update manuscript
    const result = await manuscriptsCollection.updateOne(
      { _id: new ObjectId(manuscriptId) },
      {
        $set: {
          editorId: new ObjectId(editorId),
          editorName: editor.fullName,
          editorEmail: editor.email,
          status: 'assigned',
          assignedDate: new Date(),
          updatedAt: new Date()
        }
      }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ error: 'Manuscript not found' });
    }

    const updatedManuscript = await manuscriptsCollection.findOne({ _id: new ObjectId(manuscriptId) });
    logger.info(`Manuscript ${manuscriptId} assigned to editor ${editor.email}`);

    res.json({
      message: 'Manuscript assigned successfully',
      manuscript: updatedManuscript
    });
  } catch (error) {
    logger.error('Manuscript assignment error:', error);
    res.status(500).json({ error: 'Error assigning manuscript' });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  logger.error('Unhandled error:', error);
  
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large. Maximum size is 10MB.' });
    }
    return res.status(400).json({ error: 'File upload error: ' + error.message });
  }
  
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use('*', (req,res, next) => {
 res.status(404).json({ error: 'Endpoint not found' });
});

// 14. GRACEFUL SHUTDOWN
const gracefulShutdown = async (signal) => {
 logger.info(`Received ${signal}. Starting graceful shutdown...`);
 
 try {
   // Close MongoDB connection
   await client.close();
   logger.info('MongoDB connection closed');
   
   // Close server
   process.exit(0);
 } catch (error) {
   logger.error('Error during shutdown:', error);
   process.exit(1);
 }
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// 15. SERVER STARTUP
const startServer = async () => {
 try {
   await createUploadDir();
   await connectToDatabase();
   
   app.listen(port, () => {
     logger.info(`Hitex Backend Server running on port ${port}`);
     logger.info(`Environment: ${NODE_ENV}`);
     logger.info(`Frontend URL: ${FRONTEND_URL}`);
     logger.info(`Backend URL: ${BACKEND_URL}`);
   });
 } catch (error) {
   logger.error('Failed to start server:', error);
   process.exit(1);
 }
};

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
 logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
 gracefulShutdown('unhandledRejection');
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
 logger.error('Uncaught Exception:', error);
 gracefulShutdown('uncaughtException');
});

// Start the server
startServer();

module.exports = app;