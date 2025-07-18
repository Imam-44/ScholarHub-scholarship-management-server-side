require('dotenv').config();
const express = require('express');
const cors = require('cors');
const app = express();
const port = process.env.PORT || 5000;
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const Stripe = require('stripe');
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

const corsOptions = {
  origin: ['http://localhost:5173', 'http://localhost:5174', process.env.CLIENT_URL],
  credentials: true,
  optionSuccessStatus: 200,
};
app.use(cors(corsOptions));
app.use(express.json());

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).send({ message: 'Unauthorized access' });
  }
  const token = authHeader.split(' ')[1];
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).send({ message: 'Unauthorized access' });
    }
    req.user = decoded;
    next();
  });
};

// Create MongoDB client
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    const db = client.db('assignment-12-scholarshipDB');
    const usersCollection = db.collection('users');
    const scholarshipCollection = db.collection('scholarship');
    const applicationCollection = db.collection('application');

    const reviewCollection = db.collection('reviews');
    const paymentCollection = db.collection('payment');

    // Create Indexes for performance
    await scholarshipCollection.createIndex({ scholarshipName: 1, universityName: 1, degree: 1 });
    await applicationCollection.createIndex({ userEmail: 1, scholarshipId: 1 });
    await reviewCollection.createIndex({ scholarshipId: 1, reviewerEmail: 1 });

    // JWT route
    app.post('/jwt', async (req, res) => {
      try {
        const email = req.body;
        const token = jwt.sign(email, process.env.ACCESS_TOKEN_SECRET, {
          expiresIn: '365d',
        });
        res.send({ token });
      } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message });
      }
    });

    // JWT logout route (client clears localStorage)
    app.get('/logout', async (req, res) => {
      res.send({ success: true });
    });
    //  user route
    app.post('/users', async (req, res) => {
      try {
        const user = req.body;
        const existing = await usersCollection.findOne({ email: user.email });
        if (existing) return res.send({ message: 'User already exists', inserted: false });

        const newUser = { name: user.name, email: user.email, photoURL: user.photoURL, role: 'user', lastLogin: new Date() };
        const result = await usersCollection.insertOne(newUser);
        res.send({ success: true, inserted: true, result });
      } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message });
      }
    });

    app.get('/users', verifyToken, async (req, res) => {
      try {
        const role = req.query.role;
        const filter = role ? { role } : {};
        const result = await usersCollection.find(filter).toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message });
      }
    });

    app.get('/users/role/:email', async (req, res) => {
      try {
        const user = await usersCollection.findOne({ email: req.params.email });
        res.send({ role: user?.role || 'user' });
      } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message });
      }
    });

    app.patch('/users/:id', verifyToken, async (req, res) => {
      try {
        const result = await usersCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: req.body }
        );
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message });
      }
    });




    // Server test route
    app.get('/', (req, res) => {
      res.send('Scholarship Management System Server is running!');
    });

    await client.db('admin').command({ ping: 1 });
    console.log('Pinged your deployment. You successfully connected to MongoDB!');
  } catch (error) {
    console.error('Failed to connect to MongoDB:', error);
  }
}

run().catch(console.dir);

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});