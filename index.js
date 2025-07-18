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
     
    app.delete('/users/:id', verifyToken, async (req, res) => {
  try {
    const result = await usersCollection.deleteOne({ _id: new ObjectId(req.params.id) });
    if (result.deletedCount === 0) return res.status(404).send({ message: 'User not found' });
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: 'Server error', error: error.message });
  }
});
   
// Create scholarship 
app.post('/new-scholarship', verifyToken, async (req, res) => {
  try {
    const result = await scholarshipCollection.insertOne(req.body);
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: 'Server error', error: error.message });
  }
});

app.get('/scholarship', async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 6;
  const total = await scholarshipCollection.estimatedDocumentCount();
  const scholarships = await scholarshipCollection.find().skip((page-1)*limit).limit(limit).toArray();
  res.send({ total, page, totalPages: Math.ceil(total/limit), scholarships });
});

app.get('/scholarship/all', async (req, res) => {
  res.send(await scholarshipCollection.find().toArray());
});

app.get('/scholarship/:id', async (req, res) => {
  try {
    const scholarship = await scholarshipCollection.findOne({ _id: new ObjectId(req.params.id) });
    if (!scholarship) return res.status(404).send({ message: 'Scholarship not found' });
    res.send(scholarship);
  } catch {
    res.status(500).send({ message: 'Internal Server Error' });
  }
});

app.patch('/scholarship/:id', verifyToken, async (req, res) => {
  delete req.body._id;
  const result = await scholarshipCollection.updateOne(
    { _id: new ObjectId(req.params.id) },
    { $set: req.body }
  );
  res.send(result);
});

app.delete('/scholarship/:id', verifyToken, async (req, res) => {
  const result = await scholarshipCollection.deleteOne({ _id: new ObjectId(req.params.id) });
  if (result.deletedCount === 0) return res.status(404).send({ message: 'Scholarship not found' });
  res.send(result);
});

app.get('/top-scholarship', async (req, res) => {
  const top = await scholarshipCollection
    .find().sort({ applicationFees: 1, postDate: -1 }).limit(6).toArray();
  res.send(top);
});

app.get('/search-scholarship', async (req, res) => {
  const q = req.query.query;
  if (!q) return res.status(400).send({ message: 'Query parameter is required' });
  const result = await scholarshipCollection.find({
    $or: [
      { scholarshipName: { $regex: q, $options: 'i' } },
      { universityName: { $regex: q, $options: 'i' } },
      { degree: { $regex: q, $options: 'i' } }
    ]
  }).toArray();
  res.send(result);
});

app.post('/apply-scholarship', async (req, res) => {
  const { userEmail, scholarshipId } = req.body;
  const exists = await applicationCollection.findOne({
    userEmail,
    scholarshipId: new ObjectId(scholarshipId)
  });
  if (exists) return res.status(409).send({ message: 'Already applied' });
  const result = await applicationCollection.insertOne(req.body);
  res.send(result);
});

app.get('/apply-scholarship/check', async (req, res) => {
  const { email, scholarshipId } = req.query;
  if (!email || !scholarshipId) return res.status(400).send({ message: 'Missing query parameters' });
  const exists = await applicationCollection.findOne({
    userEmail: email,
    scholarshipId: new ObjectId(scholarshipId)
  });
  res.send({ alreadyApplied: !!exists });
});

app.get('/my-applications/:email', verifyToken, async (req, res) => {
  if (req.params.email !== req.user.email) return res.status(403).send({ message: 'Forbidden access' });
  res.send(await applicationCollection.find({ userEmail: req.params.email }).toArray());
});

app.patch('/update-application/:id', verifyToken, async (req, res) => {
  const app = await applicationCollection.findOne({ _id: new ObjectId(req.params.id) });
  if (!app) return res.status(404).send({ message: 'Application not found' });
  if (app.status !== 'pending' || app.userEmail !== req.user.email)
    return res.status(403).send({ message: 'Not allowed' });
  const allowed = (({ address, degree, phone, photo, gender, ssc, hsc, studyGap }) => ({ address, degree, phone, photo, gender, ssc, hsc, studyGap }))(req.body);
  const result = await applicationCollection.updateOne({ _id: new ObjectId(req.params.id) }, { $set: allowed });
  res.send(result);
});

app.delete('/cancel-application/:id', verifyToken, async (req, res) => {
  const result = await applicationCollection.deleteOne({
    _id: new ObjectId(req.params.id),
    userEmail: req.user.email
  });
  if (result.deletedCount === 0) return res.status(404).send({ message: 'Application not found or unauthorized' });
  res.send(result);
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