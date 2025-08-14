require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const Stripe = require('stripe');

const app = express();
const port = process.env.PORT || 5000;
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// CORS Setup
const allowedOrigins =
  [
    'https://assignment-12-scholarhub.web.app',
    'https://assignment-12-scholarhub.firebaseapp.com',
    'https://scholarhub-scholarship-project.vercel.app', // ✅ Vercel Frontend URL যোগ করুন
    'http://localhost:5173' // ✅ Local React Dev Server
  ];


app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  }
}));
app.use(express.json());

// JWT Middleware
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).send({ message: 'Unauthorized access' });
  }

  const token = authHeader.split(' ')[1];
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) return res.status(401).send({ message: 'Unauthorized access' });
    req.user = decoded;
    next();
  });
};

// MongoDB Connection
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// Main async function
async function run() {
  try {
    await client.connect();
    const db = client.db('assignment-12-scholarshipDB');
    const usersCollection = db.collection('users');
    const scholarshipCollection = db.collection('scholarship');
    const applicationCollection = db.collection('application');
    const reviewCollection = db.collection('reviews');
    const paymentCollection = db.collection('payment');

    // Indexes for performance
    await scholarshipCollection.createIndex({ scholarshipName: 1, universityName: 1, degree: 1 });
    await applicationCollection.createIndex({ userEmail: 1, scholarshipId: 1 });
    await reviewCollection.createIndex({ scholarshipId: 1, reviewerEmail: 1 });

    // =====================
    // JWT ROUTES (Updated)
    // =====================

    // Generate access + refresh token
    app.post('/jwt', async (req, res) => {
      try {
        const { email } = req.body;
        if (!email) return res.status(400).send({ message: 'Email required' });

        const accessToken = jwt.sign({ email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
        const refreshToken = jwt.sign({ email }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });

        res.send({ accessToken, refreshToken });
      } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message });
      }
    });

    // Refresh token route
    app.post('/refresh-token', async (req, res) => {
      const { refreshToken } = req.body;
      if (!refreshToken) return res.status(401).send({ message: 'No refresh token provided' });

      try {
        const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        const email = decoded.email;

        const newAccessToken = jwt.sign({ email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
        res.send({ accessToken: newAccessToken });
      } catch (err) {
        res.status(403).send({ message: 'Invalid refresh token' });
      }
    });

    app.get('/logout', async (req, res) => {
      res.send({ success: true });
    });

    // -------------------------------
    // USER ROUTES
    // -------------------------------
    app.post('/users', async (req, res) => {
      try {
        const user = req.body;
        const existing = await usersCollection.findOne({ email: user.email });
        if (existing) return res.send({ message: 'User already exists', inserted: false });

        const newUser = {
          name: user.name,
          email: user.email,
          photoURL: user.photoURL,
          role: 'user',
          lastLogin: new Date(),
        };

        const result = await usersCollection.insertOne(newUser);
        res.send({ success: true, inserted: true, result });
      } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message });
      }
    });

    app.get('/users', verifyToken, async (req, res) => {
      const role = req.query.role;
      const filter = role ? { role } : {};
      const result = await usersCollection.find(filter).toArray();
      res.send(result);
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
      const result = await usersCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: req.body }
      );
      res.send(result);
    });

    app.delete('/users/:id', verifyToken, async (req, res) => {
      const result = await usersCollection.deleteOne({ _id: new ObjectId(req.params.id) });
      if (result.deletedCount === 0) return res.status(404).send({ message: 'User not found' });
      res.send(result);
    });

    // -------------------------------
    // SCHOLARSHIP ROUTES
    // -------------------------------
    app.post('/new-scholarship', verifyToken, async (req, res) => {
      const result = await scholarshipCollection.insertOne(req.body);
      res.send(result);
    });

    app.get('/scholarship', async (req, res) => {
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 6;
      const skip = (page - 1) * limit;

      const total = await scholarshipCollection.estimatedDocumentCount();
      const scholarships = await scholarshipCollection.find().skip(skip).limit(limit).toArray();

      res.send({ total, page, totalPages: Math.ceil(total / limit), scholarships });
    });

    app.get('/scholarship/all', async (req, res) => {
      const scholarships = await scholarshipCollection.find().toArray();
      res.send(scholarships);
    });

    app.get('/scholarship/:id', async (req, res) => {
      const result = await scholarshipCollection.findOne({ _id: new ObjectId(req.params.id) });
      if (!result) return res.status(404).send({ message: 'Scholarship not found' });
      res.send(result);
    });

    app.patch('/scholarship/:id', verifyToken, async (req, res) => {
      const updateData = req.body;
      delete updateData._id;
      const result = await scholarshipCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: updateData }
      );
      res.send(result);
    });

    app.delete('/scholarship/:id', verifyToken, async (req, res) => {
      const result = await scholarshipCollection.deleteOne({ _id: new ObjectId(req.params.id) });
      if (result.deletedCount === 0) return res.status(404).send({ message: 'Scholarship not found' });
      res.send(result);
    });

    app.get('/top-scholarship', async (req, res) => {
      const result = await scholarshipCollection
        .find()
        .sort({ applicationFees: 1, postDate: -1 })
        .limit(6)
        .toArray();
      res.send(result);
    });

    app.get('/search-scholarship', async (req, res) => {
      const query = req.query.query;
      if (!query) return res.status(400).send({ message: 'Query parameter is required' });

      const search = {
        $or: [
          { scholarshipName: { $regex: query, $options: 'i' } },
          { universityName: { $regex: query, $options: 'i' } },
          { degree: { $regex: query, $options: 'i' } },
        ],
      };
      const result = await scholarshipCollection.find(search).toArray();
      res.send(result);
    });

    // -------------------------------
    // APPLICATION ROUTES
    // -------------------------------
    app.post('/apply-scholarship', async (req, res) => {
      const { userEmail, scholarshipId } = req.body;

      const existing = await applicationCollection.findOne({
        userEmail,
        scholarshipId: new ObjectId(scholarshipId),
      });

      if (existing) return res.status(409).send({ message: 'Already applied' });

      const result = await applicationCollection.insertOne(req.body);
      res.send(result);
    });

    app.get('/apply-scholarship/check', async (req, res) => {
      const { email, scholarshipId } = req.query;
      const existing = await applicationCollection.findOne({
        userEmail: email,
        scholarshipId,
      });
      res.send({ alreadyApplied: !!existing });
    });

    app.get('/my-applications/:email', verifyToken, async (req, res) => {
      if (req.params.email !== req.user.email) return res.status(403).send({ message: 'Forbidden' });
      const result = await applicationCollection.find({ userEmail: req.params.email }).toArray();
      res.send(result);
    });

    app.patch('/update-application/:id', verifyToken, async (req, res) => {
      const application = await applicationCollection.findOne({ _id: new ObjectId(req.params.id) });

      if (!application || application.status !== 'pending' || application.userEmail !== req.user.email) {
        return res.status(403).send({ message: 'Unauthorized or cannot edit' });
      }

      const allowedFields = (({ address, degree, phone, photo, gender, ssc, hsc, studyGap }) => ({
        address, degree, phone, photo, gender, ssc, hsc, studyGap
      }))(req.body);

      const result = await applicationCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: allowedFields }
      );
      res.send(result);
    });

    app.delete('/cancel-application/:id', verifyToken, async (req, res) => {
      const result = await applicationCollection.deleteOne({
        _id: new ObjectId(req.params.id),
        userEmail: req.user.email,
      });
      if (result.deletedCount === 0) return res.status(404).send({ message: 'Not found or unauthorized' });
      res.send(result);
    });

    app.get('/all-applications', verifyToken, async (req, res) => {
      const { page, limit, sortBy = 'applicationDate', sortOrder = 'asc', deadline } = req.query;
      const filter = deadline ? { applicationDeadline: { $gte: new Date(deadline) } } : {};
      const sort = { [sortBy]: sortOrder === 'desc' ? -1 : 1 };
      const cursor = applicationCollection.find(filter).sort(sort);

      const paged = !isNaN(limit) && !isNaN(page) && limit > 0 && page > 0;
      const data = paged
        ? await cursor.skip((page - 1) * limit).limit(parseInt(limit)).toArray()
        : await cursor.toArray();

      const total = await applicationCollection.countDocuments(filter);
      res.send({ applications: data, total, page: parseInt(page) || 1, limit: parseInt(limit) || total });
    });

    app.get('/applications/:id', verifyToken, async (req, res) => {
      const application = await applicationCollection.findOne({ _id: new ObjectId(req.params.id) });
      if (!application) return res.status(404).send({ error: 'Application not found' });
      res.send(application);
    });

    app.patch('/applications/:id', verifyToken, async (req, res) => {
      const result = await applicationCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: req.body }
      );
      res.send(result);
    });

    app.patch('/application-status/:id', verifyToken, async (req, res) => {
      const result = await applicationCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: { status: req.body.status } }
      );
      res.send(result);
    });

    app.patch('/application-feedback/:id', verifyToken, async (req, res) => {
      const result = await applicationCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: { feedback: req.body.feedback } }
      );
      res.send(result);
    });

    // -------------------------------
    // REVIEW ROUTES
    // -------------------------------
    app.post('/reviews', verifyToken, async (req, res) => {
      const reviewData = {
        ...req.body,
        reviewerEmail: req.user.email,
        date: new Date(),
      };
      const result = await reviewCollection.insertOne(reviewData);
      res.send(result);
    });

    app.get('/reviews', async (req, res) => {
      const reviews = await reviewCollection.find(req.query.scholarshipId ? { scholarshipId: req.query.scholarshipId } : {}).toArray();
      res.send(reviews);
    });

    app.get('/reviews/:scholarshipId', async (req, res) => {
      const result = await reviewCollection.find({ scholarshipId: req.params.scholarshipId }).toArray();
      res.send(result);
    });

    app.get('/my-reviews/:email', verifyToken, async (req, res) => {
      if (req.params.email !== req.user.email) return res.status(403).send({ message: 'Unauthorized' });
      const reviews = await reviewCollection.find({ reviewerEmail: req.params.email }).toArray();
      res.send(reviews);
    });

    app.patch('/reviews/:id', verifyToken, async (req, res) => {
      const result = await reviewCollection.updateOne(
        { _id: new ObjectId(req.params.id), reviewerEmail: req.user.email },
        { $set: req.body }
      );
      if (result.matchedCount === 0) return res.status(404).send({ message: 'Not found or unauthorized' });
      res.send(result);
    });

    app.delete('/reviews/:id', verifyToken, async (req, res) => {
      const result = await reviewCollection.deleteOne({
        _id: new ObjectId(req.params.id),
        reviewerEmail: req.user.email,
      });
      if (result.deletedCount === 0) return res.status(404).send({ message: 'Not found or unauthorized' });
      res.send(result);
    });

    app.delete('/reviews/admin/:id', verifyToken, async (req, res) => {
      const result = await reviewCollection.deleteOne({ _id: new ObjectId(req.params.id) });
      res.send(result);
    });

    app.get('/reviews/average/:id', async (req, res) => {
      const reviews = await reviewCollection.find({ scholarshipId: req.params.id }).toArray();
      const average = reviews.reduce((sum, r) => sum + Number(r.rating), 0) / (reviews.length || 1);
      res.send({ average });
    });

    // -------------------------------
    // PAYMENT ROUTES
    // -------------------------------
    app.post('/create-payment-intent', async (req, res) => {
      const paymentIntent = await stripe.paymentIntents.create({
        amount: parseInt(req.body.amount * 100),
        currency: 'usd',
        payment_method_types: ['card'],
      });
      res.send({ clientSecret: paymentIntent.client_secret });
    });

    app.post('/payment-success', verifyToken, async (req, res) => {
      const paymentInfo = { ...req.body, userEmail: req.user.email };
      const result = await paymentCollection.insertOne(paymentInfo);
      res.send({ success: true, result });
    });

    // -------------------------------
    // ANALYTICS ROUTE
    // -------------------------------
    app.get('/analytics', verifyToken, async (req, res) => {
      try {
        const scholarshipByCategory = await scholarshipCollection.aggregate([
          { $group: { _id: '$scholarshipCategory', count: { $sum: 1 } } },
        ]).toArray();

        const applicationByStatus = await applicationCollection.aggregate([
          { $group: { _id: '$status', count: { $sum: 1 } } },
        ]).toArray();

        const applicationByDate = await applicationCollection.aggregate([
          {
            $group: {
              _id: { $dateToString: { format: '%Y-%m-%d', date: '$applicationDate' } },
              count: { $sum: 1 },
            },
          },
          { $sort: { _id: 1 } },
        ]).toArray();

        res.send({ scholarshipByCategory, applicationByStatus, applicationByDate });
      } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message });
      }
    });

  } catch (error) {
    console.error('MongoDB connection failed:', error);
  }
}
run().catch(console.dir);

// Root Test Route
app.get('/', (req, res) => {
  res.send('Server is running');
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
