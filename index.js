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

    //user add
    app.post('/users', async (req, res) => {
      try {
        const user = req.body;

        // check if user already exists
        const existing = await usersCollection.findOne({ email: user.email });
        if (existing) {
          return res.send({ message: 'User already exists', inserted: false });
        }

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


    // Users Routes
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
        const email = req.params.email;
        const user = await usersCollection.findOne({ email });
        res.send({ role: user?.role || 'user' });
      } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message });
      }
    });

    app.patch('/users/:id', verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const updatedRole = req.body;
        const result = await usersCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updatedRole }
        );
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message });
      }
    });

    app.delete('/users/:id', verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const result = await usersCollection.deleteOne({ _id: new ObjectId(id) });
        if (result.deletedCount === 0) {
          return res.status(404).send({ message: 'User not found' });
        }
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message });
      }
    });

    // Scholarship Routes
    app.post('/new-scholarship', verifyToken, async (req, res) => {
      try {
        const newScholarship = req.body;
        const result = await scholarshipCollection.insertOne(newScholarship);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message });
      }
    });

    // Paginated version for public listing
    app.get('/scholarship', async (req, res) => {
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 6;
      const skip = (page - 1) * limit;

      const total = await scholarshipCollection.estimatedDocumentCount();
      const scholarships = await scholarshipCollection
        .find()
        .skip(skip)
        .limit(limit)
        .toArray();

      res.send({
        total,
        page,
        totalPages: Math.ceil(total / limit),
        scholarships,
      });
    });

    // Full list version for admin panel
    app.get('/scholarship/all', async (req, res) => {
      const scholarships = await scholarshipCollection.find().toArray();
      res.send(scholarships); 
    });


    app.get('/scholarship/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await scholarshipCollection.findOne(query);

        if (!result) {
          return res.status(404).send({ message: 'Scholarship not found' });
        }

        res.send(result);
      } catch (err) {
        res.status(500).send({ message: 'Internal Server Error' });
      }
    });


    app.delete('/scholarship/:id', verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const result = await scholarshipCollection.deleteOne({ _id: new ObjectId(id) });
        if (result.deletedCount === 0) {
          return res.status(404).send({ message: 'Scholarship not found' });
        }
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message });
      }
    });



    app.patch('/scholarship/:id', verifyToken, async (req, res) => {
      const id = req.params.id;
      const updateData = req.body;


      delete updateData._id;

      try {
        const result = await scholarshipCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateData }
        );

        res.send(result);
      } catch (error) {
        console.error('Update failed:', error);
        res.status(500).send({ message: 'Update failed', error: error.message });
      }
    });



    app.get('/top-scholarship', async (req, res) => {
      try {
        const result = await scholarshipCollection
          .find()
          .sort({ applicationFees: 1, postDate: -1 })
          .limit(6)
          .toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message });
      }
    });

    app.get('/search-scholarship', async (req, res) => {
      try {
        const query = req.query.query;
        if (!query) {
          return res.status(400).send({ message: 'Query parameter is required' });
        }
        const search = {
          $or: [
            { scholarshipName: { $regex: query, $options: 'i' } },
            { universityName: { $regex: query, $options: 'i' } },
            { degree: { $regex: query, $options: 'i' } },
          ],
        };
        const result = await scholarshipCollection.find(search).toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message });
      }
    });

 
    app.post("/apply-scholarship", async (req, res) => {
      try {
        const application = req.body;
        const { userEmail, scholarshipId } = application;

        const existing = await applicationCollection.findOne({
          userEmail,
          scholarshipId: new ObjectId(scholarshipId),
        });
        if (existing) {
          return res.status(409).send({ message: "Already applied" });
        }

        const result = await applicationCollection.insertOne(application);
        res.send(result);
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Server error" });
      }
    });
    // Check if user already applied
    app.get("/apply-scholarship/check", async (req, res) => {
      try {
        const { email, scholarshipId } = req.query;
        if (!email || !scholarshipId) {
          return res.status(400).send({ message: "Missing query parameters" });
        }

        const existing = await applicationCollection.findOne({
          userEmail: email,
          scholarshipId: new ObjectId(scholarshipId),
        });

        res.send({ alreadyApplied: !!existing });
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Server error" });
      }
    });



    app.get('/my-applications/:email', verifyToken, async (req, res) => {
      try {
        const email = req.params.email;
        if (email !== req.user.email) {
          return res.status(403).send({ message: 'Forbidden access' });
        }
        const result = await applicationCollection.find({ userEmail: email }).toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message });
      }
    });

    app.patch('/update-application/:id', verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const updatedData = req.body;

        const application = await applicationCollection.findOne({ _id: new ObjectId(id) });
        if (!application) {
          return res.status(404).send({ message: 'Application not found' });
        }

        if (application.status !== 'pending') {
          return res.status(403).send({ message: 'Cannot edit application in this status' });
        }

        if (application.userEmail !== req.user.email) {
          return res.status(403).send({ message: 'Unauthorized access' });
        }


        const allowedFields = {
          address: updatedData.address,
          degree: updatedData.degree,
          phone: updatedData.phone,
          photo: updatedData.photo,
          gender: updatedData.gender,
          ssc: updatedData.ssc,
          hsc: updatedData.hsc,
          studyGap: updatedData.studyGap
        };

        const result = await applicationCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: allowedFields }
        );

        res.send(result);
      } catch (error) {
        console.error('Update Error:', error.message);
        res.status(500).send({ message: 'Server error', error: error.message });
      }
    });


    app.delete('/cancel-application/:id', verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const result = await applicationCollection.deleteOne({
          _id: new ObjectId(id),
          userEmail: req.user.email,
        });
        if (result.deletedCount === 0) {
          return res.status(404).send({ message: 'Application not found or unauthorized' });
        }
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message });
      }
    });

    app.get('/all-applications', verifyToken, async (req, res) => {
      try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;
        const sortBy = req.query.sortBy || 'applicationDate';
        const sortOrder = req.query.sortOrder === 'desc' ? -1 : 1;
        const filter = req.query.deadline
          ? { applicationDeadline: { $gte: new Date(req.query.deadline) } }
          : {};
        const result = await applicationCollection
          .find(filter)
          .sort({ [sortBy]: sortOrder })
          .skip(skip)
          .limit(limit)
          .toArray();
        const total = await applicationCollection.countDocuments(filter);
        res.send({ applications: result, total, page, limit });
      } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message });
      }
    });

    app.patch('/application-status/:id', verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const { status } = req.body;
        const result = await applicationCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status } }
        );
        if (result.matchedCount === 0) {
          return res.status(404).send({ message: 'Application not found' });
        }
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message });
      }
    });

    app.patch('/application-feedback/:id', verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const { feedback } = req.body;
        const result = await applicationCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { feedback } }
        );
        if (result.matchedCount === 0) {
          return res.status(404).send({ message: 'Application not found' });
        }
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message });
      }
    });

    // Get single application by ID
    app.get('/applications/:id', verifyToken, async (req, res) => {
      const id = req.params.id;

      try {
        const application = await applicationCollection.findOne({ _id: new ObjectId(id) });

        if (!application) {
          return res.status(404).send({ error: 'Application not found' });
        }

        res.send(application);
      } catch (error) {
        console.error('Error fetching application:', error);
        res.status(500).send({ error: 'Internal Server Error' });
      }
    });

    // Patch route: Update an application by ID
    app.patch('/applications/:id', verifyToken, async (req, res) => {
      const id = req.params.id;
      const updatedData = req.body;

      try {
        const result = await applicationCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updatedData }
        );
        res.send(result);
      } catch (err) {
        console.error('Update failed:', err);
        res.status(500).send({ error: 'Update failed' });
      }
    });



    // Review Routes
    app.post('/reviews', verifyToken, async (req, res) => {
      try {
        console.log('Review data received:', req.body);
        const reviewData = req.body;
        reviewData.reviewerEmail = req.user.email;
        reviewData.date = new Date();

      
        reviewData.scholarshipId = reviewData.scholarshipId || reviewData.scholarshipIdFromClient;

        const result = await reviewCollection.insertOne(reviewData);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message });
      }
    });


    //get review

    // Example: GET /reviews?scholarshipId=12345
    app.get('/reviews', async (req, res) => {
      const { scholarshipId } = req.query;

      try {
        const query = scholarshipId ? { scholarshipId } : {};
        const reviews = await reviewCollection.find(query).toArray();
        res.send(reviews);
      } catch (error) {
        console.error('Failed to fetch reviews:', error);
        res.status(500).send({ error: 'Failed to get reviews' });
      }
    });



    app.get('/reviews/:scholarshipId', async (req, res) => {
      try {
        const scholarshipId = req.params.scholarshipId;
        const result = await reviewCollection.find({ scholarshipId }).toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message });
      }
    });

    // GET all reviews by a user
    app.get('/my-reviews/:email', verifyToken, async (req, res) => {
      try {
        const email = req.params.email;

       
        if (req.user.email !== email) {
          return res.status(403).send({ message: 'Unauthorized access' });
        }

        const reviews = await reviewCollection.find({ reviewerEmail: email }).toArray();
        res.send(reviews);
      } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message });
      }
    });

    app.patch('/reviews/:id', verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const updatedReview = req.body;

        const result = await reviewCollection.updateOne(
          { _id: new ObjectId(id), reviewerEmail: req.user.email },
          { $set: updatedReview }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ message: 'Review not found or unauthorized' });
        }

        res.send(result);
      } catch (error) {
        console.error('Review update error:', error);
        res.status(500).send({ message: 'Server error', error: error.message });
      }
    });

    app.delete('/reviews/:id', verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const result = await reviewCollection.deleteOne({
          _id: new ObjectId(id),
          reviewerEmail: req.user.email,
        });
        if (result.deletedCount === 0) {
          return res.status(404).send({ message: 'Review not found or unauthorized' });
        }
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message });
      }
    });

    app.delete('/reviews/admin/:id', verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const result = await reviewCollection.deleteOne({ _id: new ObjectId(id) });
        if (result.deletedCount === 0) {
          return res.status(404).send({ message: 'Review not found' });
        }
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message });
      }
    });

    // Payment Routes
    app.post('/create-payment-intent', async (req, res) => {
      const { amount } = req.body;
      const paymentIntent = await stripe.paymentIntents.create({
        amount: parseInt(amount * 100),
        currency: 'usd',
        payment_method_types: ['card'],
      });
      res.send({ clientSecret: paymentIntent.client_secret });
    });


    app.post('/payment-success', verifyToken, async (req, res) => {
      try {
        const paymentInfo = req.body;
        paymentInfo.userEmail = req.user.email;
        const result = await paymentCollection.insertOne(paymentInfo);
        res.send({ success: true, result });
      } catch (error) {
        res.status(500).send({ message: 'Server error', error: error.message });
      }
    });

    // Analytics Route
    app.get('/analytics', verifyToken,  async (req, res) => {
      try {
        const scholarshipByCategory = await scholarshipCollection
          .aggregate([
            { $group: { _id: '$scholarshipCategory', count: { $sum: 1 } } },
          ])
          .toArray();
        const applicationByStatus = await applicationCollection
          .aggregate([
            { $group: { _id: '$status', count: { $sum: 1 } } },
          ])
          .toArray();
        const applicationByDate = await applicationCollection
          .aggregate([
            {
              $group: {
                _id: { $dateToString: { format: '%Y-%m-%d', date: '$applicationDate' } },
                count: { $sum: 1 },
              },
            },
            { $sort: { _id: 1 } },
          ])
          .toArray();
        res.send({ scholarshipByCategory, applicationByStatus, applicationByDate });
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