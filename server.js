require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json({ limit: '3mb' }));
app.use(express.static('public'));

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error(err));

const User = mongoose.model('User', new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
}));

const Listing = mongoose.model('Listing', new mongoose.Schema({
  title: { type: String, required: true },
  price: { type: Number, required: true },
  category: String,
  description: String,
  sold: { type: Boolean, default: false },
  seller: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  sellerName: String,
  sellerEmail: String,
  image: String,
}, { timestamps: true }));

const sign = u => jwt.sign({ id: u._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

function auth(req, res, next) {
  try {
    const t = (req.headers.authorization || '').split(' ')[1];
    req.userId = jwt.verify(t, process.env.JWT_SECRET).id;
    next();
  } catch { res.status(401).json({ error: 'Please log in' }); }
}

app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password || password.length < 6)
      return res.status(400).json({ error: 'Name, email and a 6+ character password are required' });
    const u = await User.create({ name, email, password: await bcrypt.hash(password, 10) });
    res.status(201).json({ token: sign(u), user: { id: u._id, name: u.name } });
  } catch (e) {
    res.status(400).json({ error: e.code === 11000 ? 'Email already registered' : e.message });
  }
});

app.post('/api/login', async (req, res) => {
  const u = await User.findOne({ email: (req.body.email || '').toLowerCase() });
  if (!u || !(await bcrypt.compare(req.body.password || '', u.password)))
    return res.status(400).json({ error: 'Wrong email or password' });
  res.json({ token: sign(u), user: { id: u._id, name: u.name } });
});

app.get('/api/listings', async (req, res) => {
  const q = req.query.q ? { title: new RegExp(req.query.q, 'i') } : {};
  res.json(await Listing.find(q).sort({ createdAt: -1 }));
});

app.post('/api/listings', auth, async (req, res) => {
  try {
    const u = await User.findById(req.userId);
    const { title, price, category, description, image } = req.body;
    res.status(201).json(await Listing.create({
      title, price, category, description, image,
      seller: u._id, sellerName: u.name, sellerEmail: u.email,
    }));
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.patch('/api/listings/:id/sold', auth, async (req, res) => {
  const l = await Listing.findById(req.params.id);
  if (!l || String(l.seller) !== req.userId)
    return res.status(403).json({ error: 'Not your listing' });
  l.sold = true;
  await l.save();
  res.json(l);
});

app.listen(process.env.PORT, () =>
  console.log('Campus Market on port ' + process.env.PORT));
