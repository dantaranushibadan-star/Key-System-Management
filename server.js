const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/key_system', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Schemas
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user' }, // admin, user
});

const KeySchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true },
  owner: { type: String, required: true },
  created_at: { type: Date, default: Date.now },
  expires_at: { type: Date, required: true },
  status: { type: String, default: 'active' }, // active, paused, revoked
  hwid: { type: String, default: '' }, // Hardware ID binding
  last_login: { type: Date },
  total_logins: { type: Number, default: 0 },
});

const User = mongoose.model('User', UserSchema);
const Key = mongoose.model('Key', KeySchema);

// Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Routes

// User registration
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();

    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// User login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user._id, username: user.username, role: user.role },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    res.json({ token, user: { username: user.username, role: user.role } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Key validation (for your Lua app)
app.post('/api/validate-key', async (req, res) => {
  try {
    const { key, hwid } = req.body;
    
    const keyData = await Key.findOne({ key });
    if (!keyData) {
      return res.json({ valid: false, message: 'Invalid key' });
    }

    if (keyData.status === 'revoked') {
      return res.json({ valid: false, message: 'Key has been revoked' });
    }

    if (keyData.status === 'paused') {
      return res.json({ valid: false, message: 'Key is currently paused' });
    }

    if (new Date() > keyData.expires_at) {
      return res.json({ valid: false, message: 'Key has expired' });
    }

    // HWID binding
    if (keyData.hwid && keyData.hwid !== hwid) {
      return res.json({ valid: false, message: 'Key is bound to another device' });
    }

    // If no HWID is set, bind it
    if (!keyData.hwid && hwid) {
      keyData.hwid = hwid;
    }

    keyData.last_login = new Date();
    keyData.total_logins += 1;
    await keyData.save();

    const daysLeft = Math.ceil((keyData.expires_at - new Date()) / (1000 * 60 * 60 * 24));
    
    res.json({
      valid: true,
      message: 'Key is valid',
      days_left: daysLeft,
      expires_at: keyData.expires_at,
      status: keyData.status
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin routes

// Create new key
app.post('/api/keys', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { owner, days } = req.body;
    
    const key = generateKey();
    const expires_at = new Date();
    expires_at.setDate(expires_at.getDate() + parseInt(days));

    const keyData = new Key({
      key,
      owner,
      expires_at,
    });

    await keyData.save();
    res.status(201).json({ message: 'Key created', key });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get all keys
app.get('/api/keys', authenticateToken, isAdmin, async (req, res) => {
  try {
    const keys = await Key.find().sort({ created_at: -1 });
    res.json(keys);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update key status
app.patch('/api/keys/:keyId', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    const key = await Key.findById(req.params.keyId);
    
    if (!key) {
      return res.status(404).json({ error: 'Key not found' });
    }

    key.status = status;
    await key.save();

    res.json({ message: 'Key updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete key
app.delete('/api/keys/:keyId', authenticateToken, isAdmin, async (req, res) => {
  try {
    await Key.findByIdAndDelete(req.params.keyId);
    res.json({ message: 'Key deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Extend key expiry
app.patch('/api/keys/:keyId/extend', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { days } = req.body;
    const key = await Key.findById(req.params.keyId);
    
    if (!key) {
      return res.status(404).json({ error: 'Key not found' });
    }

    const newExpiry = new Date(key.expires_at);
    newExpiry.setDate(newExpiry.getDate() + parseInt(days));
    key.expires_at = newExpiry;
    await key.save();

    res.json({ message: 'Key extended successfully', new_expiry: key.expires_at });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Helper function to generate random keys
function generateKey() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  for (let i = 0; i < 16; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
    if ((i + 1) % 4 === 0 && i !== 15) result += '-';
  }
  return result;
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});