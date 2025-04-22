require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const OpenAI = require('openai');
const cors = require('cors');
const sanitizeHtml = require('sanitize-html');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());

// Log invalid routes
const originalGet = app.get;
app.get = function (path, ...args) {
  try {
    return originalGet.call(this, path, ...args);
  } catch (err) {
    console.error(`Invalid GET route: ${path}`, err);
    throw err;
  }
};
const originalPost = app.post;
app.post = function (path, ...args) {
  try {
    return originalPost.call(this, path, ...args);
  } catch (err) {
    console.error(`Invalid POST route: ${path}`, err);
    throw err;
  }
};
const originalPut = app.put;
app.put = function (path, ...args) {
  try {
    return originalPut.call(this, path, ...args);
  } catch (err) {
    console.error(`Invalid PUT route: ${path}`, err);
    throw err;
  }
};

// Updated CORS configuration
app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://mindsproutapp.com',
    'https://www.mindsproutapp.com',
    'https://mindsprout-frontend-c2qvqb1og-jays-projects-da2f8026.vercel.app'
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Rate limiter for most /api/regular/* routes
const regularLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again after 15 minutes'
});

// Rate limiter for /api/regular/daily-affirmations (more lenient)
const affirmationsLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // Allow 200 requests per windowMs
  message: 'Too many affirmation requests from this IP, please try again after 15 minutes'
});

// Apply rate limiters
app.use('/api/regular', regularLimiter);
app.use('/api/regular/daily-affirmations', affirmationsLimiter);

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, lowercase: true },
  username: { type: String, unique: true },
  password: String,
  role: { type: String, default: 'regular' },
  goals: [{ goal: String, createdAt: Date }],
  reports: [{
    date: Date,
    quizData: [{ happiness: Number, anger: Number, stress: Number, energy: Number, confidence: Number, isPostChat: Boolean }],
    summary: {
      discussed: String,
      thoughtsFeelings: String,
      insights: String,
      moodReflection: String,
      recommendations: String
    }
  }],
  lastChatTimestamp: Date,
  chatTokens: { type: Number, default: 3 },
  lastTokenRegen: Date,
  journal: [{
    date: Date,
    type: String,
    responses: Object
  }],
  journalInsights: [{
    journalDate: Date,
    insight: String,
    createdAt: Date
  }],
  dailyAffirmations: [{
    suggest: String,
    encourage: String,
    invite: String,
    createdAt: Date,
    validUntil: Date
  }]
});

const User = mongoose.model('User', userSchema);

// OpenAI setup
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    console.log('No token provided in request');
    return res.status(401).json({ error: 'No token provided' });
  }
  try {
    console.log('Verifying token:', token);
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    console.error('Token verification error:', err.message);
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Health check endpoint
app.get('/health', (req, res) => {
  console.log('Health check requested');
  res.json({ status: 'OK', mongodb: mongoose.connection.readyState });
});

// Signup endpoint
app.post('/api/regular/signup', async (req, res) => {
  const { name, email, username, password } = req.body;
  console.log('Signup attempt:', { email, username });
  try {
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      console.log('Signup failed: User already exists');
      return res.status(400).json({ error: 'Email or username already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, username, password: hashedPassword });
    await user.save();
    const token = jwt.sign({ id: user._id, role: 'regular' }, process.env.JWT_SECRET);
    console.log('Signup successful for:', email);
    res.json({ token, message: 'Signup successful', name: user.name });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Signup failed: ' + error.message });
  }
});

// Login endpoint
app.post('/api/regular/login', async (req, res) => {
  const { email, password } = req.body;
  console.log('Login attempt for:', email);
  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      console.log('Login failed: User not found for email:', email);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    console.log('User found, validating password');
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      console.log('Login failed: Invalid password for email:', email);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user._id, role: 'regular' }, process.env.JWT_SECRET);
    console.log('Login successful for:', email);
    res.json({ token, name: user.name });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed: ' + error.message });
  }
});

// Goals endpoints
app.get('/api/regular/goals', verifyToken, async (req, res) => {
  console.log('Fetching goals for user:', req.user.id);
  try {
    const user = await User.findById(req.user.id);
    res.json(user.goals);
  } catch (error) {
    console.error('Error fetching goals:', error);
    res.status(500).json({ error: 'Failed to fetch goals' });
  }
});

app.post('/api/regular/goals', verifyToken, async (req, res) => {
  console.log('Adding goal for user:', req.user.id);
  try {
    const { goal } = req.body;
    const user = await User.findById(req.user.id);
    user.goals.push({ goal, createdAt: new Date() });
    await user.save();
    res.json(user.goals);
  } catch (error) {
    console.error('Error adding goal:', error);
    res.status(500).json({ error: 'Failed to add goal' });
  }
});

// Reports endpoints
app.get('/api/regular/reports', verifyToken, async (req, res) => {
  console.log('Fetching reports for user:', req.user.id);
  try {
    const user = await User.findById(req.user.id);
    res.json(user.reports);
  } catch (error) {
    console.error('Error fetching reports:', error);
    res.status(500).json({ error: 'Failed to fetch reports' });
  }
});

app.delete('/api/regular/reports/:id', verifyToken, async (req, res) => {
  console.log('Deleting report:', req.params.id, 'for user:', req.user.id);
  try {
    const user = await User.findById(req.user.id);
    user.reports = user.reports.filter((report) => report._id.toString() !== req.params.id);
    await user.save();
    res.json({ message: 'Report deleted' });
  } catch (error) {
    console.error('Error deleting report:', error);
    res.status(500).json({ error: 'Failed to delete report' });
  }
});

// Chat endpoints
app.get('/api/regular/last-chat', verifyToken, async (req, res) => {
  console.log('Fetching last chat info for user:', req.user.id);
  try {
    const user = await User.findById(req.user.id);
    res.json({
      lastChatTimestamp: user.lastChatTimestamp,
      chatTokens: user.chatTokens,
      lastTokenRegen: user.lastTokenRegen
    });
  } catch (error) {
    console.error('Error fetching last chat:', error);
    res.status(500).json({ error: 'Failed to fetch last chat' });
  }
});

app.post('/api/regular/chat', verifyToken, async (req, res) => {
  console.log('Processing chat for user:', req.user.id);
  try {
    const { message, chatHistory } = req.body;
    const user = await User.findById(req.user.id);
    if (user.chatTokens <= 0) {
      console.log('Chat failed: No tokens available for user:', req.user.id);
      return res.status(403).json({ error: 'No chat tokens available' });
    }

    const prompt = `You are Pal, a friendly and empathetic AI companion. Your role is to provide supportive and conversational responses. The user's message is: "${message}". The chat history is: ${JSON.stringify(chatHistory)}. Respond in a warm, understanding tone, keeping the response under 500 characters. If the user mentions harmful thoughts, gently suggest seeking professional help or contacting a helpline (e.g., Samaritans at 116 123 in the UK or 988 in the US).`;

    const completion = await openai.chat.completions.create({
      model: 'gpt-3.5-turbo',
      messages: [{ role: 'system', content: prompt }, { role: 'user', content: message }],
      max_tokens: 150
    });

    const responseText = completion.choices[0].message.content.trim();
    res.json({ text: responseText, timestamp: new Date() });
  } catch (error) {
    console.error('Error processing chat:', error);
    res.status(500).json({ error: 'Failed to process chat' });
  }
});

app.post('/api/regular/end-chat', verifyToken, async (req, res) => {
  console.log('Ending chat for user:', req.user.id);
  try {
    const { chatHistory, quiz } = req.body;
    const user = await User.findById(req.user.id);

    const prompt = `You are a summarizer for a mental health chat session. Based on the chat history: ${JSON.stringify(chatHistory)} and quiz data: ${JSON.stringify(quiz)}, provide a concise summary with the following sections: 
    - What We Discussed (100-150 words)
    - Your Thoughts & Feelings (100-150 words)
    - Insights Uncovered (100-150 words)
    - Mood Reflection (100-150 words)
    - Recommendations (100-150 words)`;

    const completion = await openai.chat.completions.create({
      model: 'gpt-3.5-turbo',
      messages: [{ role: 'system', content: prompt }],
      max_tokens: 1000
    });

    const summaryText = completion.choices[0].message.content;
    const summarySections = {
      discussed: summaryText.match(/What We Discussed\s*([\s\S]*?)(?=(Your Thoughts & Feelings|Insights Uncovered|Mood Reflection|Recommendations|$))/i)?.[1].trim() || 'No discussion summary available.',
      thoughtsFeelings: summaryText.match(/Your Thoughts & Feelings\s*([\s\S]*?)(?=(Insights Uncovered|Mood Reflection|Recommendations|$))/i)?.[1].trim() || 'No thoughts and feelings summary available.',
      insights: summaryText.match(/Insights Uncovered\s*([\s\S]*?)(?=(Mood Reflection|Recommendations|$))/i)?.[1].trim() || 'No insights available.',
      moodReflection: summaryText.match(/Mood Reflection\s*([\s\S]*?)(?=(Recommendations|$))/i)?.[1].trim() || 'No mood reflection available.',
      recommendations: summaryText.match(/Recommendations\s*([\s\S]*?)$/i)?.[1].trim() || 'No recommendations available.'
    };

    user.reports.push({
      date: new Date(),
      quizData: [quiz],
      summary: summarySections
    });

    user.lastChatTimestamp = new Date();
    user.chatTokens = Math.max(user.chatTokens - 1, 0);
    user.lastTokenRegen = user.lastTokenRegen || new Date();
    await user.save();

    res.json({
      _id: user.reports[user.reports.length - 1]._id,
      date: user.reports[user.reports.length - 1].date,
      quizData: [quiz],
      summary: summarySections
    });
  } catch (error) {
    console.error('Error ending chat:', error);
    res.status(500).json({ error: 'Failed to end chat' });
  }
});

// Journal endpoints
app.get('/api/regular/journal', verifyToken, async (req, res) => {
  console.log('Fetching journal for user:', req.user.id);
  try {
    const user = await User.findById(req.user.id);
    res.json(user.journal);
  } catch (error) {
    console.error('Error fetching journal:', error);
    res.status(500).json({ error: 'Failed to fetch journal' });
  }
});

app.post('/api/regular/insights', verifyToken, async (req, res) => {
  console.log('Saving journal for user:', req.user.id);
  try {
    const { date, type, responses } = req.body;
    const user = await User.findById(req.user.id);
    const journalEntry = { date: new Date(date), type, responses };
    user.journal.push(journalEntry);
    await user.save();
    res.json({ _id: user.journal[user.journal.length - 1]._id });
  } catch (error) {
    console.error('Error saving journal:', error);
    res.status(500).json({ error: 'Failed to save journal' });
  }
});

app.delete('/api/regular/journal/:id', verifyToken, async (req, res) => {
  console.log('Deleting journal:', req.params.id, 'for user:', req.user.id);
  try {
    const user = await User.findById(req.user.id);
    user.journal = user.journal.filter((entry) => entry._id.toString() !== req.params.id);
    await user.save();
    res.json({ message: 'Journal entry deleted' });
  } catch (error) {
    console.error('Error deleting journal:', error);
    res.status(500).json({ error: 'Failed to delete journal' });
  }
});

app.get('/api/regular/journal-insights', verifyToken, async (req, res) => {
  console.log('Fetching journal insights for user:', req.user.id);
  try {
    const user = await User.findById(req.user.id);
    res.json(user.journalInsights);
  } catch (error) {
    console.error('Error fetching journal insights:', error);
    res.status(500).json({ error: 'Failed to fetch journal insights' });
  }
});

app.post('/api/regular/journal-insights', verifyToken, async (req, res) => {
  console.log('Generating journal insight for user:', req.user.id);
  try {
    const { journalDate, responses } = req.body;
    const prompt = `You are an AI that generates insightful reflections based on journal entries. Based on the journal responses: ${JSON.stringify(responses)}, provide a concise insight (100-150 words) that highlights key themes, emotions, or patterns.`;

    const completion = await openai.chat.completions.create({
      model: 'gpt-3.5-turbo',
      messages: [{ role: 'system', content: prompt }],
      max_tokens: 200
    });

    const insight = completion.choices[0].message.content.trim();
    const user = await User.findById(req.user.id);
    user.journalInsights.push({ journalDate: new Date(journalDate), insight, createdAt: new Date() });
    await user.save();
    res.json({ insight });
  } catch (error) {
    console.error('Error generating journal insight:', error);
    res.status(500).json({ error: 'Failed to generate insight' });
  }
});

// Daily Affirmations endpoint
app.get('/api/regular/daily-affirmations', verifyToken, async (req, res) => {
  console.log('Fetching daily affirmations for user:', req.user.id);
  try {
    const user = await User.findById(req.user.id);
    const latestAffirmation = user.dailyAffirmations[user.dailyAffirmations.length - 1];
    if (latestAffirmation && new Date(latestAffirmation.validUntil) > new Date()) {
      res.json(latestAffirmation);
    } else {
      res.json(null);
    }
  } catch (error) {
    console.error('Error fetching daily affirmations:', error);
    res.status(500).json({ error: 'Failed to fetch daily affirmations' });
  }
});

app.post('/api/regular/daily-affirmations', verifyToken, async (req, res) => {
  console.log('Generating daily affirmations for user:', req.user.id);
  try {
    const user = await User.findById(req.user.id);
    const latestAffirmation = user.dailyAffirmations[user.dailyAffirmations.length - 1];
    if (latestAffirmation && new Date(latestAffirmation.validUntil) > new Date()) {
      console.log('Affirmations still valid for user:', req.user.id);
      return res.json(latestAffirmation);
    }

    const prompt = `You are an AI that generates daily affirmations. Provide three positive affirmations in the following format: 
    - I Suggest: [100-150 characters]
    - I Encourage: [100-150 characters]
    - I Invite: [100-150 characters]
    Each should be unique, uplifting, and focused on personal growth or mindfulness.`;

    const completion = await openai.chat.completions.create({
      model: 'gpt-3.5-turbo',
      messages: [{ role: 'system', content: prompt }],
      max_tokens: 300
    });

    const affirmationText = completion.choices[0].message.content;
    const affirmations = {
      suggest: affirmationText.match(/I Suggest:\s*([\s\S]*?)(?=(I Encourage:|I Invite:|$))/i)?.[1].trim() || 'Embrace your unique journey today.',
      encourage: affirmationText.match(/I Encourage:\s*([\s\S]*?)(?=(I Invite:|$))/i)?.[1].trim() || 'You are capable of great things.',
      invite: affirmationText.match(/I Invite:\s*([\s\S]*?)$/i)?.[1].trim() || 'Reflect on what brings you joy.'
    };

    const validUntil = new Date();
    validUntil.setDate(validUntil.getDate() + 1);
    validUntil.setHours(0, 0, 0, 0);

    user.dailyAffirmations.push({
      suggest: affirmations.suggest,
      encourage: affirmations.encourage,
      invite: affirmations.invite,
      createdAt: new Date(),
      validUntil
    });

    await user.save();
    res.json({
      suggest: affirmations.suggest,
      encourage: affirmations.encourage,
      invite: affirmations.invite,
      createdAt: new Date(),
      validUntil
    });
  } catch (error) {
    console.error('Error generating daily affirmations:', error);
    res.status(500).json({ error: 'Failed to generate daily affirmations' });
  }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
