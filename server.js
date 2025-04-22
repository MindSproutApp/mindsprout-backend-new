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

// Handle CORS preflight requests
app.options('*', cors());

// Rate limiting for API routes only
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // 100 requests
});
app.use('/api/regular', limiter);

// Initialize OpenAI with environment variable
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// MongoDB connection
console.log('Attempting to connect to MongoDB...');
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => console.log('Connected to MongoDB successfully!'))
  .catch(err => console.error('MongoDB connection failed:', err.message));

// Define the schema
const UserSchema = new mongoose.Schema({
  name: String,
  email: String,
  username: String,
  password: String,
  reports: [{
    date: Date,
    summary: {
      discussed: String,
      thoughtsFeelings: String,
      insights: String,
      moodReflection: String,
      recommendations: String
    },
    quizData: Array
  }],
  goals: [{ text: String, achieved: Boolean, date: Date }],
  lastChatTimestamp: Date,
  chatTokens: { type: Number, default: 3 },
  lastTokenRegen: { type: Date, default: Date.now },
  journal: [{
    date: { type: Date, required: true },
    type: { type: String, required: true },
    responses: { type: Map, of: String }
  }],
  journalInsights: [{
    journalDate: Date,
    insight: String,
    createdAt: { type: Date, default: Date.now }
  }],
  dailyAffirmations: {
    suggest: String,
    encourage: String,
    invite: String,
    validUntil: Date
  }
});

const User = mongoose.model('User', UserSchema);

const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) {
    console.log('No token provided');
    return res.status(401).json({ error: 'No token provided' });
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.log('Invalid token:', err.message);
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

app.post('/api/regular/signup', async (req, res) => {
  const { name, email, username, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, username, password: hashedPassword });
    await user.save();
    const token = jwt.sign({ id: user._id, role: 'regular' }, process.env.JWT_SECRET);
    res.json({ message: 'Signup successful', token });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Signup failed: ' + error.message });
  }
});

app.post('/api/regular/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user._id, role: 'regular' }, process.env.JWT_SECRET);
    res.json({ token, name: user.name });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed: ' + error.message });
  }
});

app.get('/api/regular/goals', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    res.json(user.goals || []);
  } catch (error) {
    console.error('Error fetching goals:', error);
    res.status(500).json({ error: 'Failed to fetch goals' });
  }
});

app.post('/api/regular/goals', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    user.goals.push({ ...req.body, date: new Date() });
    await user.save();
    res.json(user.goals);
  } catch (error) {
    console.error('Error adding goal:', error);
    res.status(500).json({ error: 'Failed to add goal' });
  }
});

app.put('/api/regular/goals', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const goal = user.goals.find(g => g.text === req.body.text);
    if (goal) goal.achieved = req.body.achieved;
    await user.save();
    res.json(user.goals);
  } catch (error) {
    console.error('Error updating goal:', error);
    res.status(500).json({ error: 'Failed to update goal' });
  }
});

app.get('/api/regular/reports', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    res.json(user.reports || []);
  } catch (error) {
    console.error('Error fetching reports:', error);
    res.status(500).json({ error: 'Failed to fetch reports' });
  }
});

app.delete('/api/regular/reports/:id', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      console.log('User not found:', req.user.id);
      return res.status(404).json({ error: 'User not found' });
    }
    const reportIndex = user.reports.findIndex(report => report._id.toString() === req.params.id);
    if (reportIndex === -1) {
      console.log('Report not found:', req.params.id);
      return res.status(404).json({ error: 'Report not found' });
    }
    user.reports.splice(reportIndex, 1); // Remove the report
    await user.save();
    res.json({ message: 'Report deleted successfully' });
  } catch (err) {
    console.error('Error deleting report:', err);
    res.status(500).json({ error: 'Failed to delete report: ' + err.message });
  }
});

app.get('/api/regular/last-chat', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const now = new Date();
    const hoursSinceLastRegen = (now - new Date(user.lastTokenRegen)) / (1000 * 60 * 60);
    if (hoursSinceLastRegen >= 3) {
      const tokensToAdd = Math.floor(hoursSinceLastRegen / 3);
      user.chatTokens = Math.min(user.chatTokens + tokensToAdd, 3);
      user.lastTokenRegen = new Date(now.getTime() - ((hoursSinceLastRegen % 3) * 1000 * 60 * 60));
      await user.save();
    }
    res.json({ lastChatTimestamp: user.lastChatTimestamp, chatTokens: user.chatTokens });
  } catch (error) {
    console.error('Error fetching last chat:', error);
    res.status(500).json({ error: 'Failed to fetch last chat' });
  }
});

app.get('/api/regular/journal', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      console.log('User not found:', req.user.id);
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user.journal || []);
  } catch (err) {
    console.error('Error fetching journal entries:', err);
    res.status(500).json({ error: 'Failed to fetch journal entries: ' + err.message });
  }
});

app.post('/api/regular/insights', authenticateToken, async (req, res) => {
  const { date, type, responses } = req.body;
  if (!date || !type || !responses) {
    console.log('Missing insights fields:', { date, type, responses });
    return res.status(400).json({ error: 'Missing required fields' });
  }
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      console.log('User not found:', req.user.id);
      return res.status(404).json({ error: 'User not found' });
    }
    if (!user.journal) {
      user.journal = [];
    }
    const responsesMap = new Map();
    Object.keys(responses).forEach(key => {
      responsesMap.set(key, responses[key]);
    });
    const journalEntry = {
      date: new Date(date),
      type: type,
      responses: responsesMap
    };
    user.journal.push(journalEntry);
    await user.save();
    res.json({ message: 'Journal entry saved', _id: journalEntry._id }); // Return _id for client
  } catch (err) {
    console.error('Error saving journal:', err.message);
    res.status(500).json({ error: 'Failed to save journal: ' + err.message });
  }
});

app.delete('/api/regular/journal/:id', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      console.log('User not found:', req.user.id);
      return res.status(404).json({ error: 'User not found' });
    }
    const journalEntryIndex = user.journal.findIndex(entry => entry._id.toString() === req.params.id);
    if (journalEntryIndex === -1) {
      console.log('Journal entry not found:', req.params.id);
      return res.status(404).json({ error: 'Journal entry not found' });
    }
    user.journal.splice(journalEntryIndex, 1); // Remove the journal entry
    await user.save();
    res.json({ message: 'Journal entry deleted successfully' });
  } catch (err) {
    console.error('Error deleting journal entry:', err);
    res.status(500).json({ error: 'Failed to delete journal entry: ' + err.message });
  }
});

app.post('/api/regular/journal-insights', authenticateToken, async (req, res) => {
  const { journalDate, responses } = req.body;
  if (!journalDate || !responses) {
    console.log('Missing journal insights fields:', { journalDate, responses });
    return res.status(400).json({ error: 'Missing required fields' });
  }
  try {
    const sanitizedResponses = Object.fromEntries(
      Object.entries(responses).map(([key, value]) => [key, sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })])
    );
    const prompt = `
      Generate a profound summary (200-300 words) based on the following journal entry, written in a reflective and empathetic tone. Address the user directly (e.g., "You shared", "Your reflections"). Focus on uncovering deeper insights from their responses, highlighting themes, emotions, or patterns. Do not use emojis or include the raw data in the summary.
      Journal Responses: ${JSON.stringify(sanitizedResponses)}
    `;
    const response = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: prompt }],
      max_tokens: 350,
      temperature: 0.7
    });
    const insight = response.choices[0].message.content.trim();
    const user = await User.findById(req.user.id);
    if (!user) {
      console.log('User not found:', req.user.id);
      return res.status(404).json({ error: 'User not found' });
    }
    if (!user.journalInsights) {
      user.journalInsights = [];
    }
    user.journalInsights.push({
      journalDate: new Date(journalDate),
      insight,
      createdAt: new Date()
    });
    await user.save();
    res.json({ insight });
  } catch (err) {
    console.error('Error generating journal insight:', err.message);
    res.status(500).json({ error: 'Failed to generate insight: ' + err.message });
  }
});

app.get('/api/regular/journal-insights', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      console.log('User not found:', req.user.id);
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user.journalInsights || []);
  } catch (err) {
    console.error('Error fetching journal insights:', err);
    res.status(500).json({ error: 'Failed to fetch journal insights: ' + err.message });
  }
});

app.post('/api/regular/chat', authenticateToken, async (req, res) => {
  const { message, chatHistory } = req.body;
  const sanitizedMessage = sanitizeHtml(message, { allowedTags: [], allowedAttributes: {} });
  const history = chatHistory.map(msg => `${msg.sender === 'user' ? 'You' : 'Pal'}: ${sanitizeHtml(msg.text, { allowedTags: [], allowedAttributes: {} })}`).join('\n');
  const systemPrompt = `
    I’m Pal, your laid-back, caring friend here to chat like we’re grabbing coffee. I’ll listen closely, reflect what you say with empathy, and keep it casual—around 30-50 words. No therapy jargon, just real support. Don’t start responses with "Pal:". End with a chill question to keep us going.
  `;
  try {
    const response = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: `Chat History:\n${history}\nYou: ${sanitizedMessage}` }
      ],
      max_tokens: 60,
      temperature: 0.8
    });
    let botResponse = response.choices[0].message.content.trim();
    const words = botResponse.split(' ');
    if (words.length > 50) botResponse = words.slice(0, 50).join(' ') + '.';
    else if (words.length < 30) botResponse += ' What’s on your mind now?';
    res.json({ text: botResponse, timestamp: new Date().toISOString() });
  } catch (error) {
    console.error('Chat error:', error);
    res.status(500).json({ error: 'Error generating chat response: ' + error.message });
  }
});

app.post('/api/regular/end-chat', authenticateToken, async (req, res) => {
  const { chatHistory, quiz } = req.body;
  console.log('End-chat request received:', { userId: req.user.id, chatHistoryLength: chatHistory?.length, quiz });

  if (!chatHistory || !quiz) {
    console.log('Missing chatHistory or quiz data');
    return res.status(400).json({ error: 'Missing chat history or quiz data' });
  }

  const history = chatHistory.map(msg => `${msg.sender === 'user' ? 'You' : 'Pal'}: ${sanitizeHtml(msg.text, { allowedTags: [], allowedAttributes: {} })}`).join('\n');
  const preQuiz = { ...quiz, isPostChat: false };

  const prompt = `
    Write a detailed summary of this chat session in a professional tone (up to 1000 words total, no emojis), addressing the user directly in first person (e.g., "You felt", "You expressed"). Split into five sections, each 200-250 words, and use ** as headers exactly as shown below:
    - **What We Discussed**: Summarize key topics you brought up in the conversation.
    - **Your Thoughts & Feelings**: Describe the main emotions and thoughts you felt, with examples.
    - **Insights Uncovered**: Detail any reflections or insights you gained during our chat.
    - **Mood Reflection**: Reflect on how you felt based on the pre-chat quiz and chat content, noting any shifts.
    - **Recommendations**: Recommend insightful activities to help with your queries.
    Use this data for context but do not include it in the summary:
    Chat History: ${history}
    Pre-Chat Quiz: ${JSON.stringify(preQuiz)}
  `;

  try {
    console.log('Generating summary with OpenAI...');
    const response = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: prompt }],
      max_tokens: 1100,
      temperature: 0.5
    });
    const text = response.choices[0].message.content.trim();
    console.log('Full raw summary response:', text);

    const sections = {};
    const sectionRegex = /\*\*(.*?)\*\*(.*?)(?=\*\*|$)/gs;
    let match;
    while ((match = sectionRegex.exec(text)) !== null) {
      const title = match[1].trim();
      const content = match[2].trim();
      if (title === 'What We Discussed') sections.discussed = content;
      else if (title === 'Your Thoughts & Feelings') sections.thoughtsFeelings = content;
      else if (title === 'Insights Uncovered') sections.insights = content;
      else if (title === 'Mood Reflection') sections.moodReflection = content;
      else if (title === 'Recommendations') sections.recommendations = content;
    }

    const requiredSections = ['discussed', 'thoughtsFeelings', 'insights', 'moodReflection', 'recommendations'];
    requiredSections.forEach(section => {
      if (!sections[section]) sections[section] = 'No content generated for this section.';
    });

    const user = await User.findById(req.user.id);
    if (!user) {
      console.log('User not found:', req.user.id);
      return res.status(404).json({ error: 'User not found' });
    }

    const report = {
      date: new Date(),
      summary: sections,
      quizData: [preQuiz]
    };
    user.reports.push(report);
    user.lastChatTimestamp = new Date();
    user.chatTokens = Math.max(user.chatTokens - 1, 0);
    await user.save();
    console.log('Report saved to MongoDB:', report);

    res.json(report);
  } catch (error) {
    console.error('End chat error:', error.message);
    res.status(500).json({ error: 'Error ending chat: ' + error.message });
  }
});

app.get('/api/regular/daily-affirmations', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      console.log('User not found:', req.user.id);
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user.dailyAffirmations || null);
  } catch (error) {
    console.error('Error fetching daily affirmations:', error);
    res.status(500).json({ error: 'Failed to fetch daily affirmations: ' + error.message });
  }
});

app.post('/api/regular/daily-affirmations', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      console.log('User not found:', req.user.id);
      return res.status(404).json({ error: 'User not found' });
    }

    // Check if affirmations are still valid
    if (user.dailyAffirmations && new Date(user.dailyAffirmations.validUntil) > new Date()) {
      return res.status(429).json({ error: 'Daily affirmations already generated. Try again tomorrow.' });
    }

    // Generate new affirmations
    const prompts = [
      {
        type: 'suggest',
        prompt: 'Please provide a specific, actionable mindfulness practice or self-care activity that users can easily incorporate into their daily routine.'
      },
      {
        type: 'encourage',
        prompt: 'Generate an encouraging phrase or action that motivates users to embrace positivity and practice self-compassion.'
      },
      {
        type: 'invite',
        prompt: 'Suggest a reflective practice or activity that users can engage in to promote mindfulness and enhance their overall well-being.'
      }
    ];

    const affirmations = {};
    for (const { type, prompt } of prompts) {
      const response = await openai.chat.completions.create({
        model: 'gpt-4o-mini',
        messages: [{ role: 'user', content: prompt }],
        max_tokens: 100,
        temperature: 0.7
      });
      affirmations[type] = response.choices[0].message.content.trim();
    }

    // Set validUntil to 24 hours from now
    const validUntil = new Date(Date.now() + 24 * 60 * 60 * 1000);

    user.dailyAffirmations = {
      suggest: affirmations.suggest,
      encourage: affirmations.encourage,
      invite: affirmations.invite,
      validUntil
    };

    await user.save();
    res.json(user.dailyAffirmations);
  } catch (error) {
    console.error('Error generating daily affirmations:', error);
    res.status(500).json({ error: 'Failed to generate daily affirmations: ' + error.message });
  }
});

// Use dynamic port for Render
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
