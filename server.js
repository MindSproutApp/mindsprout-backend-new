require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const OpenAI = require('openai');
const cors = require('cors');
const sanitizeHtml = require('sanitize-html');
const rateLimit = require('express-rate-limit');
const { google } = require('googleapis');

const app = express();

// Apply CORS middleware with proper configuration
app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://mindsproutapp.com',
    'https://www.mindsproutapp.com',
    'https://mindsprout-frontend-c2qvqb1og-jays-projects-da2f8026.vercel.app'
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  preflightContinue: false,
  optionsSuccessStatus: 204
}));

// Explicitly handle preflight OPTIONS requests
app.options('*', cors(), (req, res) => {
  console.log('Handling OPTIONS request for:', req.originalUrl);
  res.status(204).end();
});

app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

app.use(express.json());

// Override HTTP methods to log errors
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
const originalDelete = app.delete;
app.delete = function (path, ...args) {
  try {
    return originalDelete.call(this, path, ...args);
  } catch (err) {
    console.error(`Invalid DELETE route: ${path}`, err);
    throw err;
  }
};

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api/regular', limiter);

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

console.log('Attempting to connect to MongoDB...');
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => console.log('Connected to MongoDB successfully!'))
  .catch(err => console.error('MongoDB connection failed:', err.message));

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
  tranquilTokens: { type: Number, default: 1 },
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
  starlitGuidance: {
    embrace: [String],
    letGo: [String],
    validUntil: Date
  },
  hasClaimedWelcomeTokens: { type: Boolean, default: false }
});

UserSchema.index({ email: 1 }, { unique: true });

const User = mongoose.model('User', UserSchema);

const embraceWords = [
  'curiosity', 'kindness', 'courage', 'clarity', 'patience', 'listen', 'grow', 'trust', 'create', 'focus',
  'empathy', 'honesty', 'adapt', 'calm', 'learn', 'smile', 'explore', 'share', 'persist', 'reflect',
  'strength', 'openness', 'gratitude', 'balance', 'hope', 'connect', 'breathe', 'forgive', 'dream', 'act',
  'confidence', 'gentleness', 'joy', 'resolve', 'observe', 'build', 'accept', 'care', 'inspire', 'rest',
  'truth', 'freedom', 'play', 'seek', 'heal', 'nurture', 'laugh', 'move', 'understand', 'choose',
  'compassion', 'boldness', 'peace', 'effort', 'spark', 'voice', 'climb', 'embrace', 'renew', 'reach',
  'wisdom', 'energy', 'grace', 'drive', 'touch', 'shine', 'stand', 'write', 'dance', 'vision',
  'warmth', 'zest', 'ground', 'flow', 'lift', 'plant', 'run', 'see', 'sing', 'anchor',
  'sparkle', 'stride', 'mend', 'bloom', 'stretch', 'soar', 'taste', 'think', 'comfort', 'light',
  'push', 'join', 'live', 'love', 'rise', 'teach', 'walk', 'welcome', 'cherish', 'uplift',
  'believe', 'thrive', 'radiate', 'encourage', 'unite', 'celebrate', 'evolve', 'imagine', 'support', 'spark',
  'awaken', 'harmonize', 'illuminate', 'venture', 'appreciate', 'empower', 'deepen', 'align', 'motivate', 'cultivate',
  'transform', 'renewal', 'inspire', 'blossom', 'navigate', 'center', 'expand', 'release', 'discover', 'enrich',
  'persevere', 'connect', 'radiance', 'authenticity', 'serenity', 'intention', 'vitality', 'embracing', 'elevate', 'flourish'
];

const letGoWords = [
  'doubt', 'fear', 'anger', 'guilt', 'shame', 'regret', 'stress', 'envy', 'clutter', 'rush',
  'blame', 'worry', 'grudge', 'pride', 'chaos', 'hide', 'ignore', 'resent', 'delay', 'judge',
  'tension', 'greed', 'panic', 'control', 'past', 'gossip', 'frown', 'haste', 'mask', 'burden',
  'jealousy', 'neglect', 'excuse', 'stagnate', 'dwell', 'reject', 'hoard', 'fret', 'scorn', 'wait',
  'rigidity', 'spite', 'sarcasm', 'trap', 'drift', 'gripe', 'limit', 'mope', 'shirk', 'block',
  'anxiety', 'bitterness', 'clash', 'weight', 'fake', 'grind', 'mistrust', 'overthink', 'rage', 'stall',
  'cynicism', 'laziness', 'numb', 'pressure', 'scramble', 'shout', 'strain', 'tangle', 'vague', 'waste',
  'apathy', 'boredom', 'chain', 'dread', 'fence', 'gloom', 'hinder', 'isolate', 'jolt', 'lure',
  'mock', 'nag', 'obsess', 'quell', 'repress', 'slump', 'sting', 'tug', 'unrest', 'yell',
  'avoid', 'complain', 'deny', 'evade', 'fumble', 'grumble', 'hesitate', 'restrict', 'sulk', 'withdraw',
  'resentment', 'insecurity', 'frustration', 'procrastinate', 'disdain', 'distraction', 'arrogance', 'defeat', 'rigmarole', 'self-pity',
  'vengeance', 'condemn', 'struggle', 'agitation', 'denial', 'fixate', 'suppress', 'loathing', 'disrupt', 'impatience',
  'discontent', 'malice', 'scramble', 'entangle', 'overwhelm', 'despair', 'criticize', 'stubbornness', 'negativity', 'distrust',
  'grievance', 'hostility', 'indifference', 'retreat', 'sabotage', 'inertia', 'dishonesty', 'disconnection', 'conform', 'exhaustion'
];

const getRandomWords = (wordList) => {
  if (!wordList || wordList.length === 0) {
    console.error('Word list is empty or undefined:', wordList);
    return ['N/A', 'N/A', 'N/A'];
  }
  const shuffled = [...wordList].sort(() => 0.5 - Math.random());
  const selected = shuffled.slice(0, Math.min(3, shuffled.length));
  return selected;
};

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : authHeader;
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
    const hashedPassword = await bcrypt.hash(password, 8);
    const user = new User({ name, email: email.toLowerCase(), username, password: hashedPassword });
    await user.save();
    const token = jwt.sign({ id: user._id, role: 'regular' }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ message: 'Signup successful', token });
  } catch (error) {
    console.error('Signup error:', error);
    if (error.code === 11000) {
      return res.status(400).json({ error: 'Email already exists' });
    }
    res.status(500).json({ error: 'Signup failed: ' + error.message });
  }
});

app.post('/api/regular/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user._id, role: 'regular' }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, name: user.name });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed: ' + error.message });
  }
});

app.get('/api/regular/goals', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      console.log('User not found:', req.user.id);
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user.goals || []);
  } catch (error) {
    console.error('Error fetching goals:', error);
    res.status(500).json({ error: 'Failed to fetch goals' });
  }
});

app.post('/api/regular/goals', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      console.log('User not found:', req.user.id);
      return res.status(404).json({ error: 'User not found' });
    }
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
    if (!user) {
      console.log('User not found:', req.user.id);
      return res.status(404).json({ error: 'User not found' });
    }
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
    if (!user) {
      console.log('User not found:', req.user.id);
      return res.status(404).json({ error: 'User not found' });
    }
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
    user.reports.splice(reportIndex, 1);
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
    if (!user) {
      console.log('User not found:', req.user.id);
      return res.status(404).json({ error: 'User not found' });
    }
    const now = new Date();
    const hoursSinceLastRegen = (now - new Date(user.lastTokenRegen)) / (1000 * 60 * 60);
    if (hoursSinceLastRegen >= 24 && user.tranquilTokens < 1) {
      user.tranquilTokens = 1;
      user.lastTokenRegen = new Date();
      await user.save();
    }
    res.json({ lastChatTimestamp: user.lastChatTimestamp, tranquilTokens: user.tranquilTokens });
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
    const responsesMap = new Map(Object.entries(responses));
    const journalEntry = {
      date: new Date(date),
      type: type,
      responses: responsesMap
    };
    user.journal.push(journalEntry);
    await user.save();
    res.json({ message: 'Journal entry saved', _id: journalEntry._id });
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
    user.journal.splice(journalEntryIndex, 1);
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
      Generate a profound summary (250-350 words) based on the following journal entry, written in a reflective and empathetic tone. Address the user directly (e.g., "You shared", "Your reflections"). Focus on uncovering deeper insights from their responses, highlighting themes, emotions, or patterns. Do not use emojis or include the raw data in the summary.
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
    const insightEntry = {
      _id: new mongoose.Types.ObjectId(),
      journalDate: new Date(journalDate),
      insight,
      createdAt: new Date()
    };
    user.journalInsights.push(insightEntry);
    await user.save();
    console.log('Journal insight saved:', { _id: insightEntry._id, journalDate, insight: insight.substring(0, 50) + '...' });
    res.json({ _id: insightEntry._id.toString(), insight });
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
    I'm Pal, your calm, caring friend here to really listen. Think of this like a deep, thoughtful chat over coffee. I reflect what you share with empathy and curiosity—gently helping you notice patterns, emotions, and what feels meaningful. Support personal reflection and realization over advice. If the user expresses strong emotions like shame, regret, resentment, or deep sadness, you may gently invite them to explore past experiences that could be connected—but never assume or push. Let things flow naturally and focus on what the moment reveals. Stay grounded, warm, and personal—no therapy jargon. Keep replies between 30–50 words. Don't start responses with "Pal:". End with a soft, open-ended question that invites deeper thought or emotion.
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
    Write a detailed summary of this chat session in a professional tone (up to 3000 words total, no emojis, ensuring all sections are completed), addressing the user directly in first person (e.g., "You felt", "You expressed"). Split into five sections, each section must have a minimum of 300-500 words, and use ** as headers exactly as shown below:
    - **What We Discussed**: Summarize the key topics the user brought up and explain why they were important to them, based on what was said or implied in the conversation.
    - **Your Thoughts & Feelings**: Describe the main emotions and thoughts you felt, with examples.
    - **Insights Uncovered**: Detail any reflections or insights you gained during our chat.
    - **Mood Reflection**: Reflect deeply on the user’s emotional state, drawing from both their pre-chat mood input and in-chat language. Identify 1–2 meaningful emotional shifts or patterns and explore what might have influenced them.
    - **Recommendations**: Based on the specific challenges, insights, and emotions shared in this conversation, suggest 1–2 tailored next steps or activities that align with the user’s needs. Avoid generic suggestions like journaling or meditating unless explicitly discussed. Instead, pull from the conversation to offer relevant, actionable ideas or reframing.
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
      temperature: 0.5,
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
    await user.save();
    console.log('Report saved to MongoDB:', report);

    res.json(report);
  } catch (error) {
    console.error('End chat error:', error.message);
    res.status(500).json({ error: 'Error ending chat: ' + error.message });
  }
});

app.delete('/api/regular/account', authenticateToken, async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.user.id);
    if (!user) {
      console.log('User not found:', req.user.id);
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ message: 'Account deleted successfully' });
  } catch (err) {
    console.error('Error deleting account:', err);
    res.status(500).json({ error: 'Failed to delete account: ' + err.message });
  }
});

app.get('/api/regular/tranquil-tokens', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      console.log('User not found:', req.user.id);
      return res.status(404).json({ error: 'User not found' });
    }
    const now = new Date();
    const hoursSinceLastRegen = (now - new Date(user.lastTokenRegen)) / (1000 * 60 * 60);
    if (hoursSinceLastRegen >= 24 && user.tranquilTokens < 1) {
      user.tranquilTokens = 1;
      user.lastTokenRegen = new Date();
      await user.save();
    }
    res.json({ tranquilTokens: user.tranquilTokens, lastTokenRegen: user.lastTokenRegen });
  } catch (error) {
    console.error('Error fetching tokens:', error);
    res.status(500).json({ error: 'Failed to fetch tokens' });
  }
});

app.post('/api/regular/consume-token', authenticateToken, async (req, res) => {
  const { action } = req.body;
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      console.log('User not found:', req.user.id);
      return res.status(404).json({ error: 'User not found' });
    }
    if (user.tranquilTokens < 1) {
      return res.status(400).json({ error: 'Insufficient tokens' });
    }
    user.tranquilTokens -= 1;
    await user.save();
    res.json({ message: 'Token consumed', tranquilTokens: user.tranquilTokens });
  } catch (error) {
    console.error('Error consuming token:', error);
    res.status(500).json({ error: 'Failed to consume token' });
  }
});

app.get('/api/regular/starlit-guidance', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      console.log('User not found:', req.user.id);
      return res.status(404).json({ error: 'User not found' });
    }

    const now = new Date();
    if (!user.starlitGuidance || new Date(user.starlitGuidance.validUntil) < now ||
        !user.starlitGuidance.embrace?.length || !user.starlitGuidance.letGo?.length) {
      console.log('Generating new starlitGuidance for user:', req.user.id);
      const newEmbrace = getRandomWords(embraceWords);
      const newLetGo = getRandomWords(letGoWords);
      user.starlitGuidance = {
        embrace: newEmbrace,
        letGo: newLetGo,
        validUntil: new Date(now.getTime() + 24 * 60 * 60 * 1000)
      };
      await user.save();
    }
    res.json(user.starlitGuidance);
  } catch (error) {
    console.error('Error fetching Starlit Guidance:', error.message);
    res.status(500).json({ error: 'Failed to fetch Starlit Guidance: ' + error.message });
  }
});

app.post('/api/regular/claim-welcome-tokens', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      console.log('User not found:', req.user.id);
      return res.status(404).json({ error: 'User not found' });
    }
    if (user.hasClaimedWelcomeTokens) {
      console.log('User already claimed welcome tokens:', req.user.id);
      return res.status(400).json({ error: 'Welcome tokens already claimed' });
    }
    user.tranquilTokens += 5;
    user.hasClaimedWelcomeTokens = true;
    await user.save();
    console.log('Welcome tokens claimed for user:', req.user.id, 'New token balance:', user.tranquilTokens);
    res.json({ message: 'Welcome tokens claimed', tranquilTokens: user.tranquilTokens });
  } catch (error) {
    console.error('Error claiming welcome tokens:', error.message);
    res.status(500).json({ error: 'Failed to claim welcome tokens: ' + error.message });
  }
});

const { GoogleAuth } = require('google-auth-library');
const auth = new GoogleAuth({
  credentials: {
    client_email: process.env.GOOGLE_CLIENT_EMAIL,
    private_key: process.env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n'),
  },
  scopes: ['https://www.googleapis.com/auth/androidpublisher']
});

const androidPublisher = google.androidpublisher({
  version: 'v3',
  auth: auth,
});

app.post('/api/regular/purchase-tokens', authenticateToken, async (req, res) => {
  const { purchaseToken, productId } = req.body;
  try {
    const prices = {
      '1_token.': { quantity: 1 },
      '5_token.': { quantity: 5 },
      '10_token.': { quantity: 10 },
      '50_token.': { quantity: 50 },
      '100_token.': { quantity: 100 },
    };

    if (!prices[productId]) {
      console.log('Invalid product ID:', productId);
      return res.status(400).json({ error: 'Invalid product ID' });
    }

    const purchase = await androidPublisher.purchases.products.get({
      packageName: process.env.ANDROID_PACKAGE_NAME,
      productId: productId,
      token: purchaseToken
    });

    if (purchase.data.purchaseState !== 0) {
      console.log('Purchase not completed:', purchaseToken);
      return res.status(400).json({ error: 'Purchase not completed' });
    }

    if (purchase.data.consumptionState === 1) {
      console.log('Purchase already consumed:', purchaseToken);
      return res.status(400).json({ error: 'Purchase already consumed' });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      console.log('User not found:', req.user.id);
      return res.status(404).json({ error: 'User not found' });
    }

    user.tranquilTokens += prices[productId].quantity;
    await user.save();

    await androidPublisher.purchases.products.acknowledge({
      packageName: process.env.ANDROID_PACKAGE_NAME,
      productId: productId,
      token: purchaseToken
    });

    res.json({ message: 'Tokens purchased', tranquilTokens: user.tranquilTokens });
  } catch (error) {
    console.error('Error processing token purchase:', error.message);
    res.status(500).json({ error: 'Failed to purchase tokens: ' + error.message });
  }
});

app.get('/api/regular/daily-affirmations', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      console.log('User not found:', req.user.id);
      return res.status(404).json({ error: 'User not found' });
    }

    const now = new Date();
    const affirmationsPrompt = `
      Generate three unique daily affirmations for the user, each 10-20 words, in a warm and encouraging tone. Structure them as:
      - I Suggest: [action-oriented affirmation]
      - I Encourage: [emotion-focused affirmation]
      - I Invite: [reflection-oriented affirmation]
      Use a positive, empathetic voice and avoid emojis.
    `;
    const response = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: affirmationsPrompt }],
      max_tokens: 100,
      temperature: 0.7
    });
    const text = response.choices[0].message.content.trim();
    const affirmations = { suggest: '', encourage: '', invite: '' };
    const lines = text.split('\n');
    lines.forEach(line => {
      if (line.startsWith('I Suggest:')) affirmations.suggest = line.replace('I Suggest:', '').trim();
      else if (line.startsWith('I Encourage:')) affirmations.encourage = line.replace('I Encourage:', '').trim();
      else if (line.startsWith('I Invite:')) affirmations.invite = line.replace('I Invite:', '').trim();
    });

    res.json(affirmations);
  } catch (error) {
    console.error('Error generating daily affirmations:', error);
    res.status(500).json({ error: 'Failed to generate daily affirmations' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
