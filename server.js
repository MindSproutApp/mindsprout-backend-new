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
    embrace: [String], // Array of 3 words for "What Should I Embrace"
    letGo: [String], // Array of 3 words for "What Should I Let Go Of"
    validUntil: Date // When to regenerate
  }
});

const User = mongoose.model('User', UserSchema);

// Word lists for Starlit Guidance
const embraceWords = [
  'Bright Spark', 'Open Heart', 'Bold Step', 'Quiet Strength', 'Wild Dream',
  'Gentle Touch', 'Fierce Hope', 'True Path', 'Soft Glow', 'Brave Leap',
  'Deep Trust', 'Free Spirit', 'Warm Light', 'Strong Roots', 'New Horizon',
  'Pure Joy', 'Calm Flow', 'High Flight', 'Kind Voice', 'Vast Sky',
  'Steady Pulse', 'Raw Courage', 'Clear Vision', 'Sweet Bloom', 'Firm Ground',
  'Bright Flame', 'Open Door', 'True North', 'Warm Breeze', 'Deep Breath',
  'Wild Heart', 'Soft Dawn', 'Bold Truth', 'Free Dance', 'Quiet Grace',
  'Strong Tide', 'New Dawn', 'Pure Light', 'Fierce Love', 'Calm Sea',
  'High Star', 'Kind Spark', 'Vast Dream', 'Steady Flame', 'Raw Hope',
  'Clear Sky', 'Sweet Song', 'Firm Hope', 'Bright Path', 'Open Soul'
];

const letGoWords = [
  'Heavy Chain', 'Dark Cloud', 'Old Fear', 'Cold Grip', 'Faded Echo',
  'Broken Tie', 'Dull Ache', 'Lost Path', 'Tight Knot', 'False Mask',
  'Bitter Sting', 'Worn Thread', 'Hard Shell', 'Dim Shadow', 'Old Wound',
  'Cold Wall', 'Frayed Rope', 'Heavy Load', 'False Hope', 'Dark Veil',
  'Rigid Frame', 'Old Scar', 'Tight Grasp', 'Dull Spark', 'Lost Dream',
  'Cold Fear', 'Broken Link', 'Faded Light', 'Hard Edge', 'Old Doubt',
  'Dim Glow', 'Heavy Fog', 'False Step', 'Worn Mask', 'Bitter Root',
  'Cold Stone', 'Frayed Bond', 'Dark Weight', 'Old Chain', 'Tight Cage',
  'Dull Flame', 'Lost Voice', 'Hard Truth', 'Faded Star', 'Cold Touch',
  'Broken Road', 'Dim Hope', 'Heavy Mask', 'Old Storm', 'False Dawn'
];

// Helper function to select 3 random words
const getRandomWords = (wordList) => {
  if (!wordList || wordList.length === 0) {
    console.error('Word list is empty or undefined:', wordList);
    return ['N/A', 'N/A', 'N/A']; // Fallback
  }
  console.log('Word list length:', wordList.length);
  const shuffled = [...wordList].sort(() => 0.5 - Math.random());
  const selected = shuffled.slice(0, Math.min(3, shuffled.length));
  console.log('Selected words:', selected);
  return selected;
};

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
    if (hoursSinceLastRegen >= 24 && user.tranquilTokens < 1) {
      user.tranquilTokens = 1; // Regenerate one token
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
    Write a detailed summary of this chat session in a professional tone (up to 1500 words total, no emojis), addressing the user directly in first person (e.g., "You felt", "You expressed"). Split into five sections, each 250-300 words, and use ** as headers exactly as shown below:
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

// Tranquil Tokens Endpoints
app.get('/api/regular/tranquil-tokens', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const now = new Date();
    const hoursSinceLastRegen = (now - new Date(user.lastTokenRegen)) / (1000 * 60 * 60);
    if (hoursSinceLastRegen >= 24 && user.tranquilTokens < 1) {
      user.tranquilTokens = 1; // Regenerate one token
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

// Starlit Guidance Endpoint
app.get('/api/regular/starlit-guidance', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      console.log('User not found:', req.user.id);
      return res.status(404).json({ error: 'User not found' });
    }

    // Check if words need regeneration
    const now = new Date();
    console.log('Checking starlitGuidance for user:', req.user.id, 'Current starlitGuidance:', user.starlitGuidance);
    if (!user.starlitGuidance || new Date(user.starlitGuidance.validUntil) < now || 
        !user.starlitGuidance.embrace?.length || !user.starlitGuidance.letGo?.length) {
      console.log('Generating new starlitGuidance for user:', req.user.id);
      const newEmbrace = getRandomWords(embraceWords);
      const newLetGo = getRandomWords(letGoWords);
      user.starlitGuidance = {
        embrace: newEmbrace,
        letGo: newLetGo,
        validUntil: new Date(now.getTime() + 24 * 60 * 60 * 1000) // 24 hours from now
      };
      console.log('New starlitGuidance:', user.starlitGuidance);
      try {
        await user.save();
        console.log('Saved starlitGuidance for user:', req.user.id, user.starlitGuidance);
      } catch (saveError) {
        console.error('Error saving starlitGuidance:', saveError.message);
        return res.status(500).json({ error: 'Failed to save Starlit Guidance: ' + saveError.message });
      }
    } else {
      console.log('Using existing starlitGuidance for user:', req.user.id, user.starlitGuidance);
    }

    res.json(user.starlitGuidance);
  } catch (error) {
    console.error('Error fetching Starlit Guidance:', error.message);
    res.status(500).json({ error: 'Failed to fetch Starlit Guidance: ' + error.message });
  }
});

// === START OF STRIPE ADDITIONS ===
// Initialize Stripe
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// Create Stripe Checkout Session
app.post('/api/regular/create-checkout-session', authenticateToken, async (req, res) => {
  const { quantity, productId } = req.body;
  try {
    // Define token prices (matching frontend)
    const prices = {
      'tranquil_tokens_1': { amount: 99, quantity: 1 }, // £0.99
      'tranquil_tokens_5': { amount: 199, quantity: 5 }, // £1.99
      'tranquil_tokens_10': { amount: 699, quantity: 10 }, // £6.99
      'tranquil_tokens_50': { amount: 1999, quantity: 50 }, // £19.99
      'tranquil_tokens_100': { amount: 2999, quantity: 100 }, // £29.99
    };

    if (!prices[productId]) {
      console.log('Invalid product ID:', productId);
      return res.status(400).json({ error: 'Invalid product ID' });
    }

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [
        {
          price_data: {
            currency: 'gbp',
            product_data: {
              name: `${prices[productId].quantity} Tranquil Tokens`,
            },
            unit_amount: prices[productId].amount, // Amount in pence
          },
          quantity: 1,
        },
      ],
      mode: 'payment',
      success_url: `${process.env.STRIPE_SUCCESS_URL}?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: process.env.STRIPE_CANCEL_URL,
      metadata: {
        userId: req.user.id,
        productId,
        quantity: prices[productId].quantity.toString(),
      },
    });

    res.json({ sessionId: session.id });
  } catch (error) {
    console.error('Error creating checkout session:', error.message);
    res.status(500).json({ error: 'Failed to create checkout session: ' + error.message });
  }
});

// Update purchase-tokens endpoint to verify Stripe payment
app.post('/api/regular/purchase-tokens', authenticateToken, async (req, res) => {
  const { sessionId } = req.body;
  try {
    // Verify the Stripe session
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    if (session.payment_status !== 'paid') {
      console.log('Payment not completed for session:', sessionId);
      return res.status(400).json({ error: 'Payment not completed' });
    }

    // Ensure the user matches
    if (session.metadata.userId !== req.user.id) {
      console.log('User ID mismatch:', { sessionUser: session.metadata.userId, reqUser: req.user.id });
      return res.status(403).json({ error: 'Unauthorized' });
    }

    const quantity = parseInt(session.metadata.quantity, 10);
    const user = await User.findById(req.user.id);
    user.tranquilTokens += quantity;
    await user.save();

    res.json({ message: 'Tokens purchased', tranquilTokens: user.tranquilTokens });
  } catch (error) {
    console.error('Error processing token purchase:', error.message);
    res.status(500).json({ error: 'Failed to purchase tokens: ' + error.message });
  }
});
// === END OF STRIPE ADDITIONS ===

// Use dynamic port for Render
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
