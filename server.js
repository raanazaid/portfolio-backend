const express = require('express');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const morgan = require('morgan');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false,
  crossdomainXml: false,
  dnsPrefetch: false,
  frameguard: { action: 'deny' },
  ieNoOpen: false,
  referrerPolicy: { policy: 'no-referrer' },
  strictTransportSecurity: false,
  xssFilter: true
}));

// Logging middleware
app.use(morgan('combined'));

// Middleware
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  optionsSuccessStatus: 200
}));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { success: false, message: 'Too many requests' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/contact', limiter);

const sanitizeInput = (input) => {
  if (!input) return input;
  return input
    .replace(/</g, '<')
    .replace(/>/g, '>')
    .replace(/"/g, '"')
    .replace(/'/g, '\'')
    .replace(/`/g, '&#x60;');
};

const validateInput = (name, email, message) => {
  const errors = [];
  const sanitizedName = sanitizeInput(name);
  const sanitizedEmail = sanitizeInput(email);
  const sanitizedMessage = sanitizeInput(message);
  
  if (!sanitizedName || sanitizedName.trim().length === 0) errors.push('Name is required');
  if (!sanitizedEmail || sanitizedEmail.trim().length === 0) errors.push('Email is required');
  else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(sanitizedEmail)) errors.push('Email is not valid');
  if (!sanitizedMessage || sanitizedMessage.trim().length === 0) errors.push('Message is required');
  
  return { errors, sanitizedName, sanitizedEmail, sanitizedMessage };
};

const transporter = nodemailer.createTransport({
  service: 'gmail',
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD
  },
  tls: { ciphers: 'SSLv3' }
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, message } = req.body;
    const { errors, sanitizedName, sanitizedEmail, sanitizedMessage } = validateInput(name, email, message);
    if (errors.length > 0) return res.status(400).json({ success: false, errors });
    
    const mailOptions = {
      from: `"Portfolio Contact" <${process.env.GMAIL_USER}>`,
      to: process.env.GMAIL_USER,
      subject: `New Message from Portfolio Contact Form`,
      text: `Name: ${sanitizedName}\nEmail: ${sanitizedEmail}\nMessage: ${sanitizedMessage}`
    };
    
    const info = await transporter.sendMail(mailOptions);
    res.json({ success: true, message: 'Message sent successfully!', info: info.messageId });
  } catch (error) {
    console.error('Error sending email:', error);
    res.status(500).json({ success: false, message: 'Failed to send message.' });
  }
});

// AI Chat proxy endpoint - CORRECTED VERSION
app.post('/api/chat', async (req, res) => {
  try {
    const { inputs } = req.body;
    
    if (!process.env.HUGGINGFACE_API_KEY) {
      console.error('HUGGINGFACE_API_KEY missing');
      return res.status(500).json({ error: 'System Configuration Missing' });
    }

    // Use router subdomain for modern openai-compatible API
    const hfEndpoint = "https://router.huggingface.co/v1/chat/completions";
    const hfModel = "HuggingFaceH4/zephyr-7b-beta";
    
    const response = await fetch(hfEndpoint, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${process.env.HUGGINGFACE_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: hfModel,
        messages: [
          { role: "system", content: "You are an AI assistant for Raanan Zaid's portfolio. You are helpful, professional, and friendly." },
          { role: "user", content: inputs }
        ],
        max_tokens: 200,
        temperature: 0.7
      })
    });
    
    if (!response.ok) {
      const errText = await response.text();
      console.error("HuggingFace Error:", response.status, errText);
      return res.status(502).json({ error: "LLM Provider Error", status: response.status, details: errText });
    }

    const result = await response.json();
    const botReply = result.choices && result.choices[0] && result.choices[0].message 
      ? result.choices[0].message.content 
      : "I'm sorry, I couldn't generate a response.";
    
    // Maintain frontend compatibility
    return res.json([{ generated_text: botReply }]);
  } catch (error) {
    console.error('Chat API error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.use((req, res) => res.status(404).json({ error: 'Route not found' }));

const server = app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
process.on('SIGTERM', () => server.close());
process.on('SIGINT', () => server.close());
module.exports = app;