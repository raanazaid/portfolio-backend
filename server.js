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
  contentSecurityPolicy: false, // Adjust as needed
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

// Rate limiting to prevent abuse
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/contact', limiter);

// Validation function with XSS prevention
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
  
  if (!sanitizedName || sanitizedName.trim().length === 0) {
    errors.push('Name is required');
  } else if (sanitizedName.trim().length > 100) {
    errors.push('Name is too long');
  }
  
  if (!sanitizedEmail || sanitizedEmail.trim().length === 0) {
    errors.push('Email is required');
  } else {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(sanitizedEmail)) {
      errors.push('Email is not valid');
    } else if (sanitizedEmail.length > 254) {
      errors.push('Email is too long');
    }
  }
  
  if (!sanitizedMessage || sanitizedMessage.trim().length === 0) {
    errors.push('Message is required');
  } else {
    const trimmedMessage = sanitizedMessage.trim();
    if (trimmedMessage.length < 10) {
      errors.push('Message must be at least 10 characters');
    } else if (trimmedMessage.length > 5000) {
      errors.push('Message is too long');
    }
  }
  
  return { errors, sanitizedName, sanitizedEmail, sanitizedMessage };
};

// Create transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD
  },
  tls: {
    ciphers: 'SSLv3'
  }
});

// Verify transporter
transporter.verify((error) => {
  if (error) {
    console.error('Nodemailer transporter not ready:', error);
  } else {
    console.log('Nodemailer transporter is ready');
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: '1.0.0'
  });
});

// Contact form endpoint
app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, message } = req.body;
    
    // Validate and sanitize input
    const { errors, sanitizedName, sanitizedEmail, sanitizedMessage } = validateInput(name, email, message);
    if (errors.length > 0) {
      return res.status(400).json({
        success: false,
        errors: errors
      });
    }
    
    // Email options with professional formatting
    const mailOptions = {
      from: `"Portfolio Contact" <${process.env.GMAIL_USER}>`,
      to: process.env.GMAIL_USER,
      subject: `New Message from Portfolio Contact Form`,
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            h3 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
            p { margin: 15px 0; }
            strong { color: #2c3e50; }
            pre { background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #3498db; }
            small { color: #7f8c8d; }
          </style>
        </head>
        <body>
          <div class="container">
            <h3>New Contact Form Submission</h3>
            <p><strong>Name:</strong> ${sanitizedName}</p>
            <p><strong>Email:</strong> ${sanitizedEmail}</p>
            <p><strong>Message:</strong></p>
            <pre>${sanitizedMessage}</pre>
            <br>
            <small>Sent from your portfolio contact form | ${new Date().toLocaleString()}</small>
          </div>
        </body>
        </html>
      `,
      // Plain text alternative if HTML doesn't render
      text: `New Contact Form Submission\nName: ${sanitizedName}\nEmail: ${sanitizedEmail}\nMessage: ${sanitizedMessage}`
    };
    
    // Send email
    const info = await transporter.sendMail(mailOptions);
    
    console.log('Message sent: %s', info.messageId);
    
    res.json({
      success: true,
      message: 'Message sent successfully!',
      info: info.messageId,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('Error sending email:', error);
    
    // Handle specific Nodemailer errors
    const errorMessage = error.message || 'Failed to send message';
    
    if (errorMessage.includes('Authentication credentials')) {
      return res.status(500).json({
        success: false,
        message: 'Authentication failed. Please check your Gmail credentials and app password.'
      });
    }
    
    if (errorMessage.includes('Message rate limit exceeded')) {
      return res.status(429).json({
        success: false,
        message: 'Rate limit exceeded. Please try again later.'
      });
    }
    
    res.status(500).json({
      success: false,
      message: 'Failed to send message. Please try again later.',
      error: errorMessage
    });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Route not found',
    path: req.path,
    method: req.method
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  
  if (res.headersSent) {
    return next(err);
  }
  
  res.status(500).json({
    error: 'Internal server error',
    message: 'An unexpected error occurred',
    requestId: req.headers['x-request-id'] || 'N/A'
  });
});

// Start server
const server = app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📡 Health check: http://localhost:${PORT}/api/health`);
  console.log(`📧 Contact form: POST http://localhost:${PORT}/api/contact`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    console.log('Server closed');
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  server.close(() => {
    console.log('Server closed');
  });
});

module.exports = app;