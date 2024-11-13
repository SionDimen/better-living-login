require('dotenv').config();
const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const mysql = require('mysql2/promise');
const nodemailer = require('nodemailer');
const getRawBody = require('raw-body');
const session = require('express-session');  // Add this line
const app = express();

// Add session middleware
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false
}));

// Serve static files (create a 'public' folder for your HTML/CSS/JS files)
app.use(express.static('public'));

// Email configuration
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_APP_PASSWORD
    }
});

// Database connection
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
});

// Add these new endpoints before your webhook endpoint
app.post('/login', express.json(), async (req, res) => {
    const { email, password } = req.body;
    
    try {
        const [rows] = await pool.execute(
            'SELECT * FROM users WHERE email = ? AND password = ?',
            [email, password]
        );

        if (rows.length > 0) {
            req.session.user = { email: rows[0].email };
            res.json({ success: true });
        } else {
            res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/protected-content', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: 'Please log in' });
    }
    res.json({ success: true, content: 'This is protected content' });
});

app.post('/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// Use raw body for webhook endpoint
app.post('/webhook', express.raw({type: 'application/json'}), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
        event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
        console.log('Webhook verified:', event.type);

        if (event.type === 'checkout.session.completed') {
            const session = event.data.object;
            console.log('Processing payment for:', session.customer_email);
            
            try {
                // Generate a random password
                const password = Math.random().toString(36).slice(-8);
                const hashedPassword = await bcrypt.hash(password, 10);

                // Save user to database
                await pool.execute(
                    'INSERT INTO users (email, password) VALUES (?, ?)',
                    [session.customer_email, hashedPassword]
                );

                // Send email with credentials
                const transporter = nodemailer.createTransport({
                    service: 'gmail',
                    auth: {
                        user: process.env.EMAIL_USER,
                        pass: process.env.EMAIL_APP_PASSWORD
                    }
                });

                await transporter.sendMail({
                    from: process.env.EMAIL_USER,
                    to: session.customer_email,
                    subject: 'Your Login Credentials',
                    text: `Thank you for your purchase! Here are your login credentials:\n\nEmail: ${session.customer_email}\nPassword: ${password}\n\nPlease login at: https://better-living-login.onrender.com`
                });

                console.log('Payment processed successfully');
            } catch (error) {
                console.error('Error processing payment:', error);
                throw error;
            }
        }

        res.json({received: true});
    } catch (err) {
        console.error('Webhook Error:', err.message);
        res.status(400).send(`Webhook Error: ${err.message}`);
    }
});

const port = process.env.PORT || 3000;
app.listen(port, '0.0.0.0', () => {
    console.log(`Server running on port ${port}`);
});