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
        event = stripe.webhooks.constructEvent(
            req.body,
            sig,
            process.env.STRIPE_WEBHOOK_SECRET
        );
        console.log('Webhook signature verification successful!');
    } catch (err) {
        console.error('Webhook Error:', err.message);
        console.log('Signature received:', sig);
        console.log('Webhook secret used:', process.env.STRIPE_WEBHOOK_SECRET);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        const customerEmail = session.customer_details.email;
        
        try {
            // Generate password
            const password = generatePassword();

            // Save to database
            await pool.execute(
                'INSERT INTO users (email, password) VALUES (?, ?)',
                [customerEmail, password]
            );

            // Send email
            await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: customerEmail,
                subject: 'Your Login Credentials for BetterLiving',
                html: `
                    <h2>Thank you for your purchase!</h2>
                    <p>Your login credentials are:</p>
                    <p><strong>Email:</strong> ${customerEmail}</p>
                    <p><strong>Password:</strong> ${password}</p>
                    <p>You can login at: <a href="YOUR_LOGIN_PAGE_URL">Click here to login</a></p>
                `
            });

        } catch (error) {
            console.error('Error processing payment:', error);
        }
    }

    res.json({ received: true });
});

// Use JSON parsing for all other routes
app.use(express.json());

// Generate random password
function generatePassword() {
    return Math.random().toString(36).slice(-8);
}

app.listen(3000, () => console.log('Server running on port 3000'));