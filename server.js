require('dotenv').config();
const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const mysql = require('mysql2/promise');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const getRawBody = require('raw-body');
const session = require('express-session');  // Add this line
const app = express();

// Middleware
app.use(express.static('public'));
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true
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
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    connectTimeout: 60000
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log('Login attempt for:', email); // Add logging

        const [rows] = await pool.execute(
            'SELECT * FROM users WHERE email = ?',
            [email]
        );
        console.log('Found user:', rows.length > 0); // Add logging

        if (rows.length > 0) {
            const user = rows[0];
            const match = await bcrypt.compare(password, user.password);
            console.log('Password match:', match); // Add logging

            if (match) {
                req.session.userId = user.id;
                res.json({ success: true });
            } else {
                res.status(401).json({ success: false, message: 'Invalid credentials' });
            }
        } else {
            res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
    } catch (error) {
        console.error('Login error:', error); // Add logging
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
    console.log('Webhook received');
    const sig = req.headers['stripe-signature'];
    let event;

    try {
        console.log('Verifying webhook signature');
        event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
        console.log('Webhook verified:', event.type);

        if (event.type === 'checkout.session.completed') {
            const session = event.data.object;
            // Get email from customer_details instead of customer_email
            const customerEmail = session.customer_details.email;
            console.log('Processing payment for:', customerEmail);
            
            try {
                console.log('Generating password');
                const password = Math.random().toString(36).slice(-8);
                const hashedPassword = await bcrypt.hash(password, 10);

                console.log('Connecting to database');
                await pool.execute(
                    'INSERT INTO users (email, password) VALUES (?, ?)',
                    [customerEmail, hashedPassword]
                );
                console.log('User saved to database');

                console.log('Setting up email transport');
                const transporter = nodemailer.createTransport({
                    service: 'gmail',
                    auth: {
                        user: process.env.EMAIL_USER,
                        pass: process.env.EMAIL_APP_PASSWORD
                    }
                });

                console.log('Sending email');
                await transporter.sendMail({
                    from: process.env.EMAIL_USER,
                    to: customerEmail,
                    subject: 'Your Login Credentials',
                    text: `Thank you for your purchase! Here are your login credentials:\n\nEmail: ${customerEmail}\nPassword: ${password}\n\nPlease login at: https://better-living-login.onrender.com`
                });
                console.log('Email sent successfully');

                console.log('Payment processed successfully');
            } catch (error) {
                console.error('Error details:', error);
                console.error('Error processing payment:', error);
                throw error;
            }
        }

        res.json({received: true});
    } catch (err) {
        console.error('Full error details:', err);
        console.error('Webhook Error:', err.message);
        res.status(400).send(`Webhook Error: ${err.message}`);
    }
});


const port = process.env.PORT || 3000;
app.listen(port, '0.0.0.0', () => {
    console.log(`Server running on port ${port}`);
});