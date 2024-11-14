require('dotenv').config();
const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const mysql = require('mysql2/promise');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const session = require('express-session');

const app = express();

// 1. Static files middleware
app.use(express.static('public'));

// 2. Session middleware with cookie settings
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: false, // set to true if using https
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// 3. Webhook route (MUST come before body parsers)
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

// 4. Body parsers for other routes
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));

// 5. Database connection
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

// 6. Login protection middleware
const requireLogin = (req, res, next) => {
    if (req.session.userId) {
        next();
    } else {
        res.status(401).json({ success: false, message: 'Please log in' });
    }
};

// 7. Routes
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log('Login attempt for:', email);

        const [rows] = await pool.execute(
            'SELECT * FROM users WHERE email = ?',
            [email]
        );
        console.log('Found user:', rows.length > 0);

        if (rows.length > 0) {
            const user = rows[0];
            const match = await bcrypt.compare(password, user.password);
            console.log('Password match:', match);

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
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/dashboard', requireLogin, (req, res) => {
    res.sendFile(__dirname + '/public/dashboard.html');
});

app.get('/check-session', requireLogin, (req, res) => {
    res.json({ authenticated: true });
});

app.post('/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

app.get('/user-data', requireLogin, async (req, res) => {
    try {
        const [rows] = await pool.execute(
            'SELECT email, created_at FROM users WHERE id = ?',
            [req.session.userId]
        );
        
        if (rows.length > 0) {
            res.json(rows[0]);
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    } catch (error) {
        console.error('Error fetching user data:', error);
        res.status(500).json({ error: 'Server error' });
    }
}); 

app.post('/change-password', requireLogin, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        
        // Get user's current password from database
        const [rows] = await pool.execute(
            'SELECT password FROM users WHERE id = ?',
            [req.session.userId]
        );

        if (rows.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }

        // Verify current password
        const match = await bcrypt.compare(currentPassword, rows[0].password);
        if (!match) {
            return res.status(401).json({ 
                success: false, 
                message: 'Current password is incorrect' 
            });
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update password in database
        await pool.execute(
            'UPDATE users SET password = ? WHERE id = ?',
            [hashedPassword, req.session.userId]
        );

        res.json({ 
            success: true, 
            message: 'Password updated successfully' 
        });
    } catch (error) {
        console.error('Error changing password:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error' 
        });
    }
});

// 8. Start server
const port = process.env.PORT || 3000;
app.listen(port, '0.0.0.0', () => {
    console.log(`Server running on port ${port}`);
});