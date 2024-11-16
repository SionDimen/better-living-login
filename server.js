require('dotenv').config();
const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const session = require('express-session');
const crypto = require('crypto');

const app = express();

// 1. Static files middleware
app.use(express.static('public'));

// 2. Session middleware with cookie settings
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: false, 
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// 3. Database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// 4. Webhook route 
app.post('/webhook', express.raw({type: 'application/json'}), async (req, res) => {
    console.log('Webhook received at:', new Date().toISOString());
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
                // Test email configuration
                console.log('Email configuration:', {
                    user: process.env.EMAIL_USER,
                    // Don't log the actual password
                    hasPassword: !!process.env.EMAIL_APP_PASSWORD
                });

                console.log('Generating password');
                const password = generateStrongPassword(12);
                console.log('Password generated successfully');

                const hashedPassword = await bcrypt.hash(password, 10);
                console.log('Password hashed successfully');

                console.log('Saving to database...');
                await pool.query(
                    'INSERT INTO users (email, password) VALUES ($1, $2)',
                    [customerEmail, hashedPassword]
                );
                console.log('User saved to database successfully');

                console.log('Creating email transporter...');
                const transporter = nodemailer.createTransport({
                    service: 'gmail',
                    auth: {
                        user: process.env.EMAIL_USER,
                        pass: process.env.EMAIL_APP_PASSWORD
                    }
                });

                console.log('Sending email...');
                const emailResult = await transporter.sendMail({
                    from: process.env.EMAIL_USER,
                    to: customerEmail,
                    subject: 'Your Login Credentials',
                    html: `
                        <h1>Welcome to Better Living Co.!</h1>
                        <p>Thank you for your purchase! Here are your login credentials:</p>
                        <p><strong>Email:</strong> ${customerEmail}</p>
                        <p><strong>Password:</strong> ${password}</p>
                        <p>Please login at: ${process.env.SITE_URL}</p>
                        <p>We recommend changing your password after your first login.</p>
                        <br>
                        <p>Best regards,</p>
                        <p>Better Living Co. Team</p>
                    `
                });
                console.log('Email sent successfully:', emailResult);
            } catch (error) {
                console.error('Detailed error:', {
                    message: error.message,
                    stack: error.stack,
                    code: error.code
                });
                throw error;
            }
        }
        res.json({received: true});
    } catch (err) {
        console.error('Webhook Error:', {
            message: err.message,
            stack: err.stack,
            code: err.code
        });
        res.status(400).send(`Webhook Error: ${err.message}`);
    }
});

// 5. Body parsers for other routes
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));

// 6. Initialize database
async function initDatabase() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                reset_token VARCHAR(255),
                reset_token_expires TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('Database initialized successfully');
    } catch (error) {
        console.error('Database initialization error:', error);
    }
}

initDatabase();

// 7. Login protection middleware
const requireLogin = (req, res, next) => {
    if (req.session.userId) {
        next();
    } else {
        res.status(401).json({ success: false, message: 'Please log in' });
    }
};

// 8. Authentication Routes
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log('Login attempt for:', email);

        const result = await pool.query(
            'SELECT * FROM users WHERE email = $1',
            [email]
        );
        console.log('Found user:', result.rows.length > 0);

        if (result.rows.length > 0) {
            const user = result.rows[0];
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

app.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        
        const result = await pool.query(
            'SELECT id FROM users WHERE email = $1',
            [email]
        );

        if (result.rows.length > 0) {
            const resetToken = crypto.randomBytes(32).toString('hex');
            const tokenExpiry = new Date(Date.now() + 3600000); // 1 hour

            await pool.query(
                'UPDATE users SET reset_token = $1, reset_token_expires = $2 WHERE email = $3',
                [resetToken, tokenExpiry, email]
            );

            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_APP_PASSWORD
                }
            });

            await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: email,
                subject: 'Password Reset Request',
                html: `
                    <p>You requested a password reset.</p>
                    <p>Click this link to reset your password:</p>
                    <a href="${process.env.SITE_URL}/reset-password?token=${resetToken}">
                        Reset Password
                    </a>
                    <p>This link will expire in 1 hour.</p>
                `
            });
        }

        res.json({ success: true, message: 'If an account exists, you will receive reset instructions.' });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// 9. Password Reset Routes
app.get('/reset-password', async (req, res) => {
    const { token } = req.query;

    const result = await pool.query(
        'SELECT * FROM users WHERE reset_token = $1 AND reset_token_expires > NOW()',
        [token]
    );

    if (result.rows.length === 0) {
        return res.send('Invalid or expired reset token');
    }
    res.sendFile(__dirname + '/public/reset-password.html');
});

app.post('/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;

    try {
        const result = await pool.query(
            'SELECT * FROM users WHERE reset_token = $1 AND reset_token_expires > NOW()',
            [token]
        );

        if (result.rows.length === 0) {
            return res.json({ 
                success: false, 
                message: 'Invalid or expired reset token' 
            });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await pool.query(
            'UPDATE users SET password = $1, reset_token = NULL, reset_token_expires = NULL WHERE id = $2',
            [hashedPassword, result.rows[0].id]
        );

        res.json({ success: true, message: 'Password updated successfully' });
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// 10. User Management Routes
app.post('/change-password', requireLogin, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        
        const result = await pool.query(
            'SELECT password FROM users WHERE id = $1',
            [req.session.userId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }

        const match = await bcrypt.compare(currentPassword, result.rows[0].password);
        if (!match) {
            return res.status(401).json({ 
                success: false, 
                message: 'Current password is incorrect' 
            });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await pool.query(
            'UPDATE users SET password = $1 WHERE id = $2',
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

app.get('/user-data', requireLogin, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT email, created_at FROM users WHERE id = $1',
            [req.session.userId]
        );
        
        if (result.rows.length > 0) {
            res.json(result.rows[0]);
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    } catch (error) {
        console.error('Error fetching user data:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// 11. Static Page Routes
app.get('/terms', (req, res) => {
    res.sendFile(__dirname + '/public/terms.html');
});

app.get('/privacy', (req, res) => {
    res.sendFile(__dirname + '/public/privacy.html');
});

app.get('/dashboard', requireLogin, (req, res) => {
    res.sendFile(__dirname + '/public/dashboard.html');
});

app.get('/courses', requireLogin, (req, res) => {
    try {

        console.log('Attempting to serve courses page');
        
        const coursesPath = __dirname + '/public/courses.html';
        if (!require('fs').existsSync(coursesPath)) {
            console.error('Courses file not found at:', coursesPath);
            return res.status(404).json({ success: false, message: 'Courses page not found' });
        }
        
        res.sendFile(coursesPath);
    } catch (error) {
        console.error('Error serving courses page:', error);
        res.status(500).json({ success: false, message: 'Error loading courses page' });
    }
});

// 12. Session Management Routes
app.get('/check-session', requireLogin, (req, res) => {
    res.json({ authenticated: true });
});

app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).json({ 
                success: false, 
                message: 'Error during logout' 
            });
        }
        res.json({ success: true });
    });
});

// 13. Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ 
        success: false, 
        message: 'An unexpected error occurred' 
    });
});

// 14. Start server
const port = process.env.PORT || 3000;
app.listen(port, '0.0.0.0', () => {
    console.log(`Server running on port ${port}`);
});