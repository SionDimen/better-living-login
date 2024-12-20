require('dotenv').config();
const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const session = require('express-session');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

function generateStrongPassword(length = 12) {
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const numbers = '0123456789';
    const all = uppercase + lowercase + numbers;
    
    let password = '';
    // Ensure at least one of each character type
    password += uppercase[Math.floor(Math.random() * uppercase.length)];
    password += lowercase[Math.floor(Math.random() * lowercase.length)];
    password += numbers[Math.floor(Math.random() * numbers.length)];
    
    // Fill the rest of the password
    for (let i = password.length; i < length; i++) {
        password += all[Math.floor(Math.random() * all.length)];
    }
    
    // Shuffle the password
    return password.split('').sort(() => Math.random() - 0.5).join('');
}

const app = express();

// Essential middleware
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Session middleware
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
    cookie: { 
        secure: false,
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: true,
        sameSite: 'lax'
    },
    rolling: true
}));

// Single auth middleware declaration
const requireAuth = (req, res, next) => {
    if (!req.session || !req.session.userId) {
        return res.redirect('/');
    }
    next();
};

// Apply course protection
app.use('/courses/*', requireAuth);

// Static files
app.use(express.static('public'));

function validatePassword(password) {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    const errors = [];
    
    if (password.length < minLength) {
        errors.push(`Password must be at least ${minLength} characters long`);
    }
    if (!hasUpperCase) {
        errors.push('Password must contain at least one uppercase letter');
    }
    if (!hasLowerCase) {
        errors.push('Password must contain at least one lowercase letter');
    }
    if (!hasNumbers) {
        errors.push('Password must contain at least one number');
    }
    if (!hasSpecialChar) {
        errors.push('Password must contain at least one special character');
    }

    return {
        isValid: errors.length === 0,
        errors: errors
    };
}

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

// 6. Initialize database
async function initDatabase() {
    try {
        // Create users table if it doesn't exist
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
        console.log('Base table initialized successfully');

        // Add 2FA columns if they don't exist
        await pool.query(`
            ALTER TABLE users 
            ADD COLUMN IF NOT EXISTS two_factor_enabled BOOLEAN DEFAULT FALSE,
            ADD COLUMN IF NOT EXISTS two_factor_secret VARCHAR(255)
        `);
        console.log('2FA columns initialized successfully');
    } catch (error) {
        console.error('Database initialization error:', error);
    }
}

initDatabase();

// 7. Login protection middleware
const requireLogin = (req, res, next) => {
    console.log('Session in requireLogin:', req.session);
    console.log('UserId in session:', req.session.userId);
    
    if (req.session.userId) {
        next();
    } else {
        console.log('No userId in session - redirecting to login');
        if (req.xhr || req.headers.accept.indexOf('json') > -1) {
            res.status(401).json({ success: false, message: 'Please log in' });
        } else {
            res.redirect('/');
        }
    }
};

// 8. Authentication Routes
app.post('/login', async (req, res) => {
    try {
        const { email, password, token, rememberMe } = req.body;  // Add rememberMe here
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
                // Check if 2FA is enabled
                if (user.two_factor_enabled) {
                    if (!token) {
                        return res.json({ 
                            success: false, 
                            need2FA: true 
                        });
                    }

                    const verified = speakeasy.totp.verify({
                        secret: user.two_factor_secret,
                        encoding: 'base32',
                        token: token
                    });

                    if (!verified) {
                        return res.status(401).json({ 
                            success: false, 
                            message: 'Invalid 2FA code' 
                        });
                    }
                }

                // Set session
                req.session.userId = user.id;
                
                // Add this block for Remember Me
                if (rememberMe) {
                    req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days
                } else {
                    req.session.cookie.expires = false; // Session cookie
                }

                await new Promise((resolve, reject) => {
                    req.session.save((err) => {
                        if (err) {
                            console.error('Session save error:', err);
                            reject(err);
                        } else {
                            resolve();
                        }
                    });
                });

                res.json({ 
                    success: true,
                    redirectUrl: '/dashboard'
                });
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

// 2FA Routes
app.get('/user-2fa-status', requireLogin, async (req, res) => {
    try {
        console.log('Checking 2FA status for user:', req.session.userId);
        const result = await pool.query(
            'SELECT two_factor_enabled FROM users WHERE id = $1',
            [req.session.userId]
        );
        console.log('2FA status result:', result.rows[0]);
        
        res.json({
            enabled: result.rows[0]?.two_factor_enabled || false
        });
    } catch (error) {
        console.error('Error checking 2FA status:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/enable-2fa', requireLogin, async (req, res) => {
    try {
        // Generate secret
        const secret = speakeasy.generateSecret({
            name: "Better Living Co."
        });

        // Save secret to database
        await pool.query(
            'UPDATE users SET two_factor_secret = $1 WHERE id = $2',
            [secret.base32, req.session.userId]
        );

        // Generate QR code
        const qrCode = await QRCode.toDataURL(secret.otpauth_url);

        res.json({
            success: true,
            qrCode: qrCode,
            secret: secret.base32
        });
    } catch (error) {
        console.error('2FA Enable Error:', error);
        res.status(500).json({ success: false, message: 'Error enabling 2FA' });
    }
});

app.post('/verify-2fa', requireLogin, async (req, res) => {
    try {
        const { token } = req.body;
        
        // Get user's secret
        const result = await pool.query(
            'SELECT two_factor_secret FROM users WHERE id = $1',
            [req.session.userId]
        );

        const verified = speakeasy.totp.verify({
            secret: result.rows[0].two_factor_secret,
            encoding: 'base32',
            token: token
        });

        if (verified) {
            await pool.query(
                'UPDATE users SET two_factor_enabled = true WHERE id = $1',
                [req.session.userId]
            );
            res.json({ success: true });
        } else {
            res.status(400).json({ success: false, message: 'Invalid code' });
        }
    } catch (error) {
        console.error('2FA Verification Error:', error);
        res.status(500).json({ success: false, message: 'Error verifying 2FA' });
    }
});

app.post('/disable-2fa', requireLogin, async (req, res) => {
    try {
        await pool.query(
            'UPDATE users SET two_factor_enabled = false, two_factor_secret = null WHERE id = $1',
            [req.session.userId]
        );
        res.json({ success: true });
    } catch (error) {
        console.error('2FA Disable Error:', error);
        res.status(500).json({ success: false, message: 'Error disabling 2FA' });
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
app.post('/refresh-session', async (req, res) => {
    if (req.session.userId) {
        // Extend the session
        req.session.touch();
        res.json({ success: true });
    } else {
        res.status(401).json({ success: false });
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
        // Validate new password
        const validation = validatePassword(newPassword);
        if (!validation.isValid) {
            return res.status(400).json({ 
                success: false, 
                message: 'Password requirements not met',
                errors: validation.errors
            });
        }

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
        
        const validation = validatePassword(newPassword);
        if (!validation.isValid) {
            return res.status(400).json({ 
                success: false, 
                message: 'Password requirements not met',
                errors: validation.errors
            });
        }

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
    console.log('Accessing dashboard. Session:', req.session);
    res.sendFile(__dirname + '/public/dashboard.html');
});

// Apply authentication check to all routes under /courses
app.use('/courses/*', requireAuth);

app.get('/courses/:courseName', requireAuth, (req, res) => {
    try {
        const courseName = req.params.courseName;
        const coursePath = __dirname + `/public/courses/${courseName}.html`;
        
        console.log('Attempting to serve course:', courseName);
        console.log('Full course path:', coursePath);
        
        // Check if file exists with more detailed logging
        const fs = require('fs');
        if (!fs.existsSync(coursePath)) {
            console.error('Course file not found:', coursePath);
            return res.status(404).json({ 
                success: false, 
                message: 'Course not found',
                path: coursePath 
            });
        }
        
        // Log successful file find
        console.log('Course file found, attempting to send...');
        
        res.sendFile(coursePath, (err) => {
            if (err) {
                console.error('Error sending file:', err);
                res.status(500).json({ 
                    success: false, 
                    message: 'Error sending course file',
                    error: err.message 
                });
            } else {
                console.log('File sent successfully');
            }
        });
        
    } catch (error) {
        console.error('Detailed error in course route:', {
            message: error.message,
            stack: error.stack,
            code: error.code
        });
        res.status(500).json({ 
            success: false, 
            message: 'Error loading course page',
            error: error.message 
        });
    }
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
    console.error('Error:', err);
    if (err.name === 'TokenExpiredError') {
        // Handle session expiration gracefully
        res.status(440).json({ 
            success: false, 
            message: 'Session expired', 
            shouldReconnect: true 
        });
    } else {
        res.status(500).json({ 
            success: false, 
            message: 'An unexpected error occurred' 
        });
    }
});

// 14. Start server
const port = process.env.PORT || 3000;
app.listen(port, '0.0.0.0', () => {
    console.log(`Server running on port ${port}`);
});