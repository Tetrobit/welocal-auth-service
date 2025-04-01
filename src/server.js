require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// In-memory user storage (replace with database in production)
const users = [];

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'your-refresh-secret-key';

// Authentication Routes
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check if user already exists
        if (users.find(user => user.email === email)) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user
        const user = {
            id: users.length + 1,
            email,
            password: hashedPassword
        };

        users.push(user);

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error registering user' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user
        const user = users.find(user => user.email === email);
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Verify password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Generate tokens
        const accessToken = jwt.sign(
            { userId: user.id, email: user.email },
            JWT_SECRET,
            { expiresIn: '15m' }
        );

        const refreshToken = jwt.sign(
            { userId: user.id, email: user.email },
            JWT_REFRESH_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            accessToken,
            refreshToken
        });
    } catch (error) {
        res.status(500).json({ message: 'Error logging in' });
    }
});

app.post('/api/auth/refresh-token', (req, res) => {
    try {
        const { refreshToken } = req.body;

        if (!refreshToken) {
            return res.status(401).json({ message: 'Refresh token required' });
        }

        // Verify refresh token
        const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET);

        // Generate new access token
        const accessToken = jwt.sign(
            { userId: decoded.userId, email: decoded.email },
            JWT_SECRET,
            { expiresIn: '15m' }
        );

        res.json({ accessToken });
    } catch (error) {
        res.status(401).json({ message: 'Invalid refresh token' });
    }
});

// Protected route example
app.get('/api/protected', authenticateToken, (req, res) => {
    res.json({ message: 'This is a protected route', user: req.user });
});

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid access token' });
        }
        req.user = user;
        next();
    });
}

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
}); 