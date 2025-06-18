const express = require('express');
const cors = require('cors');
const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Test route
app.get('/', (req, res) => {
    res.send('Hello from backend!');
});

// Contact route (example)
app.post('/contact', (req, res) => {
    console.log('Data received:', req.body);
    res.json({ message: 'Form submitted successfully!' });
});

// Start server
app.listen(3000, () => {
    console.log('Server running at http://localhost:3000');
});
