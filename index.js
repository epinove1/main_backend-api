const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const pool = new Pool(); // .env used

app.use(express.json());

// Get route
app.get("/", (req, res) => {
  res.send("🎉 API is up and running on Render!");
});

// Signup route
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  await pool.query('INSERT INTO users (email, password) VALUES ($1, $2)', [email, hash]);
  console.log("Signup hit!", req.body);
  res.send('User created');
});

// Login route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = result.rows[0];
  if (!user) return res.status(401).send('User not found');

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).send('Invalid password');

  const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET);
  res.json({ token });
});

app.listen(3000, () => console.log('Server running on port 3000'));
