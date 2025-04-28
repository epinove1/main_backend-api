const express = require('express');
const cors = require("cors");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const pool = new Pool(); // .env used

app.use(cors());
app.use(express.json());

// Get route
app.get("/", (req, res) => {
  res.send("🎉 API is up and running on Render!");
});

app.post('/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password, requestDescription } = req.body;
    const hash = await bcrypt.hash(password, 10);

      // --- 🛡️ VALIDATE FIELDS HERE ---
  if (!firstName || !lastName || !email || !password || !requestDescription) {
    return res.status(400).send('First name, last name, email, and password are required');
  }

    await pool.query(
      "INSERT INTO dxusers (us1_firstname, us1_lastname, us1_email, us1_password, us1_requestDescription,us1_accountstatus) VALUES ($1, $2, $3, $4, $5, 'Requested')",
      [firstName, lastName, email, hash, requestDescription]
    );

    console.log('✅ User created:', email);
    res.send('User created');
  } catch (err) {
    console.error('❌ Signup error:', err.message);
    res.status(500).send('Internal Server Error');
  }
});

// Login route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query("SELECT * FROM dxusers WHERE us1_email = $1 AND us1_accountstatus = 'Active'", [email]);
  const user = result.rows[0];
  if (!user) return res.status(401).send('User not found');

  const valid = await bcrypt.compare(password, user.us1_password);
  if (!valid) return res.status(401).send('Invalid password');

  const token = jwt.sign({ id: user.us1_id }, process.env.JWT_SECRET);
  res.json({ token });
});

app.listen(3000, () => console.log('Server running on port 3000'));
