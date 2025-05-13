// Sample JavaScript file with vulnerabilities

const express = require('express');
const mysql = require('mysql');
const router = express.Router();

// Create a MySQL connection
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'hardcoded_password',  // Hardcoded credentials vulnerability
  database: 'mydb'
});

connection.connect();

// SQL Injection vulnerability
router.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  const query = {
    sql: "SELECT * FROM users WHERE id=" + userId  // SQL Injection vulnerability
  };
  connection.query(query, (err, result) => {
    res.json(result);
  });
});

// Another SQL Injection vulnerability
router.get('/search', (req, res) => {
  const searchTerm = req.query.term;
  connection.query("SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'", (err, result) => {  // SQL Injection vulnerability
    res.json(result);
  });
});

// XSS vulnerability
router.get('/profile', (req, res) => {
  const username = req.query.username;
  res.send(`<h1>Welcome, ${username}!</h1>`);  // XSS vulnerability
});

// Eval vulnerability
router.get('/calculate', (req, res) => {
  const expression = req.query.expr;
  const result = eval(expression);  // Eval vulnerability
  res.send(`Result: ${result}`);
});

module.exports = router;
