<?php
// Sample PHP file with vulnerabilities

// Hardcoded credentials vulnerability
$password = "hardcoded_password";

// Database connection
$conn = mysqli_connect("localhost", "root", $password, "mydb");

// SQL Injection vulnerability
$userId = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $userId;  // SQL Injection
$result = mysqli_query($conn, $query);

// Another SQL Injection vulnerability
$searchTerm = $_POST['search'];
$result = $conn->query("SELECT * FROM products WHERE name LIKE '%" . $searchTerm . "%'");  // SQL Injection

// XSS vulnerability
$username = $_GET['username'];
echo "Welcome, " . $username;  // XSS vulnerability

// Command injection vulnerability
$command = $_GET['cmd'];
system("ls " . $command);  // Command injection

// File inclusion vulnerability
$page = $_GET['page'];
include($page . ".php");  // File inclusion vulnerability

// File upload vulnerability
if (isset($_FILES['file'])) {
    $filename = $_FILES['file']['name'];
    move_uploaded_file($_FILES['file']['tmp_name'], "uploads/" . $filename);  // Insecure file upload
}

// Unvalidated redirect
$url = $_GET['url'];
header("Location: " . $url);  // Unvalidated redirect
?>
