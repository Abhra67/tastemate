const express = require('express');
 require('dotenv').config();
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

const app = express();
const port = process.env.PORT ||3000;

// Allow cross-origin requests (make sure to change the origin to match your frontend URL)
app.use(cors({
  origin: process.env.ORIGIN, // Replace with your frontend origin
  methods: ['GET', 'POST'], // Specify allowed HTTP methods
  allowedHeaders: ['Content-Type'], // Specify allowed headers
}));

// Middleware
app.use(bodyParser.json()); // Enable JSON parsing

// MySQL connection
const db = mysql.createConnection({
  host: process.env.host,
  user: process.env.user,
  password: process.env.password,
  database: process.env.database,
});

db.connect((err) => {
  if (err) throw err;
  console.log('Database connected!');
});

// Signup Route
app.post(
  '/signup',
  [
    body('name').notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Valid email is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password, role } = req.body; // role can be 'student' or 'admin'

    try {
      // Check if the email already exists
      const queryCheckEmail = 'SELECT * FROM users WHERE email = ?';
      db.query(queryCheckEmail, [email], (err, results) => {
        if (err) {
          return res.status(500).json({ success: false, message: 'Database error' });
        }

        if (results.length > 0) {
          return res.status(400).json({ success: false, message: 'Email is already registered' });
        }

        // Hash the password
        bcrypt.hash(password, 10, (err, hashedPassword) => {
          if (err) {
            return res.status(500).json({ success: false, message: 'Error hashing password' });
          }

          // Insert user into the database
          const query = 'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)';
          db.query(query, [name, email, hashedPassword, role || 'student'], (err) => {
            if (err) {
              console.error(err);
              return res.status(500).json({ success: false, message: 'Error saving user to database' });
            }
            res.status(201).json({ success: true, message: 'User registered successfully' });
          });
        });
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ success: false, message: 'Server error' });
    }
  }
);

app.get('/users/:email', async (req, res) => {
  const userEmail = req.params.email; // Get the email from the route parameter
  
  try {
    const query = 'SELECT name,role, email, id FROM users WHERE email = ?'; // Use a parameterized query to find the user by email
    db.query(query, [userEmail], (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }

      if (results.length === 0) { // If no user is found with the provided email
        return res.status(404).json({ success: false, message: 'User not found' });
      }

      res.status(200).json({ success: true, data: results[0] }); // Return the first (and only) result
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});




// Login Route
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Database error' });
    }

    if (results.length === 0) {
      return res.status(400).json({ message: 'User not found' });
    }

    const user = results[0];

    // Compare password with the stored hashed password
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        return res.status(500).json({ message: 'Error comparing password' });
      }

      if (isMatch) {
        // Password is correct, create a JWT token
        const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, 'your_jwt_secret_key', { expiresIn: '1h' });

        return res.status(200).json({ message: 'Login successful', token });
      } else {
        return res.status(400).json({ message: 'Incorrect password' });
      }
    });
  });
});

// Register Exam Route (New)
app.post('/registerExam', (req, res) => {
  const { fatherName, birthDate, motherName, universityName, examChoice, userId } = req.body;

  // Fetch user details from the users table using userId
  const userQuery = 'SELECT name, email FROM users WHERE id = ?';
  db.query(userQuery, [userId], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: 'Error fetching user details' });
    }

    if (results.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const { name, email } = results[0]; // Extract user details

    // Insert the registration data into the students table, including the user_id
    const query = 'INSERT INTO students (name, email, father_name, birth_date, mother_name, university_name, exam_choice, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
    db.query(query, [name, email, fatherName, birthDate, motherName, universityName, examChoice, userId], (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: 'Error registering for exam' });
      }
      
      console.log("Registration successful");
      res.status(201).json({ 
        success: true, 
        message: 'Successfully registered for the exam'
      });
    });
  });
});

app.get('/students', (req, res) => {
  // Query to fetch all registered students from the 'students' table
  const query = 'SELECT id, name, email, father_name, birth_date, mother_name, university_name, exam_choice, registration_date ,approved FROM students';
  
  db.query(query, (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: 'Error fetching students' });
    }

    if (results.length === 0) {
      return res.status(404).json({ success: false, message: 'No students found' });
    }

    // Send the list of students to the admin panel
    res.status(200).json({
      success: true,
      message: 'Successfully fetched all registered students',
      students: results
    });
  });
});
// Route to toggle the 'approved' status for a student and send an email
app.post('/approve/:id', (req, res) => {
  const studentId = req.params.id;

  // SQL query to toggle the 'approved' field
  const query = 'UPDATE students SET approved = NOT approved WHERE id = ?';

  db.query(query, [studentId], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ success: false, message: 'Error toggling approval status' });
    }

    if (results.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Student not found' });
    }

    // Get the student's details to send an email
    const getStudentQuery = 'SELECT name, email, approved FROM students WHERE id = ?';
    
    db.query(getStudentQuery, [studentId], (err, studentResults) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ success: false, message: 'Error fetching student details' });
      }

      const student = studentResults[0];
      const approvalStatus = student.approved === 1 ? 'approved' : 'disapproved';

      // Send an email notification to the student
      const mailOptions = {
        from: 'abhrakanti708@gmail.com',  // sender's email
        to: student.email,  // recipient's email
        subject: 'Your Exam Registration Status',
        text: `Dear ${student.name},\n\nYour registration for the exam has been ${approvalStatus}.\n\nBest regards,\nAdmin Team`
      };

      // Send the email
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error(error);
          return res.status(500).json({ success: false, message: 'Error sending email' });
        }

        // Respond with success
        res.status(200).json({ success: true, message: 'Approval status toggled and email sent' });
      });
    });
  });
});
// Set up the Nodemailer transport
const transporter = nodemailer.createTransport({
  service: 'gmail', // You can change the email service provider, like 'yahoo', etc.
  auth: {
    user: 'abhrakanti708@gmail.com', // Replace with your email address
    pass: 'vxze bifz qrqs aaqc',  // Replace with your email password or an App password
  },
});

// Endpoint to send email
app.post('/sendEmail', (req, res) => {
  const { email, subject, message } = req.body; // Assume you're sending these details in the request body

  // Define the email options
  const mailOptions = {
    from: 'abhrakanti708@gmail.com', // Replace with your email address
    to: email, // Recipient's email address
    subject: subject || 'Default Subject', // Default subject if not provided
    text: message || 'Default message body', // Default message if not provided
  };

  // Send the email
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log(error);
      return res.status(500).json({ success: false, message: 'Failed to send email' });
    }
    console.log('Email sent: ' + info.response);
    return res.status(200).json({ success: true, message: 'Email sent successfully' });
  });
});



// Start server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
