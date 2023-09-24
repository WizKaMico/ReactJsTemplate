const express = require('express');
const app = express();
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const port = process.env.PORT || 3001;
const mysql = require('mysql');
const session = require('express-session');
const crypto = require('crypto');
const cors = require('cors');
const cookieParser = require('cookie-parser');

app.use(
  cors({
    origin: ['http://localhost:3000'],
    methods: ['GET', 'POST'],
    credentials: true,
  })
);

app.use(cookieParser());

app.use(
  session({
    key: 'uid',
    secret: '@Light101213',
    resave: false,
    saveUninitialized: false,
    cookie: {
      expires: 60 * 60 * 24,
      domain: 'localhost', // Set the domain to the appropriate value
      path: '/', // Set the path to the appropriate value
    },
  })
);

app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'react_template',
});

db.connect((err) => {
  if (err) {
    console.error('Database connection error: ' + err.message);
  } else {
    console.log('Connected to the database ' + db);
  }
});

function generateRandomCode() {
  return Math.floor(1000 + Math.random() * 9000);
}

app.post('/login', (req, res) => {
  const { uid, password } = req.body;

  // Hash the provided password with MD5
  const hashedPassword = crypto.createHash('md5').update(password).digest('hex');

  // Generate a random 4-digit code
  const code = generateRandomCode();

  // Replace 'user_login' with your actual user table name and 'user_security' with your security table name
  const selectUserQuery = `SELECT * FROM user_login WHERE uid = ? AND password = ?`;
  const insertCodeQuery = `INSERT INTO user_security (uid, code, status, date_created) VALUES (?, ?, 'UNUSED', NOW())`;

  db.query(selectUserQuery, [uid, hashedPassword], (err, results) => {
    if (err) {
      console.error('Database query error: ' + err.message);
      return res.status(500).send('Internal Server Error');
    }

    if (results.length === 1) {
      // User found, retrieve the user's email
      const userEmail = results[0].email;

      // Send an email to the user's email address
      sendLoginEmail(userEmail, code);

      // Insert the code into the security table
      db.query(insertCodeQuery, [uid, code], (err) => {
        if (err) {
          console.error('Error inserting code: ' + err.message);
          return res.status(500).send('Internal Server Error');
        }

        // User found, set a session variable to the user's email
        req.session.userEmail = userEmail;
        console.log('Session user set to: ' + userEmail);
        res.status(200).send('Login successful');
      });
    } else {
      console.error('Invalid credentials');
      res.status(401).send('Invalid credentials');
    }
  });
});

app.post('/security', (req, res) => {
    const { email, code } = req.body;
  
    // SQL query to check if the email and code combination is valid and unused
    const selectUserQuery = `
      SELECT * 
      FROM user_security US 
      LEFT JOIN user_login UL ON US.uid = UL.uid 
      WHERE UL.email = ? AND US.code = ? AND US.status = 'UNUSED'
    `;
  
    db.query(selectUserQuery, [email, code], (err, results) => {
      if (err) {
        console.error('Database query error: ' + err.message);
        return res.status(500).send('Internal Server Error');
      }
  
      if (results.length === 1) {
        // The email and code combination is valid
        // Update the status to 'USED' for the specific UID
        const uid= results[0].uid;
        const code = results[0].code;
        const updateStatusQuery = `UPDATE user_security SET status = 'USED' WHERE uid = ? AND code = ?`;
  
        db.query(updateStatusQuery, [uid],[code], (updateErr) => {
          if (updateErr) {
            console.error('Error updating code status: ' + updateErr.message);
            return res.status(500).send('Internal Server Error');
          }
  
          // Send a success response
          res.status(200).send('Validation successful');
        });
      } else {
        // Invalid email and code combination
        console.error('Invalid email and code combination');
        res.status(401).send('Invalid email and code combination');
      }
    });
  });
  
  
app.get('/api/login', (req, res) => {
    if (req.session.userEmail) {
      console.log(req.session.userEmail + 'check');
      res.send({ loggedIn: true, user: req.session.userEmail });
    } else {
      res.status(401).send({ loggedIn: false });
    }
  });

function sendLoginEmail(toEmail, code) {
  const transporter = nodemailer.createTransport({
    host: 'smtp.outlook.com',
    port: 587,
    secure: false,
    auth: {
      user: 'gmfacistol@outlook.com',
      pass: '@Devcore101213',
    },
  });

  transporter.sendMail(
    {
      from: 'gmfacistol@outlook.com',
      to: toEmail,
      subject: 'Login Successful',
      text: `Your login code is: ${code}`,
    },
    (error, info) => {
      if (error) {
        console.error('Email sending error: ' + error.message);
      } else {
        console.log('Email sent: ' + info.response);
      }
    }
  );
}

app.listen(port, () => {
  console.log('The app is listening to the port ' + port);
});
