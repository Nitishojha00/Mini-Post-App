const express = require('express');
const app = express();
const userModel = require('./models/user.js');
const postModel = require('./models/post.js');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use (express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.render('index');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/register', async (req, res) => {
    const { username, name, age, email, password } = req.body;
    let user = await userModel.findOne({ email });
    if (user) {
        return res.status(400).send('User already exists');
    }

    bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(password, salt, async (err, hash) => {
            let user = new userModel({
                username,
                name,
                age,
                email,
                password: hash
            });

            await user.save(); // ✅ this actually inserts it into the DB

            let token = jwt.sign({ email: email, userid: user._id }, "shsh");
            res.cookie('token', token);
            res.send('User registered successfully');
        });
    });
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;

    userModel.findOne({ email }, (err, user) => {
        if (err) {
            return res.status(500).send('Server error');
        }

        if (!user) {
            return res.status(400).send('Invalid email or password');
        }

        bcrypt.compare(password, user.password, (err, result) => {
            if (err) {
                return res.status(500).send('Server error');
            }

            if (result) {
                // Create JWT token
                const token = jwt.sign({ userid: user._id, email: user.email }, 'shsh');
                res.cookie('token', token);
                return res.status(200).send('Login successful');
            } else {
                return res.status(401).send('Invalid email or password');
            }
        });
    });
});


app.get('/logout', (req, res) => {
    res.clearCookie('token'); // clear the cookie properly
    res.redirect('/login');   // redirect to login page
});

app.get('/profile',isLoggedIn,(req,res)=>{
    console.log(req.user);
    res.render('login');
})


function isLoggedIn(req, res, next) {
    const token = req.cookies.token;

    if (!token) {
        return res.send("You must be logged in.");
    }

    try {
        const data = jwt.verify(token, "shsh");
        req.user = data;
        next(); // move to next middleware or route handler
    } catch (err) {
        return res.send("Invalid or expired token.");
    }
}

app.listen(3000, () => {
    console.log('http://localhost:3000');
  });
