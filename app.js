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
app.use(express.json());
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

      await user.save();

      let token = jwt.sign({ email: email, userid: user._id }, "shsh");
      res.cookie('token', token);
      res.send('User registered successfully');
    });
  });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const user = await userModel.findOne({ email });

  if (!user) {
    return res.status(400).send('Invalid email or password');
  }

  const result = await bcrypt.compare(password, user.password);

  if (result) {
    const token = jwt.sign({ userid: user._id, email: user.email }, 'shsh');
    res.cookie('token', token);
    return res.status(200).redirect('/profile');
  } else {
    return res.status(401).send('Invalid email or password');
  }
});

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

app.get('/profile', isLoggedIn, async (req, res) => {
  const user = await userModel.findById(req.user.userid).populate('post').exec();
  if (!user) {
    return res.status(404).send('User not found');
  }

  const posts = await postModel.find({ user: req.user.userid }).populate('user', 'username').exec();
  if (!posts) {
    return res.status(404).send('No posts found');
  }

  res.render('profile', { user, posts });
});

// Like post route
app.get('/like/:id', isLoggedIn, async (req, res) => {
  const mongoose = require('mongoose');
  const postId = req.params.id;

  if (!mongoose.Types.ObjectId.isValid(postId)) {
    return res.json({ error: 'Invalid Post ID' });
  }

  const post = await postModel.findById(postId);
  if (!post) return res.json({ error: 'Post not found' });

  const userId = req.user.userid.toString();

  const index = post.likes.indexOf(userId);

  if (index === -1) {
    post.likes.push(userId); // Like the post
  } else {
    post.likes.splice(index, 1); // Unlike the post
  }

  await post.save();

  res.json({ likes: post.likes.length, isLiked: index === -1 });
});


// Edit post route
app.get('/edit-post/:id', isLoggedIn, async (req, res) => {
    const postId = req.params.id;
    
    // Ensure the post exists
    const post = await postModel.findById(postId);
    
    if (!post) {
      return res.status(404).send('Post not found');
    }
  
    // Check if the post belongs to the logged-in user
    if (post.user.toString() !== req.user.userid.toString()) {
      return res.status(403).send('You cannot edit this post');
    }
  
    // Render the edit form and pass the post data
    res.render('edit-post', { post });
  });
  
  // Update the post
  app.post('/edit-post/:id', isLoggedIn, async (req, res) => {
    const postId = req.params.id;
    const { content } = req.body;
  
    // Ensure the post exists
    const post = await postModel.findById(postId);
    
    if (!post) {
      return res.status(404).send('Post not found');
    }
  
    // Check if the post belongs to the logged-in user
    if (post.user.toString() !== req.user.userid.toString()) {
      return res.status(403).send('You cannot edit this post');
    }
  
    // Update the post content
    post.content = content;
    await post.save();
  
    // Redirect back to the profile page
    res.redirect('/profile');
  });
  

// Middleware to check if the user is logged in
function isLoggedIn(req, res, next) {
  const token = req.cookies.token;

  if (!token) {
    return res.send("You must be logged in.");
  }

  const data = jwt.verify(token, "shsh");
  if (!data) {
    return res.send("Invalid or expired token.");
  }

  req.user = data;
  next();
}

app.listen(3000, () => {
  console.log('Server running at http://localhost:3000');
});
