const mongoose = require('mongoose');

mongoose.connect('mongodb://127.0.0.1:27017/first-mini-project'); // fixed the colon in URI too

const userSchema = mongoose.Schema({
  username: String,
  name: String,
  age: Number,
  email: String,
  password: String,
  post: [
    {
      type: mongoose.Schema.Types.ObjectId, // ✅ fixed "typeof" to "type"
      ref: "post"
    }
  ]
});

module.exports = mongoose.model('user', userSchema);
