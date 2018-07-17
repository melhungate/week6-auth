const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const bcrypt = require("bcrypt");

const userSchema = new Schema({
	email: { type: String, unique: true, required: true },
	password: { type: String, required: true }
});

// before a new user is saved
userSchema.pre("save", function(next) {
  const user = this;
  // if the user's password has changed since the last time the user was saved, or if this is a completely new user
  if (user.isModified("password") || user.isNew) {
    // hash their password
    bcrypt.hash(user.password, 10, (err, hash) => {
      if (err) {
        return next(err);
      }
      // set their password to be equal to the hash
      user.password = hash;
      next();
    });
  } else {
    return next();
  }
});

userSchema.methods.comparePassword = function(password){
	return bcrypt.compare(password, this.password);
};

module.exports = mongoose.model("User", userSchema);