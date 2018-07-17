const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const User = require("./models/user"); //capital "U" means we can use the new keyword!
const tokenService = require("./tokenService");

const jwt = require("jsonwebtoken");
const config = require("./config.json");

const app = express();
const PORT = 8080;

app.use(bodyParser.json());

const uri = "mongodb://localhost:27017/auth";
mongoose.connect(uri);

app.post("/signup", (req, res) => {
	// 1. Grab email and password
	const { email, password } = req.body;
	// 2. Instantiate a new user
	const user = new User({
		email, //This is destructuring. Altenative syntax: email: email, password: password
		password 
	})
	// 3. Store the email and password on the user that we just instantiated
	// 4. Save the user in our database 
	user 
		.save()
		.then(doc => {
			res.status(200).json({
				message: 'success',
				payload: doc
			})
		})
		.catch(err => {
			res.status(500).json({
				message: err.message
			})
		})
});

// post to login
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  User.findOne({ email }).then(user => {
    if (user) {
      user
        // compare a user's hash to the password sent in the HTTP request body
        .comparePassword(password)
        .then(isMatch => {
          // if they match
          // send back the user
          if (isMatch) {
          	const token = tokenService.create(user);
            res.status(200).json({
              message: "success",
              payload: token
            });
          } else {
            // no match, send back a 401
            res.status(401).json({ message: "unauthorized" });
          }
        })
        // all other errors are 500s!
        .catch(err => {
          res.status(500).json({
            message: err.message
          });
        });
    } else {
      // no user found with the posted email
      res.status(401).json({
        message: "unauthorized"
      });
    }
  });
});

app.get('/user/current', (req, res) => {
	// 1. Store the authentication header in a variable
	const authHeader = req.get("authorization")
	// 2. If it is not present, 401
	if (!authHeader) {
		res.status(401).send({ message: 'forbidden' })
	}
	// ["Bearer", "jf5lkdjarfoeisf"]
	const token = authHeader.split(" ")[1];

	jwt.verify(token, config.secret, (err, decoded) => {
		if (err) {
			res.status(401).send({
				message:'forbidden'
			})
		}
		const { id } = decoded.user;

		User.findById(id).then(doc => {
			if (doc) {
				res.status(200).send({
					message: 'success',
					payload: doc
				})
			} else {
				res.status(401).send({
					message: 'forbidden'
				})
			}
		})
		//res.status(200).send(decoded);
	})
	// 3. If it is present, just send it back

});

app.listen(PORT, () => {
  console.log(`Listening on ${PORT}`);
});
