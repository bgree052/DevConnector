const express = require("express");
const router = express.Router();
const gravatar = require("gravatar");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("config");
const { check, validationResult } = require("express-validator/check");

//Bring in the user model
const User = require("../../models/User");

// @route   POST api/users
// @desc    Register user
// @access  Public
router.post(
  "/",
  [
    check("name", "Name is required")
      .not()
      .isEmpty(),
    check("email", "Please include a valid email").isEmail(),
    check(
      "password",
      "Please enter a password with 6 or more characters"
    ).isLength({
      min: 6
    })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;

    try {
      // See if user exists (error if they already exist)
      let user = await User.findOne({ email });

      if (user) {
        return res
          .status(400)
          .json({ errors: [{ msg: "User already exists" }] });
      }

      // Get user's gravatar
      const avatar = gravatar.url(email, {
        s: "200",
        r: "pg",
        d: "mm"
      });

      //create the user
      user = new User({
        name,
        email,
        avatar,
        password
      });

      // Encrypt password
      const salt = await bcrypt.genSalt(10);

      user.password = await bcrypt.hash(password, salt);

      //save the user in the database
      await user.save(); //(anything that returns a promise you need to put await in front of it)

      //get the payload which includes the user ID
      const payload = {
        user: {
          id: user.id
        }
      };

      //then sign the token, pass in the payload, secret token & expire time, then if we get the token we send it back to the client, if not then an error
      jwt.sign(
        payload,
        config.get("jwtSecret"),
        { expiresIn: 360000 }, //TODO Change back to 3600 when site is deployed
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );

      // Return jsonwebtoken
      //res.send("User registered");
    } catch (err) {
      console.error(err.message);
      res.status(500).send("Sever error");
    }
  }
);

module.exports = router;
