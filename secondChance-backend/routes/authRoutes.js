const express = require("express");
const router = express.Router();
const connectToDatabase = require("../models/db");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const logger = require('../logger');

router.post("/register", async (req, res) => {
  try {
    // Task 1: Connect to `secondChance` in MongoDB through `connectToDatabase` in `db.js`.
    const db = await connectToDatabase();

    // Task 2: Access MongoDB `users` collection
    const collection = await db.collection("users");

    // Task 3: Check if user credentials already exists in the database and throw an error if they do
    const existingEmail = await collection.findOne({ email: req.body.email });

    if (existingEmail) {
      logger.error("Email id already exists");
      return res.status(400).json({ error: "Email id already exists" });
    }

    // Task 4: Create a hash to encrypt the password so that it is not readable in the database
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(req.body.password, salt);
    const newEmail = req.body.email;
    // Task 5: Insert the user into the database
    const newUser = await collection.insertOne({
      email: newEmail,
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      password: hash,
      createdAt: new Date(),
    });

    // Task 6: Create JWT authentication if passwords match with user._id as payload
    const payload = {
      user: {
        id: newUser.insertedId,
      },
    };

    const authtoken = jwt.sign(payload, process.env.JWT_SECRET);

    // Task 7: Log the successful registration using the logger
    logger.info("User registered successfully");

    // Task 8: Return the user email and the token as a JSON
    res.json({ authtoken, newEmail });
  } catch (error) {
     res.status(500).json({
      message: "Internal server error",
      error: error.message
   });
  }
});

module.exports = router;
