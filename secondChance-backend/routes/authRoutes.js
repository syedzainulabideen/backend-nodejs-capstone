const express = require("express");
const router = express.Router();
const connectToDatabase = require("../models/db");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const logger = require("../logger");

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
      error: error.message,
    });
  }
});

router.post("/login", async (req, res) => {
  try {
    const db = await connectToDatabase();

    const collection = db.collection("users");

    const theUser = await collection.findOne({ email: req.body.email });

    if (!theUser) {
      logger.error("User not found");
      return res.status(404).json({ error: "User not found" });
    }

    const result = await bcrypt.compare(req.body.password, theUser.password);

    if (!result) {
      logger.error("Passwords do not match");
      return res.status(401).json({ error: "Wrong password" });
    }

    const userName = theUser.firstName;
    const userEmail = theUser.email;

    const payload = {
      user: {
        id: theUser._id.toString(),
      },
    };

    const authtoken = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({ authtoken, userName, userEmail });
  } catch (error) {
    res.status(500).json({
      message: "Internal server error",
      error: error.message,
    });
  }
});

const { body, validationResult } = require("express-validator");

router.put("/update", async (req, res) => {
  // Task 2: Validate the input using `validationResult` and return an appropriate message if you detect an error
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.error("Validation errors in update request", errors.array());
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    // Task 3: Check if `email` is present in the header and throw an appropriate error message if it is not present
    const email = req.headers.email;

    if (!email) {
      logger.error("Email not found in the request headers");
      return res
        .status(400)
        .json({ error: "Email not found in the request headers" });
    }

    // Task 4: Connect to MongoDB
    const db = await connectToDatabase();
    const collection = db.collection("users");

    // Task 5: Find the user credentials in database
    const existingUser = await collection.findOne({ email });
    existingUser.updatedAt = new Date();

    // Task 6: Update the user credentials in the database
    const updatedUser = await collection.findOneAndUpdate(
      { email },
      { $set: existingUser },
      { returnDocument: "after" },
    );

    // Task 7: Create JWT authentication with `user._id` as a payload using the secret key from the .env file
    const payload = {
      user: {
        id: updatedUser._id.toString(),
      },
    };

    const authtoken = jwt.sign(payload, process.env.JWT_SECRET);

    res.json({ authtoken });
  } catch (error) {
    res.status(500).json({
      message: "Internal server error",
      error: error.message,
    });
  }
});

module.exports = router;
