const User = require("../models/user.js");
const { ComparePassword, HashPassword } = require("../utils/hashPassword.js");
const axios = require("axios");
const oAuth2Client = require("../config/oauth.js");
const { GenerateAccessToken } = require("../utils/token.js");
const e = require("express");

const Register = async (req, res, next) => {
  const { username, email, password, phone_number } = req.body;

  try {
    // Check if email already exists
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ message: "Email sudah terdaftar" });
    }

    // Hash the password before saving it
    const hashedPassword = HashPassword(password);

    // Create a new user record in the database
    const user = await User.create({
      username,
      email,
      password: hashedPassword,
      phone_number,
    });

    // Return a success response
    res.status(201).json({
      message: "Daftar berhasil",
      data: user,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

const Login = async (req, res, next) => {
  const { email, password } = req.body;

  try {
    // Find the user by email
    const user = await User.findOne({ where: { email } });

    if (!user) {
      return res.status(400).json({ message: "Pengguna tidak ditemukan" });
    }

    if (!user.password) {
      return res.status(400).json({ message: "user registered by google" });
    }

    // Compare the hashed password with the provided password
    const isPasswordValid = ComparePassword(user.password, password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: "Password salah" });
    }

    // Generate a JWT token for the user
    const token = GenerateAccessToken(user);

    // Send Response Data (token and data user)
    res.status(200).json({
      message: "Sukses login",
      data: {
        token,
        user: {
          username: user.username,
          email: user.email,
          role: user.role,
          created_at: user.createdAt,
        },
      },
    });
  } catch (error) {
    // Send Error Response
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

const LoginByGoogle = async (req, res, next) => {
  const { code } = req.body;
  try {
    const { tokens } = await oAuth2Client.getToken(code);
    console.log(tokens);
    const userResponse = await axios.get("https://www.googleapis.com/oauth2/v3/userinfo", {
      headers: {
        Authorization: `Bearer ${tokens.access_token}`,
      },
    });

    const userData = userResponse.data;
    console.log(userData);
    const exitedUser = await User.findOne({ where: { email: userData.email } });

    if (exitedUser) {
      const token = GenerateAccessToken(exitedUser);
      return res.json({
        message: "Login successful",
        data: {
          token,
          user: {
            username: exitedUser.username,
            email: exitedUser.email,
            role: exitedUser.role,
            created_at: exitedUser.createdAt,
            photo_profile: exitedUser.photo_profile,
          },
        },
      });
    } else {
      const response = await User.create({
        username: userData.name,
        email: userData.email,
        photo_profile: userData.picture,
      });
      const token = GenerateAccessToken(response);
      return res.json({
        message: "Login successful",
        token,
        user: {
          username: response.username,
          email: response.email,
          role: response.role,
          photo_profile: response.photo_profile,
          created_at: response.createdAt,
        },
      });
    }
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      message: "Server error",
      error: error.message,
    });
  }
};

module.exports = { Register, Login, LoginByGoogle };
