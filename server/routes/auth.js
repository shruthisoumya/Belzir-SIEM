const express = require("express");
const router = express.Router();

const crypto = require("crypto");
const bcrypt = require("bcrypt");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const jwt = require("jsonwebtoken");

const User = require("../services/User");

const logActivity = require("../utils/logActivity");
const { sendEmail } = require("../services/graphEmailService");

const auth = require("../middleware/auth");
const authorize = require("../middleware/authorize");

const { buildUserQuery } = require("../utils/buildQuery");

const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";


// ==========================
// REGISTER USER
// ==========================
router.post("/register", async (req, res) => {
  const { name, fullName, email, password, role, companyName } = req.body;
  const finalName = (name || fullName || "").trim();

  if (!finalName) {
    return res.status(400).json({ message: "Name is required" });
  }

  try {
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      name: finalName,
      email,
      password: hashedPassword,
      role,
      companyName
    });

    await user.save();

    res.status(201).json({ message: "User created successfully" });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ==========================
// INVITE USER
// ==========================
router.post("/invite-user", async (req, res) => {
  const { name, fullName, email, role, companyName } = req.body;
  const finalName = (name || fullName || "").trim();

  try {
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: "User already exists" });
    }

    const token = crypto.randomBytes(32).toString("hex");

    const user = new User({
      name: finalName,
      email,
      password: null,
      role,
      companyName: companyName || "",
      isActive: false,
      inviteToken: token,
      inviteExpires: new Date(Date.now() + 2 * 60 * 60 * 1000)
    });

    await user.save();

    const link = `${FRONTEND_URL}/set-password?token=${token}`;
    await sendEmail(email, link, "invite");

    res.status(201).json({
      message: "User invited successfully",
      inviteLink: link
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ==========================
// SET PASSWORD
// ==========================
router.post("/set-password", async (req, res) => {
  const { token, password } = req.body;

  try {
    const user = await User.findOne({
      inviteToken: token,
      inviteExpires: { $gt: new Date() }
    });

    if (!user) {
      return res.status(400).json({ message: "Invalid or expired link" });
    }

    user.password = await bcrypt.hash(password, 10);
    user.isActive = true;
    user.inviteToken = null;
    user.inviteExpires = null;

    await user.save();

    res.json({ message: "Password set successfully" });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ==========================
// LOGIN (UNCHANGED)
// ==========================
router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const deviceToken = req.headers["x-device-token"];

  try {
    const user = await User.findOne({ email }).select("+password");

    if (!user) {
      await logActivity({ user: { email }, event: "LOGIN", status: "FAILED", req });
      return res.status(400).json({ message: "User not found" });
    }

    if (!user.isActive) {
      await logActivity({ user, event: "LOGIN", status: "FAILED", req });
      return res.status(400).json({ message: "User not active" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      await logActivity({ user, event: "LOGIN", status: "FAILED", req });
      return res.status(400).json({ message: "Invalid password" });
    }

    await logActivity({ user, event: "LOGIN", status: "SUCCESS", req });

    const userData = user.toObject();
    delete userData.password;

    const token = jwt.sign(
      {
        id: user._id,
        role: user.role,
        companyName: user.companyName,
        email: user.email
      },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    if (deviceToken && user.trustedDevices?.some(d => d.token === deviceToken)) {
      return res.json({ user: userData, token });
    }

    if (!user.mfaEnabled) {
      return res.json({ user: userData, token });
    }

    return res.json({
      mfaRequired: true,
      userId: user._id
    });

  } catch (err) {
    console.error("LOGIN ERROR:", err);

    await logActivity({ user: { email }, event: "LOGIN", status: "FAILED", req });

    return res.status(500).json({ error: err.message });
  }
});


// ==========================
// LOGIN MFA (UNCHANGED)
// ==========================
router.post("/login-mfa", async (req, res) => {
  const { userId, token } = req.body;

  try {
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: "base32",
      token
    });

    if (!verified) {
      return res.status(400).json({ message: "Invalid code" });
    }

    const userData = user.toObject();
    delete userData.password;

    const jwtToken = jwt.sign(
      {
        id: user._id,
        role: user.role,
        companyName: user.companyName,
        email: user.email
      },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    return res.json({
      user: userData,
      token: jwtToken
    });

  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

router.get("/users", auth, authorize(["global-admin", "local-admin", "employee"]), async (req, res) => {
  try {
    const query = buildUserQuery(req.user);

    const users = await User.find(query).select("-password");

    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const AuthLog = require("../models/AuthLog");

router.get("/logs", auth, authorize(["global-admin", "local-admin", "employee"]), async (req, res) => {
  try {
    const user = req.user;

    let query = {};

    if (user.role === "global-admin") {
      query = {};
    }

    else if (user.role === "local-admin") {
      query = {
        company: user.companyName
      };
    }

    else if (user.role === "employee") {
      query = {
        userId: user.id
      };
    }

    const logs = await AuthLog.find(query)
      .populate("userId", "name email role companyName")
      .sort({ createdAt: -1 });

    res.json(logs);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;