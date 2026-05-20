const mongoose = require("mongoose");

const authLogSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User"
  },

  email: String,

  company: {
    type: String,
    index: true
  },

  event: {
    type: String,
    enum: [
      "LOGIN",
      "OTP_SENT",
      "OTP_VERIFIED",
      "INVITE_USER",
      "PASSWORD_SET"
    ]
  },

  otp: String,

  status: {
    type: String,
    enum: ["SUCCESS", "FAILED"]
  },

  ip: String,

  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model("AuthLog", authLogSchema);