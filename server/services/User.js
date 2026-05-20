const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true
    },

    password: {
      type: String,
      default: null,
      select: false
    },

    role: {
      type: String,
      enum: ["employee", "local-admin", "global-admin"],
      default: "employee",
      index: true
    },

    companyName: {
      type: String,
      default: "",
      index: true
    },

    isActive: {
      type: Boolean,
      default: false
    },

    inviteToken: String,
    inviteExpires: Date,

    // 🔐 MFA
    mfaEnabled: {
      type: Boolean,
      default: false
    },

    mfaSecret: {
      type: String
    },

    trustedDevices: [
      {
        token: String,
        expiresAt: Date
      }
    ],

    // 🔥 BACKUP CODES
    backupCodes: [String]
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", UserSchema);