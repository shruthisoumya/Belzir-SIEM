const AuthLog = require("../models/AuthLog");

const logActivity = async ({ user, event, status = "SUCCESS", req, otp }) => {
  try {
    await AuthLog.create({
      userId: user?._id || null,
      email: user?.email || null,
      company: user?.companyName || null,   // ✅ FIXED HERE
      event: event.toUpperCase(),
      status: status.toUpperCase(),
      otp: otp || null,
      ip: req?.ip || req?.headers["x-forwarded-for"] || ""
    });
  } catch (err) {
    console.error("Failed to log activity:", err);
  }
};

module.exports = logActivity;