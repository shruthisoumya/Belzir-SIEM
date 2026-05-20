const jwt = require("jsonwebtoken");
const User = require("../services/User");

module.exports = async function (req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "No token" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await User.findById(decoded.id).select("-password");

    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    // 🔥 IMPORTANT: normalize user object for RBAC
    req.user = {
      id: user._id,
      email: user.email,
      role: user.role,
      companyName: user.companyName,
      isActive: user.isActive
    };

    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
};