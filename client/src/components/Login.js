import React, { useState } from "react";
import axios from "axios";
import "../styles/login.css";
import { Mail, Lock } from "lucide-react";
import { useNavigate } from "react-router-dom";

export default function Login() {
  const navigate = useNavigate();
  const API_URL = process.env.REACT_APP_API_URL;

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const [mfaCode, setMfaCode] = useState("");
  const [showMfa, setShowMfa] = useState(false);
  const [userId, setUserId] = useState("");

  const [trustDevice, setTrustDevice] = useState(false);
  const [message, setMessage] = useState("");

  // =========================
  // 🔐 LOGIN
  // =========================
  const handleLogin = async () => {
    if (!email || !password) {
      setMessage("Please enter email and password");
      return;
    }

    try {
      const res = await axios.post(
        `${API_URL}/api/users/login`, // ✅ keep your existing route
        {
          email,
          password
        },
        {
          headers: {
            "x-device-token": localStorage.getItem("deviceToken")
          }
        }
      );

      console.log("LOGIN RESPONSE 👉", res.data);

      // ✅ STEP 1: FIRST TIME MFA SETUP
      if (res.data.mfaSetupRequired) {
        navigate("/setup-mfa", {
          state: { userId: res.data.userId }
        });
        return;
      }

      // ✅ STEP 2: MFA REQUIRED → SHOW OTP UI
      if (res.data.mfaRequired) {
        setShowMfa(true);
        setUserId(res.data.userId);
        setMessage("Enter code from Microsoft Authenticator");
        return;
      }

      // ✅ STEP 3: TRUSTED DEVICE LOGIN
     if (res.data.user) {
  // Save logged-in user
  localStorage.setItem("user", JSON.stringify(res.data.user));

  // 🔹 Save JWT token for API requests
  localStorage.setItem("token", res.data.token);

  if (res.data.deviceToken) {
    localStorage.setItem("deviceToken", res.data.deviceToken);
  }

  navigate("/dashboard");
}

    } catch (err) {
      console.error("LOGIN ERROR 👉", err);
      setMessage(err.response?.data?.message || "Login failed");
    }
  };

  // =========================
  // 🔐 VERIFY MFA
  // =========================
  const handleVerifyMfa = async () => {
    try {
      const res = await axios.post(
        `${API_URL}/api/users/login-mfa`, // ✅ keep your existing route
        {
          userId,
          token: mfaCode,
          trustDevice: trustDevice // ✅ FIXED (was hardcoded true)
        },
        {
          headers: {
            "x-device-token": localStorage.getItem("deviceToken")
          }
        }
      );

      console.log("MFA VERIFY RESPONSE 👉", res.data);

      if (res.data.deviceToken) {
        localStorage.setItem("deviceToken", res.data.deviceToken);
      }

      // Save logged-in user
localStorage.setItem("user", JSON.stringify(res.data.user));

// 🔹 Save JWT token for API requests
localStorage.setItem("token", res.data.token);

navigate("/dashboard");
    } catch (err) {
      console.error("MFA ERROR 👉", err);
      setMessage(err.response?.data?.message || "Invalid code");
    }
  };

  return (
    <div className="container">
      <div className="left">
        <div className="left-content">
          <h1>Belzir IT Support</h1>
          <p>Secure login using Microsoft Authenticator</p>
        </div>
      </div>

      <div className="right">
        <div className="login-card">
          <h2>Welcome Back</h2>
          <p className="subtitle">Sign in to your account</p>

          {!showMfa ? (
            <>
              <label>Email Address</label>
              <div className="input-box">
                <Mail className="icon" size={18} />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
              </div>

              <label>Password</label>
              <div className="input-box">
                <Lock className="icon" size={18} />
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </div>

              <div style={{ marginTop: "10px" }}>
                <input
                  type="checkbox"
                  checked={trustDevice}
                  onChange={(e) => setTrustDevice(e.target.checked)}
                />
                <label style={{ marginLeft: "5px" }}>
                  Trust this device for 24 hours
                </label>
              </div>

              <button className="login-btn" onClick={handleLogin}>
                Sign In →
              </button>
            </>
          ) : (
            <>
              <label>Enter Authenticator Code</label>
              <input
                type="text"
                maxLength="6"
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value)}
                style={{ textAlign: "center", letterSpacing: "5px" }}
              />

              <div style={{ marginTop: "10px" }}>
                <input
                  type="checkbox"
                  checked={trustDevice}
                  onChange={(e) => setTrustDevice(e.target.checked)}
                />
                <label style={{ marginLeft: "5px" }}>
                  Trust this device for 24 hours
                </label>
              </div>

              <button className="login-btn" onClick={handleVerifyMfa}>
                Verify Code
              </button>
            </>
          )}

          {message && <p className="message">{message}</p>}
        </div>
      </div>
    </div>
  );
}