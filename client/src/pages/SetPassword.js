import React, { useState } from "react";
import axios from "axios";
import { useSearchParams, useNavigate } from "react-router-dom";
import "../styles/SetPassword.css";
import { API_URL } from "../components/config";

const SetPassword = () => {

  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");

  const [searchParams] = useSearchParams();
  const token = searchParams.get("token");

  const navigate = useNavigate();

  // ✅ PASSWORD STRENGTH FUNCTION (INSIDE COMPONENT)
  const getPasswordStrength = (password) => {
    let strength = 0;

    if (password.length >= 6) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^A-Za-z0-9]/.test(password)) strength++;

    if (strength <= 1) return "Weak";
    if (strength <= 3) return "Medium";
    return "Strong";
  };

  // ✅ CALL FUNCTION AFTER STATE
  const strength = getPasswordStrength(password);

  const handleSubmit = async () => {
    try {
      await axios.post(`${API_URL}/api/users/set-password`, {
        token,
        password
      });

      setMessage("✅ Password set successfully");

      setTimeout(() => {
        navigate("/login");
      }, 1500);

    } catch (err) {
      setMessage("❌ Invalid or expired link");
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">

        <h2>Set Your Password</h2>

        <input
          type="password"
          placeholder="Enter password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />

        {/* ✅ STRENGTH TEXT */}
        <p className={`strength ${strength.toLowerCase()}`}>
          Strength: {strength}
        </p>

        <button onClick={handleSubmit}>
          Set Password
        </button>

        {message && <p className="message">{message}</p>}

      </div>
    </div>
  );
};

export default SetPassword;