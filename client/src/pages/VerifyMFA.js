import React, { useState, useRef, useEffect } from "react";
import axios from "axios";
import { useNavigate, useLocation } from "react-router-dom";

export default function VerifyMFA() {
  const [otp, setOtp] = useState(["", "", "", "", "", ""]);
  const [message, setMessage] = useState("");
  const [timer, setTimer] = useState(30);

  const inputsRef = useRef([]);
  const navigate = useNavigate();
  const location = useLocation();

  const API_URL = process.env.REACT_APP_API_URL;

  // ✅ GET USER ID (works for both login + settings flow)
  const storedUser = JSON.parse(localStorage.getItem("user"));
  const userId = location.state?.userId || storedUser?._id;

  // ✅ detect setup flow
  const fromSetup = location.state?.fromSetup || false;

  // ================= TIMER =================
  useEffect(() => {
    const interval = setInterval(() => {
      setTimer((prev) => (prev === 1 ? 30 : prev - 1));
    }, 1000);

    return () => clearInterval(interval);
  }, []);

  // ================= INPUT =================
  const handleChange = (value, index) => {
    if (!/^[0-9]?$/.test(value)) return;

    const newOtp = [...otp];
    newOtp[index] = value;
    setOtp(newOtp);

    if (value && index < 5) {
      inputsRef.current[index + 1].focus();
    }

    if (newOtp.join("").length === 6) {
      handleVerify(newOtp.join(""));
    }
  };

  // ================= BACKSPACE =================
  const handleKeyDown = (e, index) => {
    if (e.key === "Backspace" && !otp[index] && index > 0) {
      inputsRef.current[index - 1].focus();
    }
  };

  // ================= VERIFY =================
  const handleVerify = async (finalToken) => {
    const token = finalToken || otp.join("");

    if (token.length !== 6) {
      setMessage("Enter 6-digit code");
      return;
    }

    try {
      const res = await axios.post(`${API_URL}/api/users/verify-mfa`, {
        userId,
        token
      });

      // ✅ update user (important)
      if (res.data?.user) {
        localStorage.setItem("user", JSON.stringify(res.data.user));
      }

      if (fromSetup) {
        alert("2FA Enabled Successfully ✅");
      } else {
        alert("Verification Successful ✅");
      }

      navigate("/dashboard");

    } catch (err) {
      setMessage("Invalid or expired code");

      setOtp(["", "", "", "", "", ""]);
      inputsRef.current[0].focus();
    }
  };

  return (
    <div style={styles.overlay}>
      <div style={styles.modal}>

        <h2 style={styles.title}>Verify it’s you</h2>
        <p style={styles.subtitle}>
          Enter the 6-digit code from your authenticator app
        </p>

        <div style={styles.otpContainer}>
          {otp.map((digit, index) => (
            <input
              key={index}
              ref={(el) => (inputsRef.current[index] = el)}
              type="text"
              maxLength="1"
              value={digit}
              onChange={(e) => handleChange(e.target.value, index)}
              onKeyDown={(e) => handleKeyDown(e, index)}
              style={styles.otpInput}
            />
          ))}
        </div>

        <p style={styles.timer}>
          Code refreshes in <strong>{timer}s</strong>
        </p>

        <button style={styles.verifyBtn} onClick={() => handleVerify()}>
          VERIFY
        </button>

        {message && <p style={styles.error}>{message}</p>}

      </div>
    </div>
  );
}

// ================= STYLES =================
const styles = {
  overlay: {
    position: "fixed",
    top: 0,
    left: 0,
    width: "100vw",
    height: "100vh",
    background: "rgba(0,0,0,0.4)",
    backdropFilter: "blur(6px)",
    display: "flex",
    justifyContent: "center",
    alignItems: "center"
  },
  modal: {
    background: "#fff",
    borderRadius: "12px",
    padding: "30px",
    width: "400px",
    textAlign: "center",
    boxShadow: "0 10px 40px rgba(0,0,0,0.2)"
  },
  title: { marginBottom: "10px" },
  subtitle: {
    fontSize: "14px",
    color: "#666",
    marginBottom: "20px"
  },
  otpContainer: {
    display: "flex",
    justifyContent: "space-between",
    gap: "10px",
    marginBottom: "10px"
  },
  otpInput: {
    width: "45px",
    height: "55px",
    fontSize: "22px",
    textAlign: "center",
    border: "1px solid #ccc",
    borderRadius: "8px"
  },
  timer: {
    fontSize: "13px",
    color: "#888",
    marginBottom: "15px"
  },
  verifyBtn: {
    width: "100%",
    padding: "12px",
    background: "#1a73e8",
    color: "#fff",
    border: "none",
    borderRadius: "6px",
    fontWeight: "bold",
    cursor: "pointer"
  },
  error: {
    color: "red",
    marginTop: "10px"
  }
};