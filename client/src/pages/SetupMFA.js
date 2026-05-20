import React, { useEffect, useState } from "react";
import axios from "axios";
import { useLocation, useNavigate } from "react-router-dom";

export default function SetupMFA() {
  const [qrCode, setQrCode] = useState("");
  const [manualCode, setManualCode] = useState("");
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(true);

  const location = useLocation();
  const navigate = useNavigate();

  const userId = location.state?.userId;
  const API_URL = process.env.REACT_APP_API_URL;

  useEffect(() => {
    const fetchQR = async () => {
      try {
        if (!userId) {
          setMessage("Session expired. Please login again.");
          setLoading(false);
          setTimeout(() => navigate("/login"), 2000);
          return;
        }

        const res = await axios.post(
          `${API_URL}/api/users/setup-mfa`,
          { userId: String(userId) }
        );

        setQrCode(res.data.qrCode);
        if (res.data.manualCode) {
          setManualCode(res.data.manualCode);
        }

        setLoading(false);

      } catch (err) {
        console.error(err);
        setMessage("Error loading QR code");
        setLoading(false);
      }
    };

    fetchQR();
  }, [userId, API_URL, navigate]);

  return (
    <div style={styles.overlay}>
      <div style={styles.modal}>

        {/* HEADER */}
        <h2 style={styles.title}>Set up two-factor authentication</h2>
        <p style={styles.subtitle}>
          Scan the QR code using your authenticator app
        </p>

        {/* QR */}
        {loading ? (
          <p style={{ marginTop: "20px" }}>Loading...</p>
        ) : (
          <>
            <div style={styles.qrContainer}>
              <img src={qrCode} alt="QR" style={styles.qr} />
            </div>

            {/* Manual Code */}
            {manualCode && (
              <p style={styles.manual}>
                Or enter this code manually:
                <br />
                <strong>{manualCode}</strong>
              </p>
            )}

            {/* NEXT BUTTON */}
            <button
              style={styles.nextBtn}
              onClick={() =>
                navigate("/verify-mfa", {
                  state: { userId }
                })
              }
            >
              NEXT
            </button>

            {/* CANCEL */}
            <button
              style={styles.cancelBtn}
              onClick={() => navigate("/login")}
            >
              CANCEL
            </button>
          </>
        )}

        {/* ERROR */}
        {message && <p style={styles.error}>{message}</p>}
      </div>
    </div>
  );
}

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
    alignItems: "center",
    zIndex: 999
  },

  modal: {
    background: "#fff",
    borderRadius: "12px",
    padding: "30px",
    width: "420px",
    textAlign: "center",
    boxShadow: "0 10px 40px rgba(0,0,0,0.2)"
  },

  title: {
    marginBottom: "10px"
  },

  subtitle: {
    fontSize: "14px",
    color: "#555"
  },

  qrContainer: {
    marginTop: "20px",
    padding: "15px",
    border: "1px solid #eee",
    borderRadius: "10px",
    display: "inline-block"
  },

  qr: {
    width: "200px",
    height: "200px"
  },

  manual: {
    fontSize: "12px",
    color: "#666",
    marginTop: "10px",
    wordBreak: "break-all"
  },

  nextBtn: {
    width: "100%",
    marginTop: "20px",
    padding: "12px",
    background: "#1a73e8",
    color: "#fff",
    border: "none",
    borderRadius: "6px",
    fontWeight: "bold",
    cursor: "pointer"
  },

  cancelBtn: {
    marginTop: "10px",
    background: "transparent",
    border: "none",
    color: "#555",
    cursor: "pointer"
  },

  error: {
    color: "red",
    marginTop: "10px"
  }
};