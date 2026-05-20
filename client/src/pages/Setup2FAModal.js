import React from "react";
import { useNavigate } from "react-router-dom";
import "../styles/modal.css";

export default function Setup2FAModal({
  isOpen,
  qrCode,
  manualCode,
  onClose
}) {
  const navigate = useNavigate();

  if (!isOpen) return null;

  const handleNext = () => {
    const user = JSON.parse(localStorage.getItem("user"));
    if (!user || !user._id) {
      alert("Session expired. Please login again.");
      return;
    }

    if (onClose) onClose();

    navigate("/verify-mfa", {
      state: {
        userId: user._id,
        fromSetup: true
      }
    });
  };

  return (
    <div className="modal-overlay">
      <div className="modal-card center">
        <h2>Setup Two-Factor Authentication</h2>

        <h4>Scan QR Code</h4>
        <p className="sub">
          Scan this QR code with your authenticator app
        </p>

        {qrCode ? (
          <img src={qrCode} alt="QR" className="qr" />
        ) : (
          <p>Loading QR...</p>
        )}

        <p className="manual">Or enter this code manually:</p>
        <div className="manual-code">{manualCode || "----"}</div>

        <button
          className="primary full"
          onClick={handleNext}
          disabled={!qrCode}
        >
          NEXT
        </button>

        <button className="cancel small" onClick={onClose}>
          CANCEL
        </button>
      </div>
    </div>
  );
}