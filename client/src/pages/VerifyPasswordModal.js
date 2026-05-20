import React, { useState } from "react";
import { FaEye, FaEyeSlash } from "react-icons/fa";
import "../styles/modal.css";

export default function VerifyPasswordModal({ isOpen, onClose, onVerify }) {
  const [password, setPassword] = useState("");
  const [show, setShow] = useState(false);
  const [error, setError] = useState("");

  if (!isOpen) return null;

  const handleSubmit = async () => {
    const result = await onVerify(password);

    if (!result) {
      setError("Wrong password ❌");
    } else {
      setError("");
      setPassword("");
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-card">

        <h3>Verify Password</h3>

        {/* 🔥 INPUT WITH ICON */}
        <div className="input-group">
  <input
    type={show ? "text" : "password"}
    placeholder="Enter your password"
    value={password}
    onChange={(e) => setPassword(e.target.value)}
  />

  <span className="eye-icon" onClick={() => setShow(!show)}>
    {show ? <FaEyeSlash /> : <FaEye />}
  </span>
</div>

        {/* ERROR */}
        {error && <p className="error">{error}</p>}

        <div className="modal-actions">
          <button className="cancel" onClick={onClose}>
            CANCEL
          </button>

          <button className="primary" onClick={handleSubmit}>
            VERIFY
          </button>
        </div>

      </div>
    </div>
  );
}