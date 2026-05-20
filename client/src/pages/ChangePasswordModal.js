import React, { useState } from "react";
import { FaEye, FaEyeSlash } from "react-icons/fa";
import axios from "axios";
import "../styles/modal.css";

export default function ChangePasswordModal({ isOpen, onClose }) {
  const [newPass, setNewPass] = useState("");
  const [confirm, setConfirm] = useState("");

  const [showNew, setShowNew] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);

  const API_URL = process.env.REACT_APP_API_URL;

  if (!isOpen) return null;

  const handleChange = async () => {
    const user = JSON.parse(localStorage.getItem("user"));

    if (!newPass || !confirm) {
      alert("Please fill all fields");
      return;
    }

    if (newPass !== confirm) {
      alert("Passwords do not match ❌");
      return;
    }

    try {
      await axios.post(`${API_URL}/api/users/change-password`, {
        userId: user._id,
        newPassword: newPass
      });

      alert("Password changed successfully ✅");

      // 🔥 clear fields
      setNewPass("");
      setConfirm("");

      onClose();

    } catch (err) {
      alert("Error changing password ❌");
    }
  };

  // 🔥 reusable input
  const renderInput = (value, setValue, show, setShow, placeholder) => (
    <div className="input-group">
      <input
        type={show ? "text" : "password"}
        placeholder={placeholder}
        value={value}
        onChange={(e) => setValue(e.target.value)}
      />

      <span className="eye-icon" onClick={() => setShow(!show)}>
        {show ? <FaEyeSlash /> : <FaEye />}
      </span>
    </div>
  );

  return (
    <div className="modal-overlay">
      <div className="modal-card">

        <h3>Change Password</h3>

        {/* ✅ NEW PASSWORD */}
        {renderInput(newPass, setNewPass, showNew, setShowNew, "New Password")}

        {/* ✅ CONFIRM PASSWORD */}
        {renderInput(confirm, setConfirm, showConfirm, setShowConfirm, "Confirm Password")}

        <div className="modal-actions">
          <button className="cancel" onClick={onClose}>
            CANCEL
          </button>

          <button className="primary" onClick={handleChange}>
            CHANGE PASSWORD
          </button>
        </div>

      </div>
    </div>
  );
}