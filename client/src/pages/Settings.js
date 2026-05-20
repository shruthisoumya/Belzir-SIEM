import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import VerifyPasswordModal from "./VerifyPasswordModal";
import ChangePasswordModal from "./ChangePasswordModal";
import Setup2FAModal from "./Setup2FAModal";
import axios from "axios";
import "../styles/settings.css";

export default function Settings() {
  const navigate = useNavigate();
  const user = JSON.parse(localStorage.getItem("user"));

  const [verifyOpen, setVerifyOpen] = useState(false);
  const [changeOpen, setChangeOpen] = useState(false);
  const [open2FA, setOpen2FA] = useState(false);

  const [actionType, setActionType] = useState("");
  const [qrCode, setQrCode] = useState("");
  const [manualCode, setManualCode] = useState("");

  const [twoFAEnabled, setTwoFAEnabled] = useState(user?.mfaEnabled || false);
  const [togglePending, setTogglePending] = useState(false);

  const API_URL = process.env.REACT_APP_API_URL;

  // Role flags
  const isGlobalAdmin = user?.role === "global-admin";
  const isLocalAdmin = user?.role === "local-admin";
  const isEmployee = user?.role === "employee";

  if (!user) {
    return <h3 style={{ padding: "20px" }}>No user logged in</h3>;
  }

  // ================= VERIFY PASSWORD =================
  const handleVerify = async (password) => {
    try {
      await axios.post(`${API_URL}/api/users/verify-password`, {
        userId: user._id,
        password
      });

      setVerifyOpen(false);

      if (actionType === "password") setChangeOpen(true);
      if (actionType === "2fa") await setup2FA();
      if (actionType === "delete") await handleDeleteAccount();

      return true;
    } catch (err) {
      return false;
    }
  };

  // ================= SETUP 2FA =================
  const setup2FA = async () => {
    try {
      const res = await axios.post(`${API_URL}/api/users/setup-mfa`, {
        userId: user._id
      });
      setQrCode(res.data.qrCode);
      setManualCode(res.data.manualCode);
    } catch {
      alert("Failed to load QR");
      setTwoFAEnabled(false);
      setTogglePending(false);
      setOpen2FA(false);
    }
  };

  // ================= DELETE =================
  const handleDeleteAccount = async () => {
    const confirmDelete = window.confirm("Delete account permanently?");
    if (!confirmDelete) return;

    try {
      await axios.delete(`${API_URL}/api/users/delete-user/${user._id}`);
      localStorage.removeItem("user");
      alert("Account deleted ❌");
      window.location.href = "/login";
    } catch {
      alert("Delete failed");
    }
  };

  // ================= ACTIONS =================
  const handleChangePassword = () => {
    setActionType("password");
    setVerifyOpen(true);
  };

  const handleToggle2FA = async () => {
    if (twoFAEnabled) {
      try {
        await axios.post(`${API_URL}/api/users/disable-mfa`, {
          userId: user._id
        });
        alert("MFA Disabled ❌");
        setTwoFAEnabled(false);
      } catch {
        alert("Failed to disable MFA");
      }
      return;
    }

    setTwoFAEnabled(true);
    setTogglePending(true);
    setActionType("2fa");
    setQrCode("");
    setManualCode("");
    setOpen2FA(true);

    try {
      await setup2FA();
    } catch {
      setTwoFAEnabled(false);
      setOpen2FA(false);
    }
  };

  const handleDeleteClick = () => {
    setActionType("delete");
    setVerifyOpen(true);
  };

  const handle2FAClose = () => {
    if (togglePending) {
      setTwoFAEnabled(false);
      setTogglePending(false);
    }
    setOpen2FA(false);
  };

  const handleManageUsers = () => {
    navigate("/manage-users"); // You should have a route for managing users
  };

  return (
    <div className="settings-container">
      <h2>Security & Account</h2>

      {/* PASSWORD */}
      <div className="settings-card">
        <div>
          <p className="label">Password</p>
          <p className="desc">Change your password</p>
        </div>
        <button className="outline-btn" onClick={handleChangePassword}>
          CHANGE PASSWORD
        </button>
      </div>
      <div className="settings-card">
  <div>
    <p className="label">Your Role</p>
    <p className="desc">{user.role}</p>
  </div>
</div>

      {/* 2FA */}
      {(isEmployee || isLocalAdmin || isGlobalAdmin) && (
        <div className="settings-card">
          <div>
            <p className="label">Two-Factor Authentication</p>
            <p className="desc">Add extra security</p>
          </div>
          <label className="switch">
            <input
              type="checkbox"
              checked={twoFAEnabled}
              onChange={handleToggle2FA}
            />
            <span className="slider"></span>
          </label>
        </div>
      )}

      {/* DELETE */}
      {(isEmployee || isLocalAdmin || isGlobalAdmin) && (
        <div className="settings-card">
          <div>
            <p className="label">Delete Account</p>
            <p className="desc">Delete your account</p>
          </div>
          <button className="danger-btn" onClick={handleDeleteClick}>
            DELETE ACCOUNT
          </button>
        </div>
      )}

      {/* ADMIN USER MANAGEMENT */}
      {(isLocalAdmin || isGlobalAdmin) && (
        <div className="settings-card">
          <div>
            <p className="label">User Management</p>
            <p className="desc">
              {isGlobalAdmin
                ? "Manage all users"
                : "Manage users in your company"}
            </p>
          </div>
          <button className="outline-btn" onClick={handleManageUsers}>
            MANAGE USERS
          </button>
        </div>
      )}

      {/* MODALS */}
      <VerifyPasswordModal
        isOpen={verifyOpen}
        onClose={() => setVerifyOpen(false)}
        onVerify={handleVerify}
      />

      <ChangePasswordModal
        isOpen={changeOpen}
        onClose={() => setChangeOpen(false)}
      />

      <Setup2FAModal
        isOpen={open2FA}
        qrCode={qrCode}
        manualCode={manualCode}
        onClose={handle2FAClose}
        setTwoFAEnabled={setTwoFAEnabled}
      />
    </div>
  );
}