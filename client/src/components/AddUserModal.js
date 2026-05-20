import React, { useState, useEffect } from "react";
import axios from "axios";
import "../styles/AddUserModal.css";
import { API_URL } from "./config";

const AddUserModal = ({ isOpen, onClose, refreshUsers }) => {
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    role: "employee", // default role
    companyName: ""
  });

  useEffect(() => {
    if (isOpen) {
      setFormData({
        name: "",
        email: "",
        role: "employee",
        companyName: ""
      });
    }
  }, [isOpen]);

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async () => {
    if (!formData.name || !formData.email) {
      alert("Please fill all required fields");
      return;
    }

    try {
      const token = localStorage.getItem("token"); // ✅ get JWT
      const res = await axios.post(
  `${API_URL}/api/users/invite-user`,
  formData,
  {
    headers: {
      Authorization: `Bearer ${localStorage.getItem("token")}`
    }
  }
);

      alert("User invited successfully!");
      console.log("Invite Link 👉", res.data.inviteLink);

      if (refreshUsers) refreshUsers();
      onClose();
    } catch (err) {
      console.log("INVITE ERROR 👉", err.response || err);
      alert(
        err.response?.data?.message ||
        "Error inviting user. Check backend."
      );
    }
  };

  if (!isOpen) return null;

  return (
    <div className="add-overlay">
      <div className="add-modal">
        <div className="add-header">
          <h2>Invite New User</h2>
          <span className="close" onClick={onClose}>×</span>
        </div>

        <div className="add-body">
          <div className="form-group">
            <label>Name</label>
            <input
              name="name"
              placeholder="John Doe"
              value={formData.name}
              onChange={handleChange}
            />
          </div>

          <div className="form-group">
            <label>Email Address</label>
            <input
              name="email"
              placeholder="john@company.com"
              value={formData.email}
              onChange={handleChange}
            />
          </div>

          <div className="form-row">
            <div className="form-group">
              <label>Role</label>
              <select
                name="role"
                value={formData.role}
                onChange={handleChange}
              >
                <option value="employee">Employee</option>
                {(JSON.parse(localStorage.getItem("user"))?.role === "local-admin" ||
                  JSON.parse(localStorage.getItem("user"))?.role === "global-admin") && (
                  <option value="local-admin">Local Admin</option>
                )}
                {JSON.parse(localStorage.getItem("user"))?.role === "global-admin" && (
                  <option value="global-admin">Global Admin</option>
                )}
              </select>
            </div>

            <div className="form-group">
              <label>Company</label>
              <input
                name="companyName"
                placeholder="Company Inc."
                value={formData.companyName}
                onChange={handleChange}
              />
            </div>
          </div>
        </div>

        <div className="add-footer">
          <button type="button" className="cancel-btn" onClick={onClose}>
            Cancel
          </button>

          <button type="button" className="create-btn" onClick={handleSubmit}>
            Invite User
          </button>
        </div>
      </div>
    </div>
  );
};

export default AddUserModal;