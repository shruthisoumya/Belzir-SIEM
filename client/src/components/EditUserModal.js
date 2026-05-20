import React, { useState, useEffect } from "react";
import axios from "axios";
import "../styles/AddUserModal.css"; // reuse same styling
import { API_URL } from "./config";

const EditUserModal = ({ isOpen, onClose, user, refreshUsers, currentRole }) => {
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    role: "User",
    companyName: ""
  });

  // 🔥 Prefill data when modal opens
  useEffect(() => {
    if (user) {
      setFormData({
        name: user.name || "",
        email: user.email || "",
        role: user.role || "User",
        companyName: user.companyName || ""
      });
    }
  }, [user]);

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleUpdate = async () => {
    try {
      console.log("UPDATE PAYLOAD 👉", formData); // ✅ debug

      await axios.put(
        `${API_URL}/api/users/update-user/${user._id}`,
        formData
      );

      alert("User updated successfully");

      // ✅ WAIT for refresh
      if (refreshUsers) {
        await refreshUsers();
      }

      onClose();

    } catch (err) {
      console.log("UPDATE ERROR 👉", err.response || err);
      alert("Error updating user");
    }
  };

  // 🔥 ROLE LOGIC (NEW ADDED ONLY)
const normalizeRole = (r = "") =>
  r.toLowerCase().replace(/_/g, "-");

const getRoleOptions = () => {
  const role =
    normalizeRole(currentRole) ||
    normalizeRole(JSON.parse(localStorage.getItem("user"))?.role);

  const rolesMap = {
    "global-admin": [
      { value: "global-admin", label: "Global Admin" },
      { value: "local-admin", label: "Local Admin" },
      { value: "employee", label: "Employee" }
    ],
    "local-admin": [
      { value: "local-admin", label: "Local Admin" },
      { value: "employee", label: "Employee" }
    ],
    "employee": [
      { value: "employee", label: "Employee" }
    ]
  };

  return rolesMap[role] || [];
  console.log("ROLE USED FOR DROPDOWN 👉", role);
};

  if (!isOpen || !user) return null;

  return (
    <div className="add-overlay">
      <div className="add-modal">

        {/* HEADER */}
        <div className="add-header">
          <h2>Edit User</h2>
          <span className="close" onClick={onClose}>×</span>
        </div>

        {/* FORM */}
        <div className="add-body">

          <div className="form-group">
            <label>Name</label>
            <input
              name="name"
              value={formData.name}
              onChange={handleChange}
            />
          </div>

          <div className="form-group">
            <label>Email</label>
            <input
              name="email"
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
                {getRoleOptions().map((role) => (
                  <option key={role.value} value={role.value}>
                    {role.label}
                  </option>
                ))}
              </select>
            </div>

            <div className="form-group">
              <label>Company</label>
              <input
                name="companyName"
                value={formData.companyName}
                onChange={handleChange}
              />
            </div>
          </div>

        </div>

        {/* FOOTER */}
        <div className="add-footer">
          <button className="cancel-btn" onClick={onClose}>
            Cancel
          </button>

          <button className="create-btn" onClick={handleUpdate}>
            Update User
          </button>
        </div>

      </div>
    </div>
  );
};

export default EditUserModal;