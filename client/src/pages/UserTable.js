import React, { useState } from "react";
import { FaEye, FaEdit, FaTrash, FaCog } from "react-icons/fa";
import { FaUserPlus } from "react-icons/fa";
import AddUserModal from "../components/AddUserModal";
import ViewUserModal from "../components/ViewUserModal";
import DeleteUserModal from "../components/DeleteUserModal";
import EditUserModal from "../components/EditUserModal";
import "../styles/UserTable.css";
import axios from "axios";
import { API_URL } from "../components/config";
import { useNavigate } from "react-router-dom";

const UserTable = ({ users, refreshUsers }) => {
  const [open, setOpen] = useState(false);
const navigate = useNavigate();
  const [viewUser, setViewUser] = useState(null);
  const [viewOpen, setViewOpen] = useState(false);

  const [deleteUser, setDeleteUser] = useState(null);
  const [deleteOpen, setDeleteOpen] = useState(false);

  const [editUser, setEditUser] = useState(null);
const [editOpen, setEditOpen] = useState(false);

const handleDelete = async () => {
  try {
    await axios.delete(
      `${API_URL}/api/users/delete-user/${deleteUser._id}`,
      {
        headers: {
          Authorization: `Bearer ${localStorage.getItem("token")}`
        }
      }
    );

    alert("User deleted");

    setDeleteOpen(false);
    setDeleteUser(null);

    if (refreshUsers) refreshUsers();

  } catch (err) {
    console.log("DELETE ERROR 👉", err.response || err);
    alert(err.response?.data?.message || "Error deleting user");
  }
};

  return (
    <div className="user-table">

      {/* HEADER */}
      <div className="table-header">
        <h2>System Users</h2>

        <button className="add-user-btn" onClick={() => setOpen(true)}>
          <FaUserPlus className="btn-icon" />
<span>Add User</span>
        </button>
      </div>

      {/* TABLE */}
      <table className="user-table-content">
        <thead>
          <tr>
            <th>Name</th>
            <th>Email Address</th>
            <th>Company</th>
            <th>System Role</th>
            <th>Action</th>
          </tr>
        </thead>

        <tbody>
  {users.length > 0 ? (
    users.map((u, idx) => (
      <tr key={idx}>
        <td>{u.name || u.fullName || "N/A"}</td>
        <td>{u.email}</td>
        <td>{u.companyName}</td>
        <td>{u.role}</td>
                <td>
  {/* VIEW */}
  <FaEye
    className="action-icon"
    onClick={() => {
      setViewUser(u);
      setViewOpen(true);
    }}
  />

  {/* EDIT */}
  <FaEdit
    className="action-icon"
    onClick={() => {
      setEditUser(u);
      setEditOpen(true);
    }}
  />

  {/* DELETE */}
  <FaTrash
    className="action-icon"
    onClick={() => {
      setDeleteUser(u);
      setDeleteOpen(true);
    }}
  />

  {/* ⚙️ SETTINGS */}
  <FaCog
    className="action-icon"
    title="Settings"
    onClick={() => {
      navigate("/settings", { state: { user: u } }); // 🔥 pass user
    }}
  />
</td>
                
              </tr>
            ))
          ) : (
            <tr>
              <td colSpan="5" style={{ textAlign: "center" }}>
                No users found
              </td>
            </tr>
          )}
        </tbody>
      </table>

      {/* ADD USER */}
      <AddUserModal
        isOpen={open}
        onClose={() => setOpen(false)}
        refreshUsers={refreshUsers}
      />

      {/* VIEW USER */}
      <ViewUserModal
        isOpen={viewOpen}
        onClose={() => setViewOpen(false)}
        user={viewUser}
      />

      {/* DELETE USER */}
      <DeleteUserModal
        isOpen={deleteOpen}
        onClose={() => setDeleteOpen(false)}
        onDelete={handleDelete}
        user={deleteUser}
      />

      <EditUserModal
  isOpen={editOpen}
  onClose={() => setEditOpen(false)}
  user={editUser}
  refreshUsers={refreshUsers}
/>

    </div>
  );
};

export default UserTable;