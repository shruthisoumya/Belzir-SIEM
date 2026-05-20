import React from "react";
import { FaExclamationTriangle } from "react-icons/fa";
import "../styles/DeleteUserModal.css";

const DeleteUserModal = ({ isOpen, onClose, onDelete, user }) => {
  if (!isOpen || !user) return null;

  return (
    <div className="delete-overlay">
      <div className="delete-modal">

        {/* ICON */}
        <div className="delete-icon">
          <FaExclamationTriangle />
        </div>

        {/* TEXT */}
        <h2>Delete User</h2>
        <p>
          Are you sure you want to delete <b>{user.fullName}</b>?
        </p>

        {/* BUTTONS */}
        <div className="delete-actions">
          <button className="cancel-btn" onClick={onClose}>
            Cancel
          </button>

          <button className="confirm-delete-btn" onClick={onDelete}>
            Delete
          </button>
        </div>

      </div>
    </div>
  );
};

export default DeleteUserModal;