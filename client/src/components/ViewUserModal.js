import React from "react";
import "../styles/ViewUserModal.css";

const ViewUserModal = ({ isOpen, onClose, user }) => {
  if (!isOpen || !user) return null;

  return (
    <div className="view-overlay">
      <div className="view-card">

        {/* HEADER */}
        <div className="view-header">
          <h2>User Details</h2>
          <span className="close" onClick={onClose}>×</span>
        </div>


        {/* DETAILS */}
        <div className="details">
            
        {/* NAME */}
        <div className="detail-row">
            <span>Name</span>
          <h3>{user.name}</h3>
         
        </div>

          <div className="detail-row">
            <span>Email</span>
            <p>{user.email}</p>
          </div>

          <div className="detail-row">
            <span>Company</span>
            <p>{user.companyName || "--"}</p>
          </div>

          <div className="detail-row">
            <span>Role</span>
            <p>{user.role}</p>
          </div>

        </div>

        {/* FOOTER */}
        <div className="view-footer">
          <button className="close-btn" onClick={onClose}>
            Close
          </button>
        </div>

      </div>
    </div>
  );
};

export default ViewUserModal;