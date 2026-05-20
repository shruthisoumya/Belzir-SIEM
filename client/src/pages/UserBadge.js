// src/components/UserBadge.js
import React from "react";
import "../styles/userBadge.css";

const user = JSON.parse(localStorage.getItem("user"));
export default function UserBadge({ user }) {
  if (!user) return null;

  return (
    <div className="current-user-right">
      <span className="username">{user.name || user.email}</span>
      <div className="avatar">
        {user.name ? user.name.charAt(0).toUpperCase() : "U"}
      </div>
    </div>
  );
}