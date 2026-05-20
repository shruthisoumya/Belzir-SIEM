import React from "react";
import { Outlet } from "react-router-dom";
import Sidebar from "../pages/Sidebar";
import "../styles/Layout.css";
import UserBadge from "../pages/UserBadge";

const Layout = () => {
  const user = JSON.parse(localStorage.getItem("user")); // get current user

  return (
    <div className="layout">
      <Sidebar />

      <div className="main-content">
        {/* ✅ TOP-RIGHT USER BADGE */}
        <div className="top-bar">
          <UserBadge user={user} />
        </div>

        {/* ✅ PAGE CONTENT */}
        <Outlet />
      </div>
    </div>
  );
};

export default Layout;