import React, { useState, useEffect } from "react";
import "../styles/Sidebar.css";
import {
  FaHome,
  FaUser,
  FaSignOutAlt,
  FaGlobe,
  FaMoon,
  FaSun,
  FaHistory
} from "react-icons/fa";
import { useNavigate } from "react-router-dom";

import belzirLogo from "../assets/Belzir-logo-with-Slogan--Light.png";
import belzirLogodark from "../assets/Belzir-logo-with-Slogan--Dark.png";

const Sidebar = () => {
  const navigate = useNavigate();

  // ✅ Load theme from localStorage
  const [darkMode, setDarkMode] = useState(
    localStorage.getItem("theme") === "dark"
  );

  // ✅ Apply theme to body
  useEffect(() => {
    if (darkMode) {
      document.body.classList.add("dark-mode");
      localStorage.setItem("theme", "dark");
    } else {
      document.body.classList.remove("dark-mode");
      localStorage.setItem("theme", "light");
    }
  }, [darkMode]);

  // ✅ Toggle theme
  const toggleTheme = () => {
    setDarkMode(!darkMode);
  };

  // ✅ Logout
  const handleLogout = () => {
    if (window.confirm("Are you sure you want to logout?")) {
      localStorage.removeItem("token");
      navigate("/");
    }
  };

  return (
    <div className="sidebar">

      {/* TOP SECTION */}
      <div>

        {/* LOGO */}
        <div className="logo">
          <img
            key={darkMode}
            src={darkMode ? belzirLogodark : belzirLogo}
            alt="Belzir Logo"
          />
        </div>

        <div className="divider"></div>

        {/* NAV */}
        <ul className="sidebar-top">
          <li
            className="nav-item dashboard-item"
            onClick={() => navigate("/dashboard")}
          >
            <FaHome className="icon" />
            <span>Dashboard</span>
          </li>
        </ul>

      </div>

      {/* BOTTOM SECTION */}
      <div>

        <button onClick={() => window.location.href = "/daily-review"}>
  Belzir-SIEM Daily Review
</button>

        {/* USER LOGS */}
        <div
          className="system-users-btn"
          onClick={() => navigate("/user-logs")}
        >
          <FaHistory className="icon" />
          <span>User Activity Logs</span>
        </div>

        {/* USERS */}
        <div
          className="system-users-btn"
          onClick={() => navigate("/users")}
        >
          <FaUser className="icon" />
          <span>System Users</span>
        </div>

        <div className="divider"></div>

        {/* ACTION ICONS */}
        <div className="sidebar-icons">

          {/* DARK MODE TOGGLE */}
          {darkMode ? (
            <FaSun
              className="icon"
              onClick={toggleTheme}
              title="Light Mode"
            />
          ) : (
            <FaMoon
              className="icon"
              onClick={toggleTheme}
              title="Dark Mode"
            />
          )}

          {/* LANGUAGE */}
          <FaGlobe className="icon" title="Language" />

          {/* LOGOUT */}
          <FaSignOutAlt
            className="icon"
            onClick={handleLogout}
            title="Logout"
          />
        </div>

      </div>
    </div>
  );
};

export default Sidebar;