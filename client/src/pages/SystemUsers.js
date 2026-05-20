import React, { useEffect, useState } from "react";
import Sidebar from "./Sidebar";
import UserTable from "./UserTable";
import axios from "axios";
import { API_URL } from "../components/config";

const SystemUsers = () => {
  const [users, setUsers] = useState([]);

  const currentUser = JSON.parse(localStorage.getItem("user")); // ✅ ROLE SOURCE

  const fetchUsers = async () => {
    try {
      const token = localStorage.getItem("token");

      const res = await axios.get(`${API_URL}/api/users/users`, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });

      setUsers(res.data);
    } catch (err) {
      console.log("ERROR FETCHING USERS 👉", err.response || err);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  return (
    <div className="dashboard-container">
      <Sidebar />

      <div className="main-content">
        <UserTable
          users={users}
          refreshUsers={fetchUsers}
          currentRole={currentUser?.role}   // ✅ FIXED PASSING ROLE
        />
      </div>
    </div>
  );
};

export default SystemUsers;