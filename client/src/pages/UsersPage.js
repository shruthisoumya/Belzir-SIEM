import React, { useEffect, useState } from "react";
import axios from "axios";
import UserTable from "../pages/UserTable";
import { API_URL } from "../components/config";

const UsersPage = () => {
  const [users, setUsers] = useState([]);

  const fetchUsers = async () => {
    try {
      const token = localStorage.getItem("token");

      const res = await axios.get(
        `${API_URL}/api/users/users`,   // ✅ FIXED HERE
        {
          headers: {
            Authorization: `Bearer ${token}`
          }
        }
      );

      setUsers(res.data);
    } catch (err) {
      console.error("Error fetching users:", err);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  return (
    <div>
      <UserTable users={users} refreshUsers={fetchUsers} />
    </div>
  );
};

export default UsersPage;