import React, { useEffect, useState } from "react";
import "../styles/dashboard.css";
import axios from "axios";
import { API_URL } from "../components/config";

const Dashboard = () => {
  const [users, setUsers] = useState([]);
  // ✅ GET USER
  const user = JSON.parse(localStorage.getItem("user"));

  useEffect(() => {
    axios.get(`${API_URL}/api/users/users`) // ✅ correct API
      .then(res => setUsers(res.data))
      .catch(err => console.log(err));
  }, []);

  return (
  <div>
    <h2 className="page-title">Dashboard</h2>
    
  </div>
);
};

export default Dashboard;