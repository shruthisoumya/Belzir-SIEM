import React, { useEffect, useState } from "react";
import axios from "axios";
import "../styles/userLogs.css";

export default function UserLogs() {
  const [logs, setLogs] = useState([]);
  const [currentPage, setCurrentPage] = useState(1);
  const [logsPerPage, setLogsPerPage] = useState(10);
  const [searchQuery, setSearchQuery] = useState("");

  const API_URL = process.env.REACT_APP_API_URL || "http://10.0.3.83:5000";

  useEffect(() => {
    const fetchLogs = async () => {
      try {
        const token = localStorage.getItem("token");

        const res = await axios.get(`${API_URL}/api/users/logs`, {
  headers: {
    Authorization: `Bearer ${token}`
  }
});
        console.log("LOGS 👉", res.data);
        setLogs(res.data);

      } catch (err) {
        console.error("Failed to fetch logs", err.response || err);
      }
    };

    fetchLogs();
  }, []);

  const filteredLogs = logs.filter((log) => {
  const query = searchQuery.toLowerCase();

  return (
    (log.name || "").toLowerCase().includes(query) ||
    (log.email || "").toLowerCase().includes(query) ||
    (log.company || "").toLowerCase().includes(query) ||
    (log.event || "").toLowerCase().includes(query)
  );
});

  const totalPages = Math.max(1, Math.ceil(filteredLogs.length / logsPerPage));
  const safeCurrentPage = Math.min(currentPage, totalPages);

  const indexOfLastLog = safeCurrentPage * logsPerPage;
  const indexOfFirstLog = indexOfLastLog - logsPerPage;

  const currentLogs = filteredLogs.slice(indexOfFirstLog, indexOfLastLog);

  const goToPage = (page) => {
    if (typeof page !== "number") return;
    if (page < 1 || page > totalPages) return;
    setCurrentPage(page);
  };

  const getPageNumbers = () => {
    const pages = [];

    if (totalPages <= 1) return [1];

    if (totalPages <= 7) {
      for (let i = 1; i <= totalPages; i++) pages.push(i);
    } else {
      if (safeCurrentPage <= 4) {
        pages.push(1, 2, 3, 4, 5, "...", totalPages);
      } else if (safeCurrentPage >= totalPages - 3) {
        pages.push(
          1,
          "...",
          totalPages - 4,
          totalPages - 3,
          totalPages - 2,
          totalPages - 1,
          totalPages
        );
      } else {
        pages.push(
          1,
          "...",
          safeCurrentPage - 1,
          safeCurrentPage,
          safeCurrentPage + 1,
          "...",
          totalPages
        );
      }
    }

    return pages;
  };

  return (
    <div className="logs-container">
      <div className="table-header">
        <h2>User Activity Logs</h2>
      </div>

      <div className="pagination-top">
        <input
          type="text"
          placeholder="Search..."
          value={searchQuery}
          onChange={(e) => {
            setSearchQuery(e.target.value);
            setCurrentPage(1);
          }}
          className="logs-search-input-inline"
        />

        <button onClick={() => goToPage(safeCurrentPage - 1)} disabled={safeCurrentPage === 1}>
          Prev
        </button>

        {getPageNumbers().map((num, idx) =>
          num === "..." ? (
            <span key={`dots-${idx}`}>…</span>
          ) : (
            <button
              key={idx}
              onClick={() => goToPage(num)}
              className={num === safeCurrentPage ? "active-page" : ""}
            >
              {num}
            </button>
          )
        )}

        <button onClick={() => goToPage(safeCurrentPage + 1)} disabled={safeCurrentPage === totalPages}>
          Next
        </button>
      </div>

      <table className="logs-table">
        <thead>
          <tr>
            <th>Date & Time</th>
            <th>Name</th>
            <th>Email Address</th>
            <th>Company</th>
            <th>System Role</th>
            <th>Action</th>
            <th>Status</th>
          </tr>
        </thead>

        <tbody>
          {currentLogs.length === 0 ? (
            <tr>
              <td colSpan="7" style={{ textAlign: "center" }}>
                No activity logs found
              </td>
            </tr>
          ) : (
            currentLogs.map((log) => (
              <tr key={log._id}>
                <td>{new Date(log.createdAt).toLocaleString()}</td>
                <td>{log.name || "-"}</td>
                <td>{log.email}</td>
                <td>{log.company}</td>
                <td>{log.role || "-"}</td>
                <td>{log.event}</td>
                <td>
                  <span className={log.status?.toLowerCase() === "success" ? "status-success" : "status-failed"}>
                    {log.status}
                  </span>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}