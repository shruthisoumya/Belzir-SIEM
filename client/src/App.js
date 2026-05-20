import React from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";

import Login from "./components/Login";
import Dashboard from "./pages/Dashboard";
import Layout from "./components/Layout";
import UsersPage from "./pages/UsersPage";
import VerifyOTP from "./pages/VerifyOTP";
import SetupMFA from "./pages/SetupMFA";
import VerifyMFA from "./pages/VerifyMFA";
import SetPassword from "./pages/SetPassword";
import Settings from "./pages/Settings";
import UserLogs from "./pages/UserLogs";

import DailyReview from "./pages/DailyReview";
import Overview from "./pages/Overview";
import Triage from "./pages/Triage";
import Incidents from "./pages/Incidents";
import Patterns from "./pages/Patterns";
import Detection from "./pages/Detection";
import Hunt from "./pages/Hunt";
import Mitre from "./pages/Mitre";
import ThreatIntel from "./pages/ThreatIntel";
import SOAR from "./pages/SOAR";
import Metrics from "./pages/Metrics";
import Investigation from "./pages/Investigation";
import ClosedLoop from "./pages/ClosedLoop";
import Respond from "./pages/Respond";

import "./App.css";

function TicketsPlaceholder() {
  return (
    <div style={{ padding: "40px", color: "#17233a" }}>
      <h1>Tickets</h1>
      <p>We don’t use this currently.</p>
    </div>
  );
}

function App() {
  return (
    <Router>
      <Routes>
        {/* SIEM */}
        <Route path="/" element={<DailyReview />} />
        <Route path="/daily-review" element={<DailyReview />} />
        <Route path="/overview" element={<Overview />} />
        <Route path="/triage" element={<Triage />} />
        <Route path="/incidents" element={<Incidents />} />
        <Route path="/patterns" element={<Patterns />} />
        <Route path="/detection" element={<Detection />} />
        <Route path="/hunt" element={<Hunt />} />
        <Route path="/mitre" element={<Mitre />} />
        <Route path="/threat-intel" element={<ThreatIntel />} />
        <Route path="/soar" element={<SOAR />} />
        <Route path="/tickets" element={<TicketsPlaceholder />} />
        <Route path="/respond" element={<Respond />} />
        <Route path="/metrics" element={<Metrics />} />
        <Route path="/investigation" element={<Investigation />} />
        <Route path="/closed-loop" element={<ClosedLoop />} />

        {/* Auth */}
        <Route path="/login" element={<Login />} />
        <Route path="/set-password" element={<SetPassword />} />
        <Route path="/setup-mfa" element={<SetupMFA />} />
        <Route path="/verify-mfa" element={<VerifyMFA />} />
        <Route path="/verify-otp" element={<VerifyOTP />} />

        {/* Legacy Belzir IAM */}
        <Route element={<Layout />}>
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/users" element={<UsersPage />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/user-logs" element={<UserLogs />} />
        </Route>
      </Routes>
    </Router>
  );
}

export default App;