import React, { useEffect, useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import "../../styles/SiemLayout.css";

const menuSections = [
  {
    title: "OPERATIONS",
    items: [
      { label: "Daily Review", icon: "☼", path: "/daily-review" },
      { label: "Overview", icon: "▦", path: "/overview" },
      { label: "Triage", icon: "◉", path: "/triage" },
      { label: "Incidents", icon: "⚠", path: "/incidents" },
      { label: "Patterns", icon: "▧", path: "/patterns" },
    ],
  },
  {
    title: "INTELLIGENCE",
    items: [
      { label: "Detection", icon: "◎", path: "/detection" },
      { label: "Hunt", icon: "◴", path: "/hunt" },
      { label: "Closed Loop", icon: "↻", path: "/closed-loop" },
      { label: "Investigate", icon: "⌕", path: "/investigation" },
      { label: "MITRE", icon: "▦", path: "/mitre" },
      { label: "Threat Intel", icon: "♢", path: "/threat-intel" },
      { label: "Knowledge", icon: "▣", path: "/knowledge" },
    ],
  },
  {
    title: "RESPONSE",
    items: [
      { label: "SOAR", icon: "⌘", path: "/soar" },
      { label: "Tickets", icon: "▤", path: "/tickets" },
      { label: "Respond", icon: "›_", path: "/respond" },
    ],
  },
  {
    title: "SYSTEM",
    items: [
      { label: "Metrics", icon: "▥", path: "/metrics" },
      { label: "Admin", icon: "⚙", path: "/admin" },
    ],
  },
];

export default function SiemLayout({ children }) {
  const navigate = useNavigate();
  const location = useLocation();
  const [currentTime, setCurrentTime] = useState("");

  useEffect(() => {
    const updateClock = () => {
      setCurrentTime(
        new Intl.DateTimeFormat("de-DE", {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
          hour12: false,
          timeZone: "Europe/Berlin",
        }).format(new Date())
      );
    };

    updateClock();
    const timer = setInterval(updateClock, 1000);

    return () => clearInterval(timer);
  }, []);

  return (
    <div className="siem-shell">
      <aside className="siem-leftbar">
        {menuSections.map((section) => (
          <div key={section.title}>
            <div className="siem-section">{section.title}</div>

            {section.items.map((item) => (
              <div
                key={item.label}
                className={`siem-nav ${
                  location.pathname === item.path ? "active" : ""
                }`}
                onClick={() => navigate(item.path)}
              >
                <span>{item.icon}</span>
                <span>{item.label}</span>
              </div>
            ))}
          </div>
        ))}
      </aside>

      <main className="siem-body">
        <header className="siem-topbar">
          <div></div>

          <div className="siem-topbar-right">
            <span>● Live</span>
            <span>{currentTime}</span>
            <select defaultValue="default">
              <option value="default">Belzir SOC</option>
            </select>
            <span>Analyst Console</span>
            <button type="button">Logout</button>
          </div>
        </header>

        {children}
      </main>
    </div>
  );
}