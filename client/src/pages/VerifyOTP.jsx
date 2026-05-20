import React, { useState } from "react";
import axios from "axios";
import { useLocation, useNavigate } from "react-router-dom";

export default function VerifyOTP() {
  const [otp, setOtp] = useState("");
  const [trustDevice, setTrustDevice] = useState(false);

  const navigate = useNavigate();
  const location = useLocation();

  const API_URL = process.env.REACT_APP_API_URL;

  const userId = location.state?.userId;

  const handleVerify = async () => {
    if (!otp) {
      alert("Enter OTP");
      return;
    }

    try {
      const res = await axios.post(
        `${API_URL}/api/users/verify-email-otp`,
        {
          userId,
          otp,
          trustDevice
        },
        {
          headers: {
            "x-device-token": localStorage.getItem("deviceToken")
          }
        }
      );

      // ✅ Save device token (VERY IMPORTANT)
      if (res.data.deviceToken) {
        localStorage.setItem("deviceToken", res.data.deviceToken);
      }

      localStorage.setItem("user", JSON.stringify(res.data.user));

      alert("Login successful ✅");
      navigate("/dashboard");

    } catch (err) {
      alert(err.response?.data?.message || "Invalid OTP");
    }
  };

  return (
    <div style={{ textAlign: "center", marginTop: "50px" }}>
      <h2>Email OTP Verification</h2>

      <input
        type="text"
        placeholder="Enter OTP"
        value={otp}
        onChange={(e) => setOtp(e.target.value)}
      />

      <br /><br />

      {/* ✅ TRUST DEVICE */}
      <div>
        <input
          type="checkbox"
          checked={trustDevice}
          onChange={(e) => setTrustDevice(e.target.checked)}
        />
        <label style={{ marginLeft: "5px" }}>
          Trust this device for 24 hours
        </label>
      </div>

      <br />

      <button onClick={handleVerify}>
        Verify OTP
      </button>
    </div>
  );
}