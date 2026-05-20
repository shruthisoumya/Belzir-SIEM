require("dotenv").config(); // ✅ ADD THIS AT VERY TOP
const { ClientSecretCredential } = require("@azure/identity");
const { Client } = require("@microsoft/microsoft-graph-client");
require("isomorphic-fetch");

// ENV
const tenantId = process.env.AZURE_TENANT_ID;
const clientId = process.env.AZURE_CLIENT_ID;
const clientSecret = process.env.AZURE_CLIENT_SECRET;
const senderEmail = process.env.SENDER_EMAIL;

// 🔍 DEBUG LOGS
console.log("CLIENT:", clientId);
console.log("SECRET:", clientSecret ? "OK" : "MISSING");
console.log("SENDER:", senderEmail);

// AUTH
const credential = new ClientSecretCredential(
  tenantId,
  clientId,
  clientSecret
);

// GRAPH CLIENT
const client = Client.initWithMiddleware({
  authProvider: {
    getAccessToken: async () => {
      const token = await credential.getToken(
        "https://graph.microsoft.com/.default"
      );
      return token.token;
    }
  }
});

// ✅ ONLY ONE FUNCTION
const sendEmail = async (toEmail, content, type = "invite") => {
  try {
    console.log("🚀 EMAIL FUNCTION STARTED");
    console.log("📨 TO:", toEmail);
    console.log("📧 TYPE:", type);
    console.log("📦 CONTENT:", content);
    let subject = "";
    let bodyContent = "";

    // =========================
    // 📧 INVITE EMAIL (OLD - KEEP)
    // =========================
    if (type === "invite") {
      subject = "Action required - Belzir Invite";

      bodyContent = `
        <div style="margin:0;padding:0;background:#f5f5f5;font-family:Arial,Helvetica,sans-serif;">
          <!-- Header -->
          <div style="background:#0b5ea8;color:#fff;text-align:center;padding:12px;font-size:16px;">
            Action required
          </div>
          <!-- Card -->
          <div style="max-width:600px;margin:20px auto;background:#ffffff;border:1px solid #ddd;padding:30px;text-align:center;">
            <h1 style="color:#0b5ea8;margin-bottom:10px;">Belzir</h1>
            <h2 style="font-weight:normal;">You're invited to Belzir</h2>
            <div style="margin:25px 0;">
              <a href="${content}" 
                 target="_blank"
                 style="background-color:#0b5ea8;color:#ffffff;padding:12px 25px;text-decoration:none;border-radius:5px;display:inline-block;font-weight:bold;">
                 Set Your Password
              </a>
            </div>
            <div style="border:1px solid #0b5ea8;padding:10px;border-radius:5px;display:inline-block;color:#333;">
              Link is valid for 2 hours
            </div>
            <div style="text-align:left;margin-top:30px;color:#444;font-size:14px;">
              <p>Hello,</p>
              <p>We received a request to invite you to join your Belzir account.</p>
              <p>Click the button above to set your password and get started.</p>
              <p>If you were not expecting this invitation, you can safely ignore this email.</p>
              <p style="font-weight:bold;">Do not share this link with anyone.</p>
              <p style="margin-top:20px;">For questions or concerns, contact your administrator.</p>
              <p>Thank you,<br/>Belzir Team</p>
            </div>
          </div>
        </div>
      `;
    }

    // =========================
    // 🔐 OTP EMAIL (OLD - KEEP)
    // =========================
    if (type === "otp") {
      subject = "Action required: Your Belzir verification code";

      bodyContent = `
        <div style="font-family: Arial, sans-serif; background-color:#f4f4f4; padding:20px;">
          <div style="max-width:600px; margin:auto; background:white; border:1px solid #ddd;">
            <div style="background:#0b5cab; color:white; text-align:center; padding:10px; font-weight:bold;">Action required</div>
            <div style="text-align:center; padding:20px;">
              <h1 style="color:#0b5cab; margin:0;">Belzir</h1>
            </div>
            <div style="text-align:center;">
              <h2 style="margin:0;">Your Belzir code: ${content}</h2>
              <div style="display:inline-block;margin-top:10px;padding:8px 16px;border:1px solid #0b5cab;border-radius:6px;color:#0b5cab;font-size:14px;">
                Code is valid for 5 minutes
              </div>
            </div>
            <div style="padding:20px; color:#333; font-size:14px; line-height:1.6;">
              <p>Hello,</p>
              <p>We received your request to sign in to your Belzir account.</p>
              <p>Your one-time code is:</p>
              <h2 style="letter-spacing:4px;">${content}</h2>
              <p>If you are not attempting to sign in to your account, it is possible that someone else is using your credentials. <strong>Do not forward this code to anyone.</strong></p>
              <p>For questions or concerns, contact your administrator or support team.</p>
              <p>Thank you,<br/>Belzir Team</p>
            </div>
          </div>
        </div>
      `;
    }

    // =========================
    // ✅ MFA ENABLED EMAIL
    // =========================
   if (type === "mfa-enabled") {
  subject = "MFA Activated – OTP Disabled Until MFA Is Re-enabled";

  bodyContent = `
    <div style="margin:0;padding:0;background:#f5f5f5;font-family:Arial,Helvetica,sans-serif;">
      
      <!-- Header -->
      <div style="background:#0b5ea8;color:#fff;text-align:center;padding:12px;font-size:16px;">
        Action required
      </div>

      <!-- Card -->
      <div style="max-width:600px;margin:20px auto;background:#ffffff;border:1px solid #ddd;padding:30px;">
        
        <!-- Logo -->
        <h1 style="color:#0b5ea8;text-align:center;margin-bottom:10px;">Belzir</h1>

        <!-- Title -->
        <h2 style="font-weight:normal;text-align:center;">
          MFA Activated – OTP Disabled Until MFA Is Re-enabled
        </h2>

        <!-- Body -->
        <div style="margin-top:25px;color:#444;font-size:14px;line-height:1.6;">
          
          <p>Dear ${content},</p>

          <p>
            We are writing to confirm that multi-factor authentication (MFA) using an authenticator app has been successfully activated for your account.
          </p>

          <p>
            As a result, one-time passwords (OTP) delivered via email have been disabled as an authentication method. OTP will remain disabled until MFA is turned off again in your account settings.
          </p>

          <p><strong>What this means for you:</strong></p>

          <ul>
            <li>You will now be required to enter a code from your authenticator app after your password.</li>
            <li>You will no longer receive or be prompted for OTP codes via email or SMS while MFA is active.</li>
          </ul>

          <p>
            If you did not authorize this change, please disable MFA immediately via your security settings, reset your password, and contact our support team at support@belzir.com.
          </p>

          <p>
            For assistance, reply to this email or visit our Help Center.
          </p>

          <p>
            Stay secure,<br/>
            Your Belzir Security Team
          </p>

        </div>
      </div>
    </div>
  `;
}

    // =========================
    // ✅ MFA DISABLED EMAIL
    // =========================
  if (type === "mfa-disabled") {
  subject = "MFA Disabled – Action Required: Confirm Your OTP Status";

  bodyContent = `
    <div style="margin:0;padding:0;background:#f5f5f5;font-family:Arial,Helvetica,sans-serif;">
      
      <!-- Header -->
      <div style="background:#0b5ea8;color:#fff;text-align:center;padding:12px;font-size:16px;">
        Action required
      </div>

      <!-- Card -->
      <div style="max-width:600px;margin:20px auto;background:#ffffff;border:1px solid #ddd;padding:30px;">
        
        <!-- Logo -->
        <h1 style="color:#0b5ea8;text-align:center;margin-bottom:10px;">Belzir</h1>

        <!-- Title -->
        <h2 style="font-weight:normal;text-align:center;">
          MFA Disabled – Action Required: Confirm Your OTP Status
        </h2>

        <!-- Body -->
        <div style="margin-top:25px;color:#444;font-size:14px;line-height:1.6;">
          
          <p>Dear ${content},</p>

          <p>
            We are writing to confirm that multi-factor authentication (MFA) using an authenticator app has been successfully disabled for your account.
          </p>

          <p>
            However, please be aware that one-time passwords (OTP) delivered via your registered email remain active as a second authentication factor.
          </p>

          <p><strong>What this means for you:</strong></p>

          <ul>
            <li>You will no longer be prompted to enter a code from your authenticator app during login.</li>
            <li>You will still be required to enter an OTP sent to your email or phone (if enabled) after entering your password.</li>
          </ul>

          <p>
            If you did not initiate this change, please reset your password immediately and contact our support team at support@belzir.com.
          </p>

          <p>
            For any questions, reply to this email or visit our Help Center.
          </p>

          <p>
            Stay secure,<br/>
            Your Belzir Security Team
          </p>

        </div>
      </div>
    </div>
  `;
}
    // =========================
    // SEND EMAIL
    // =========================
    const response = await client
      .api(`/users/${senderEmail}/sendMail`)
      .post({
        message: {
          subject,
          body: {
            contentType: "HTML",
            content: bodyContent
          },
          toRecipients: [
            {
              emailAddress: {
                address: toEmail
              }
            }
          ]
        }
      });

    console.log("✅ EMAIL SENT SUCCESSFULLY");
    console.log("📬 GRAPH RESPONSE:", response);

  } catch (err) {
    console.error("❌ EMAIL FAILED");
    console.error("FULL ERROR 👉", err);
    console.error("GRAPH ERROR 👉", err.response?.data);
  }
};

module.exports = { sendEmail };