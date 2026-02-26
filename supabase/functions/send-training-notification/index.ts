import { serve } from "https://deno.land/std@0.190.0/http/server.ts";
import nodemailer from "npm:nodemailer@6.9.12";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

interface TrainingNotificationRequest {
  targetId: string;
  targetEmail: string;
  targetName: string;
  campaignName: string;
  clickedAt: string;
}

serve(async (req: Request): Promise<Response> => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const smtpUser = Deno.env.get("SMTP_USER");
    const smtpPass = Deno.env.get("SMTP_PASS");
    if (!smtpUser || !smtpPass) {
      throw new Error("Email service not configured. Please add SMTP_USER and SMTP_PASS.");
    }

    const authHeader = req.headers.get("Authorization");
    if (!authHeader) {
      throw new Error("No authorization header");
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
    );

    const {
      targetId,
      targetEmail,
      targetName,
      campaignName,
      clickedAt,
    }: TrainingNotificationRequest = await req.json();

    console.log(`📚 Sending training notification to ${targetEmail}`);

    const clickedDate = new Date(clickedAt).toLocaleString();
    const userName = targetName || "Employee";

    const emailHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f5f5f5;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #f5f5f5;">
    <tr>
      <td align="center" style="padding: 40px 20px;">
        <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.08);">
          <tr>
            <td style="background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%); color: white; padding: 30px 40px; text-align: center; border-radius: 8px 8px 0 0;">
              <h1 style="margin: 0; font-size: 24px; font-weight: 600;">⚠️ Security Training Required</h1>
            </td>
          </tr>
          <tr>
            <td style="padding: 40px;">
              <p style="font-size: 16px; color: #333; margin: 0 0 20px;">Dear <strong>${userName}</strong>,</p>
              <p style="font-size: 15px; color: #555; line-height: 1.6; margin: 0 0 20px;">
                During a recent security awareness simulation, you were identified as having clicked on a simulated phishing link. 
                This is an important learning opportunity to help protect yourself and our organization from real cyber threats.
              </p>
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin: 25px 0;">
                <tr>
                  <td style="background-color: #fef2f2; border-left: 4px solid #dc2626; padding: 20px; border-radius: 0 8px 8px 0;">
                    <p style="margin: 0 0 10px; font-weight: 600; color: #991b1b; font-size: 14px;">🚨 Incident Details</p>
                    <p style="margin: 0; color: #7f1d1d; font-size: 13px; line-height: 1.6;">
                      <strong>Campaign:</strong> ${campaignName}<br>
                      <strong>Clicked At:</strong> ${clickedDate}<br>
                      <strong>Status:</strong> Flagged for Training
                    </p>
                  </td>
                </tr>
              </table>
              <p style="font-size: 15px; color: #555; line-height: 1.6; margin: 0 0 20px;">
                As a result, you have been enrolled in our <strong>Security Awareness Training Program</strong>. 
                Our IT Security team will reach out to you shortly with training materials and schedule.
              </p>
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin: 25px 0;">
                <tr>
                  <td style="background-color: #f0fdf4; border-left: 4px solid #16a34a; padding: 20px; border-radius: 0 8px 8px 0;">
                    <p style="margin: 0 0 15px; font-weight: 600; color: #166534; font-size: 14px;">✅ Tips to Identify Phishing Emails:</p>
                    <ul style="margin: 0; padding-left: 20px; color: #15803d; font-size: 13px; line-height: 1.8;">
                      <li>Check the sender's email address carefully</li>
                      <li>Look for urgent or threatening language</li>
                      <li>Hover over links before clicking to see the actual URL</li>
                      <li>Be suspicious of unexpected attachments</li>
                      <li>Verify requests through official channels</li>
                      <li>When in doubt, contact IT Security</li>
                    </ul>
                  </td>
                </tr>
              </table>
              <p style="font-size: 15px; color: #555; line-height: 1.6; margin: 0 0 20px;">
                Remember: Real phishing attacks can lead to data breaches, financial loss, and compromise of sensitive information. 
                This training will help you better identify and avoid such threats in the future.
              </p>
              <p style="font-size: 15px; color: #555; margin: 0;">
                If you have any questions, please contact your IT Security team.
              </p>
            </td>
          </tr>
          <tr>
            <td style="background-color: #f8f9fa; padding: 25px 40px; border-radius: 0 0 8px 8px; border-top: 1px solid #e5e7eb;">
              <p style="margin: 0; font-size: 13px; color: #6b7280; text-align: center;">
                🔒 This is an automated message from your organization's Security Awareness Program.<br>
                <span style="color: #9ca3af;">Please do not reply to this email.</span>
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
    `;

    // Create SMTP transporter using Gmail
    const transporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 465,
      secure: true,
      auth: {
        user: smtpUser,
        pass: smtpPass,
      },
    });

    const emailResponse = await transporter.sendMail({
      from: `Security Team <${smtpUser}>`,
      to: targetEmail,
      subject: "⚠️ Security Training Required - Phishing Simulation Alert",
      html: emailHtml,
    });

    console.log("✅ Training notification sent:", emailResponse.messageId);

    // Update target with training assigned flag
    const { error: updateError } = await supabase
      .from("campaign_targets")
      .update({ status: "training_assigned" })
      .eq("id", targetId);

    if (updateError) {
      console.error("Failed to update target status:", updateError);
    }

    // Log audit event
    const token = authHeader.replace("Bearer ", "");
    const { data: userData } = await supabase.auth.getUser(token);
    
    await supabase.from("security_audit_logs").insert({
      user_id: userData.user?.id,
      action: "training_assigned",
      details: { targetId, targetEmail, campaignName },
    });

    return new Response(JSON.stringify({ success: true, messageId: emailResponse.messageId }), {
      status: 200,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  } catch (error: any) {
    console.error("❌ Error sending training notification:", error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  }
});
