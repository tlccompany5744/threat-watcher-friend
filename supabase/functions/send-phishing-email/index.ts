import { serve } from "https://deno.land/std@0.190.0/http/server.ts";
import nodemailer from "npm:nodemailer@6.9.12";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

interface SendEmailRequest {
  campaignId: string;
  targetId: string;
  targetEmail: string;
  targetName: string;
  subject: string;
  bodyHtml: string;
  senderName: string;
  senderEmail: string;
  trackingUrl: string;
  attachmentUrl?: string | null;
  attachmentName?: string | null;
}

serve(async (req: Request): Promise<Response> => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const smtpUser = Deno.env.get("SMTP_USER");
    const smtpPass = Deno.env.get("SMTP_PASS");
    if (!smtpUser || !smtpPass) {
      console.error("SMTP credentials not configured");
      throw new Error("Email service not configured. Please add SMTP_USER and SMTP_PASS.");
    }

    const authHeader = req.headers.get("Authorization");
    if (!authHeader) {
      console.error("No authorization header provided");
      throw new Error("No authorization header");
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
    );

    const {
      campaignId,
      targetId,
      targetEmail,
      targetName,
      subject,
      bodyHtml,
      senderName,
      senderEmail,
      trackingUrl,
      attachmentUrl,
      attachmentName,
    }: SendEmailRequest = await req.json();

    console.log(`📧 Sending phishing simulation email to ${targetEmail}`);
    console.log(`Campaign: ${campaignId}, Target: ${targetId}`);

    // Create tracking pixel URL
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const projectUrl = supabaseUrl?.replace('.supabase.co', '.functions.supabase.co');
    const trackingPixelUrl = `${projectUrl}/functions/v1/track-email?tid=${targetId}&action=open`;
    const clickUrl = `${projectUrl}/functions/v1/track-email?tid=${targetId}&action=click&redirect=${encodeURIComponent(trackingUrl)}`;

    console.log(`Tracking URLs configured`);

    // Build email HTML
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
            <td style="padding: 40px;">
              ${bodyHtml.replace(/\[CLICK_LINK\]/g, clickUrl).replace(/\[TARGET_NAME\]/g, targetName || 'User')}
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
  <img src="${trackingPixelUrl}" width="1" height="1" style="display:none;" alt="" />
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

    // Prepare mail options
    const mailOptions: any = {
      from: `${senderName} <${smtpUser}>`,
      to: targetEmail,
      subject: subject,
      html: emailHtml,
      replyTo: senderEmail,
    };

    // Add attachment if provided
    if (attachmentUrl && attachmentName) {
      try {
        console.log(`Fetching attachment: ${attachmentName}`);
        const attachmentResponse = await fetch(attachmentUrl);
        
        if (attachmentResponse.ok) {
          const attachmentBuffer = await attachmentResponse.arrayBuffer();
          mailOptions.attachments = [{
            filename: attachmentName,
            content: Buffer.from(attachmentBuffer),
          }];
          console.log(`Attachment added: ${attachmentName} (${attachmentBuffer.byteLength} bytes)`);
        } else {
          console.warn(`Failed to fetch attachment: ${attachmentResponse.status}`);
        }
      } catch (attachError) {
        console.error("Error processing attachment:", attachError);
      }
    }

    // Send via SMTP
    console.log(`Sending email via Gmail SMTP to: ${targetEmail}`);
    const emailResponse = await transporter.sendMail(mailOptions);

    console.log("✅ Email sent successfully:", emailResponse.messageId);

    // Update target status to sent
    const { error: updateError } = await supabase
      .from("campaign_targets")
      .update({ status: "sent", sent_at: new Date().toISOString() })
      .eq("id", targetId);

    if (updateError) {
      console.error("Failed to update target status:", updateError);
    }

    // Log audit event
    const token = authHeader.replace("Bearer ", "");
    const { data: userData } = await supabase.auth.getUser(token);
    
    await supabase.from("security_audit_logs").insert({
      user_id: userData.user?.id,
      action: "email_sent",
      details: { campaignId, targetId, targetEmail },
    });

    return new Response(JSON.stringify({ success: true, messageId: emailResponse.messageId }), {
      status: 200,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  } catch (error: any) {
    console.error("❌ Error sending email:", error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  }
});
