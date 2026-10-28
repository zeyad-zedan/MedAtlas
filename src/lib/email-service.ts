/**
 * Transactional Email Delivery Service for MedAtlas MCQ
 *
 * Supports reputable transactional email providers:
 * - Resend (RESEND_API_KEY)
 * - Postmark (POSTMARK_SERVER_TOKEN)
 * - SendGrid (SENDGRID_API_KEY)
 *
 * Configured via server-side environment variables only.
 * Never hardcodes or exposes API keys or codes.
 */

export interface VerificationCodeEmailPayload {
  to: string;
  displayName?: string;
  code: string;
  expiresInMinutes?: number;
}

export type EmailTransportOverrideFn = (
  payload: VerificationCodeEmailPayload
) => Promise<void>;

let customEmailTransportForTests: EmailTransportOverrideFn | null = null;

export function setEmailTransportForTests(
  handler: EmailTransportOverrideFn | null
): void {
  customEmailTransportForTests = handler;
}

export function getActiveEmailProvider(): 'resend' | 'postmark' | 'sendgrid' | 'test' | 'none' {
  if (customEmailTransportForTests) return 'test';
  if (process.env.RESEND_API_KEY?.trim()) return 'resend';
  if (process.env.POSTMARK_SERVER_TOKEN?.trim()) return 'postmark';
  if (process.env.SENDGRID_API_KEY?.trim()) return 'sendgrid';
  return 'none';
}

export function getFromEmailAddress(): string {
  const custom = process.env.EMAIL_FROM?.trim();
  if (custom) return custom;
  return 'MedAtlas Security <security@medatlas.ai.studio>';
}

/**
 * Builds high-contrast, accessible HTML email template for 6-digit verification code.
 */
export function buildVerificationCodeHtml(params: {
  displayName?: string;
  code: string;
  expiresInMinutes: number;
}): string {
  const greeting = params.displayName ? `Hello ${params.displayName},` : 'Hello,';
  const formattedCode = `${params.code.slice(0, 3)} ${params.code.slice(3)}`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Your MedAtlas Verification Code</title>
</head>
<body style="margin: 0; padding: 0; background-color: #F8FAFC; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #0F172A;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #F8FAFC; padding: 40px 16px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width: 520px; background-color: #FFFFFF; border-radius: 12px; border: 1px solid #E2E8F0; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);">
          <!-- Header -->
          <tr>
            <td style="padding: 28px 32px; background-color: #0F172A; text-align: left;">
              <span style="font-size: 20px; font-weight: 700; color: #FFFFFF; letter-spacing: -0.5px;">MedAtlas MCQ</span>
              <span style="display: block; font-size: 12px; color: #94A3B8; margin-top: 4px;">Lecture-Aligned Clinical Mastery</span>
            </td>
          </tr>
          <!-- Body Content -->
          <tr>
            <td style="padding: 32px 32px 24px 32px;">
              <p style="font-size: 15px; line-height: 1.5; color: #334155; margin: 0 0 16px 0;">${greeting}</p>
              <p style="font-size: 15px; line-height: 1.5; color: #334155; margin: 0 0 24px 0;">
                You recently requested to reset your MedAtlas account password. Use the verification code below to complete your password reset:
              </p>
              
              <!-- Code Card -->
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin: 28px 0;">
                <tr>
                  <td align="center" style="background-color: #F1F5F9; border-radius: 10px; border: 1px solid #CBD5E1; padding: 22px;">
                    <div style="font-size: 11px; text-transform: uppercase; font-weight: 700; letter-spacing: 1.5px; color: #64748B; margin-bottom: 8px;">
                      Verification Code
                    </div>
                    <div style="font-family: 'SF Mono', Consolas, Monaco, monospace; font-size: 36px; font-weight: 800; letter-spacing: 6px; color: #0284C7;">
                      ${formattedCode}
                    </div>
                    <div style="font-size: 12px; color: #64748B; margin-top: 10px;">
                      Expires in <strong>${params.expiresInMinutes} minutes</strong> · Single-use only
                    </div>
                  </td>
                </tr>
              </table>

              <p style="font-size: 14px; line-height: 1.5; color: #64748B; margin: 0 0 16px 0;">
                Enter this code directly on the MedAtlas website to verify your identity and set a new password.
              </p>

              <div style="background-color: #FEF2F2; border-left: 4px solid #EF4444; padding: 12px 14px; border-radius: 4px; margin-top: 24px;">
                <p style="font-size: 12px; line-height: 1.4; color: #991B1B; margin: 0;">
                  <strong>Security notice:</strong> If you did not request this password reset, please ignore this email. Your password will remain unchanged and your account is secure.
                </p>
              </div>
            </td>
          </tr>
          <!-- Footer -->
          <tr>
            <td style="padding: 20px 32px 28px 32px; background-color: #F8FAFC; border-top: 1px solid #E2E8F0; text-align: center;">
              <p style="font-size: 11px; color: #94A3B8; margin: 0; line-height: 1.4;">
                MedAtlas MCQ Platform · Automated Security Notification<br>
                For your security, MedAtlas staff will never ask you for this code.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

/**
 * Builds plain-text email version for clients without HTML support.
 */
export function buildVerificationCodeText(params: {
  displayName?: string;
  code: string;
  expiresInMinutes: number;
}): string {
  const greeting = params.displayName ? `Hello ${params.displayName},` : 'Hello,';
  return `${greeting}

You recently requested to reset your MedAtlas MCQ account password.

Your 6-digit verification code is:
>>> ${params.code} <<<

This code expires in ${params.expiresInMinutes} minutes and can only be used once.

Enter this code directly on the MedAtlas password reset page to choose your new password.

If you did not request a password reset, you can safely ignore this email. Your account remains secure.

--
MedAtlas MCQ Platform
security@medatlas.ai.studio
`;
}

export interface SendEmailResult {
  ok: boolean;
  provider: 'resend' | 'postmark' | 'sendgrid' | 'test';
  id?: string;
  error?: string;
}

/**
 * Sends a 6-digit verification code email using the configured transactional email provider.
 * Throws ClientSafeError if no provider is configured or delivery fails.
 */
export async function sendVerificationCodeEmail(
  payload: VerificationCodeEmailPayload
): Promise<SendEmailResult> {
  const expiresInMinutes = payload.expiresInMinutes || 10;
  const to = payload.to.toLowerCase().trim();
  const subject = `Your MedAtlas Verification Code: ${payload.code}`;
  const from = getFromEmailAddress();

  const html = buildVerificationCodeHtml({
    displayName: payload.displayName,
    code: payload.code,
    expiresInMinutes,
  });

  const text = buildVerificationCodeText({
    displayName: payload.displayName,
    code: payload.code,
    expiresInMinutes,
  });

  // 1. Check custom test transport hook
  if (customEmailTransportForTests) {
    await customEmailTransportForTests(payload);
    return { ok: true, provider: 'test', id: 'test_dispatch' };
  }

  // 2. Resend provider
  const resendApiKey = process.env.RESEND_API_KEY?.trim();
  if (resendApiKey) {
    try {
      const res = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${resendApiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from,
          to: [to],
          subject,
          html,
          text,
        }),
      });

      if (!res.ok) {
        const errJson: any = await res.json().catch(() => null);
        console.error('Resend delivery failed:', {
          status: res.status,
          message: errJson?.message || 'UNKNOWN_ERROR',
        });
        throw new Error(`Resend email delivery failed with status ${res.status}`);
      }

      const data: any = await res.json().catch(() => ({}));
      return { ok: true, provider: 'resend', id: data?.id };
    } catch (err: any) {
      console.error('Resend delivery network error:', err?.message || err);
      throw err;
    }
  }

  // 3. Postmark provider
  const postmarkToken = process.env.POSTMARK_SERVER_TOKEN?.trim();
  if (postmarkToken) {
    try {
      const res = await fetch('https://api.postmarkapp.com/email', {
        method: 'POST',
        headers: {
          'X-Postmark-Server-Token': postmarkToken,
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({
          From: from,
          To: to,
          Subject: subject,
          HtmlBody: html,
          TextBody: text,
          MessageStream: 'outbound',
        }),
      });

      if (!res.ok) {
        const errJson: any = await res.json().catch(() => null);
        console.error('Postmark delivery failed:', {
          status: res.status,
          message: errJson?.Message || 'UNKNOWN_ERROR',
        });
        throw new Error(`Postmark email delivery failed with status ${res.status}`);
      }

      const data: any = await res.json().catch(() => ({}));
      return { ok: true, provider: 'postmark', id: data?.MessageID };
    } catch (err: any) {
      console.error('Postmark delivery network error:', err?.message || err);
      throw err;
    }
  }

  // 4. SendGrid provider
  const sendgridApiKey = process.env.SENDGRID_API_KEY?.trim();
  if (sendgridApiKey) {
    try {
      const res = await fetch('https://api.sendgrid.com/v3/mail/send', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${sendgridApiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          personalizations: [{ to: [{ email: to }] }],
          from: { email: from.includes('<') ? from.replace(/.*<([^>]+)>.*/, '$1') : from },
          subject,
          content: [
            { type: 'text/plain', value: text },
            { type: 'text/html', value: html },
          ],
        }),
      });

      if (!res.ok) {
        const errText = await res.text().catch(() => '');
        console.error('SendGrid delivery failed:', {
          status: res.status,
          error: errText.slice(0, 200),
        });
        throw new Error(`SendGrid email delivery failed with status ${res.status}`);
      }

      return { ok: true, provider: 'sendgrid' };
    } catch (err: any) {
      console.error('SendGrid delivery network error:', err?.message || err);
      throw err;
    }
  }

  // 5. No provider configured
  const errorMsg =
    'Transactional email delivery is not configured on this server. Set RESEND_API_KEY, POSTMARK_SERVER_TOKEN, or SENDGRID_API_KEY and EMAIL_FROM in your server environment.';
  console.error('sendVerificationCodeEmail:', errorMsg);
  const unconfiguredErr = new Error(errorMsg);
  (unconfiguredErr as any).isUnconfigured = true;
  throw unconfiguredErr;
}
