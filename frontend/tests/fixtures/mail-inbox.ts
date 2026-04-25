/**
 * MailHog Inbox Poller
 *
 * Polls the MailHog v2 API for emails matching criteria.
 * MailHog runs at :8025 in the local dev Docker Compose stack.
 *
 * Usage:
 *   const mail = await waitForMail('user@example.com', 'Verify your email');
 *   const link = extractLink(mail.html, /verify/);
 */

interface MailHogMessage {
  ID: string;
  From: { Relays: null; Mailbox: string; Domain: string; Params: string };
  To: Array<{ Relays: null; Mailbox: string; Domain: string; Params: string }>;
  Content: {
    Headers: Record<string, string[]>;
    Body: string;
    Size: number;
    MIME: null | {
      Parts: Array<{ Headers: Record<string, string[]>; Body: string }>;
    };
  };
  Created: string;
  Raw: { From: string; To: string[]; Data: string; Helo: string };
}

interface MailHogSearchResult {
  total: number;
  count: number;
  start: number;
  items: MailHogMessage[];
}

export interface ParsedMail {
  id: string;
  from: string;
  to: string;
  subject: string;
  body: string;
  html: string;
  receivedAt: Date;
}

const MAILHOG_API = 'http://localhost:8025/api';

/**
 * Probe MailHog availability with a short timeout.
 *
 * Tests that depend on email delivery should call this and `test.skip()`
 * when it returns false so they don't time out (and pollute the report)
 * on developer machines / CI runs without the mailhog container.
 */
export async function isMailHogAvailable(timeoutMs = 1500): Promise<boolean> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    const res = await fetch(`${MAILHOG_API}/v2/messages?limit=1`, {
      signal: ctrl.signal,
    });
    clearTimeout(t);
    return res.ok;
  } catch {
    return false;
  }
}

/**
 * Search MailHog for messages sent to a specific address.
 */
async function searchMail(to: string): Promise<MailHogMessage[]> {
  const url = `${MAILHOG_API}/v2/search?kind=to&query=${encodeURIComponent(to)}`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`MailHog search failed: ${res.status} ${res.statusText}`);
  }
  const data: MailHogSearchResult = await res.json();
  return data.items;
}

/**
 * Parse a MailHog message into a simpler object.
 */
function parseMail(msg: MailHogMessage): ParsedMail {
  const subject = (msg.Content.Headers['Subject'] ?? ['(no subject)'])[0];
  const fromHeader = (msg.Content.Headers['From'] ?? [''])[0];
  const toAddr = msg.To.map((t) => `${t.Mailbox}@${t.Domain}`).join(', ');

  // Prefer HTML part from MIME, fall back to Body
  let html = '';
  let body = msg.Content.Body;
  if (msg.Content.MIME?.Parts) {
    for (const part of msg.Content.MIME.Parts) {
      const ct = (part.Headers['Content-Type'] ?? [''])[0];
      if (ct.includes('text/html')) {
        html = part.Body;
      }
      if (ct.includes('text/plain')) {
        body = part.Body;
      }
    }
  }
  if (!html) html = body;

  return {
    id: msg.ID,
    from: fromHeader,
    to: toAddr,
    subject,
    body,
    html,
    receivedAt: new Date(msg.Created),
  };
}

/**
 * Poll MailHog until a matching email arrives.
 *
 * @param to       Recipient email address
 * @param subject  Substring to match in subject line (case-insensitive)
 * @param opts.timeout  Max wait in ms (default 30 000)
 * @param opts.interval Poll interval in ms (default 1 000)
 * @param opts.after    Only match emails received after this Date
 */
export async function waitForMail(
  to: string,
  subject: string,
  opts: { timeout?: number; interval?: number; after?: Date } = {},
): Promise<ParsedMail> {
  const timeout = opts.timeout ?? 30_000;
  const interval = opts.interval ?? 1_000;
  const after = opts.after ?? new Date(Date.now() - 60_000); // default: last minute
  const deadline = Date.now() + timeout;
  const subjectLower = subject.toLowerCase();

  while (Date.now() < deadline) {
    const messages = await searchMail(to);
    for (const msg of messages) {
      const parsed = parseMail(msg);
      if (
        parsed.subject.toLowerCase().includes(subjectLower) &&
        parsed.receivedAt > after
      ) {
        return parsed;
      }
    }
    await new Promise((r) => setTimeout(r, interval));
  }
  throw new Error(
    `Timed out waiting for email to="${to}" subject~="${subject}" after ${timeout}ms`,
  );
}

/**
 * Extract the first URL from an HTML string that matches a pattern.
 *
 * @param html     HTML body of the email
 * @param pattern  RegExp or string the URL must match
 * @returns        The matched URL, or throws if none found
 */
export function extractLink(html: string, pattern: RegExp | string): string {
  const hrefRegex = /href=["']([^"']+)["']/gi;
  let match: RegExpExecArray | null;
  while ((match = hrefRegex.exec(html)) !== null) {
    const url = match[1];
    if (typeof pattern === 'string' ? url.includes(pattern) : pattern.test(url)) {
      return url;
    }
  }
  throw new Error(`No link matching ${pattern} found in email HTML`);
}

/**
 * Delete all messages in MailHog. Useful for test isolation.
 */
export async function deleteAllMail(): Promise<void> {
  const res = await fetch(`${MAILHOG_API}/v1/messages`, { method: 'DELETE' });
  if (!res.ok) {
    throw new Error(`MailHog delete failed: ${res.status}`);
  }
}

/**
 * Delete a specific message.
 */
export async function deleteMail(messageId: string): Promise<void> {
  const res = await fetch(`${MAILHOG_API}/v1/messages/${messageId}`, {
    method: 'DELETE',
  });
  if (!res.ok && res.status !== 404) {
    throw new Error(`MailHog delete message failed: ${res.status}`);
  }
}
