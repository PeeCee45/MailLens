require("dotenv").config();

const { Telegraf, Input } = require("telegraf");
const { resolveMx } = require("node:dns/promises");
const net = require("node:net");

const BOT_TOKEN = process.env.BOT_TOKEN;
const SENDER_EMAIL = (process.env.SENDER_EMAIL || "").trim();
const HELO_HOSTNAME = (process.env.HELO_HOSTNAME || "maillens.local").trim();
const SMTP_TIMEOUT = Number(process.env.SMTP_TIMEOUT || 12000);
const SMTP_DELAY_MS = Number(process.env.SMTP_DELAY_MS || 1500);
const MAX_FILE_BYTES = Number(process.env.MAX_FILE_BYTES || 1048576);
const MAX_EMAILS = Number(process.env.MAX_EMAILS || 500);

if (!BOT_TOKEN) throw new Error("BOT_TOKEN is required.");
if (!SENDER_EMAIL || !isValidEmail(SENDER_EMAIL)) {
  throw new Error("Set a valid SENDER_EMAIL in your environment.");
}

const bot = new Telegraf(BOT_TOKEN);
const activeJobs = new Map();
const mxCache = new Map();

function isValidEmail(email) {
  return typeof email === "string" &&
    email.length <= 254 &&
    /^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$/i.test(email);
}

function isValidDomain(domain) {
  return typeof domain === "string" &&
    domain.length <= 253 &&
    /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(domain);
}

function getDomain(email) {
  return email.slice(email.lastIndexOf("@") + 1).toLowerCase().replace(/\.$/, "");
}

function extractEmails(content) {
  const matches = content.match(/[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+/gi) || [];
  return [...new Set(matches.map((email) => email.toLowerCase()))];
}

async function lookupMx(domain) {
  if (mxCache.has(domain)) return mxCache.get(domain);

  const promise = (async () => {
    try {
      const records = await resolveMx(domain);
      if (!records.length) {
        return { status: "no_mx", hosts: [], primary: null };
      }

      records.sort((a, b) => a.priority - b.priority);
      return {
        status: "found",
        hosts: records.map((record) => `${record.exchange} (priority ${record.priority})`),
        primary: records[0].exchange.replace(/\.$/, "")
      };
    } catch (error) {
      const status = error.code === "ENOTFOUND"
        ? "domain_not_found"
        : ["ENODATA", "ESERVFAIL", "ETIMEOUT"].includes(error.code)
          ? "dns_error"
          : "lookup_error";

      return {
        status,
        hosts: [],
        primary: null,
        error: error.code || error.message
      };
    }
  })();

  mxCache.set(domain, promise);
  return promise;
}

class SmtpLineReader {
  constructor(socket) {
    this.socket = socket;
    this.buffer = "";
    this.lines = [];
    this.waiters = [];
    this.failure = null;

    socket.on("data", (chunk) => {
      this.buffer += chunk.toString("utf8");

      while (this.buffer.includes("\n")) {
        const index = this.buffer.indexOf("\n");
        const line = this.buffer.slice(0, index).replace(/\r$/, "");
        this.buffer = this.buffer.slice(index + 1);

        const waiter = this.waiters.shift();
        if (waiter) waiter.resolve(line);
        else this.lines.push(line);
      }
    });

    socket.on("error", (error) => this.fail(error));
    socket.on("close", () => this.fail(new Error("SMTP server closed the connection.")));
  }

  fail(error) {
    if (this.failure) return;
    this.failure = error;
    while (this.waiters.length) {
      this.waiters.shift().reject(error);
    }
  }

  nextLine() {
    if (this.lines.length) return Promise.resolve(this.lines.shift());
    if (this.failure) return Promise.reject(this.failure);

    return new Promise((resolve, reject) => {
      this.waiters.push({ resolve, reject });
    });
  }

  async readResponse() {
    const first = await this.nextLine();
    const match = first.match(/^(\d{3})([ -])(.*)$/);

    if (!match) {
      return { code: 0, response: first || "Unrecognised SMTP response" };
    }

    const code = Number(match[1]);
    const responseLines = [first];

    if (match[2] === "-") {
      while (true) {
        const line = await this.nextLine();
        responseLines.push(line);
        if (line.startsWith(`${code} `)) break;
      }
    }

    return { code, response: responseLines.join(" | ") };
  }
}

function classifySmtpResponse(stage, code, response) {
  const value = String(response || "").toLowerCase();

  const reputationTerms = [
    "spamhaus", "sorbs", "barracuda", "blacklist", "blocklist",
    "reputation", "listed on", "rbl", "dnsbl"
  ];

  if (reputationTerms.some((term) => value.includes(term))) {
    return "sender_ip_or_domain_blocklisted";
  }

  const securityTerms = [
    "recipient verification disabled",
    "recipient verification not permitted",
    "does not allow recipient verification",
    "does not accept recipient verification",
    "vrfy disabled",
    "anti-spam",
    "spam protection",
    "security policy",
    "access denied",
    "not permitted",
    "policy rejection",
    "authentication required",
    "relay access denied"
  ];

  if (
    securityTerms.some((term) => value.includes(term)) ||
    (code === 550 && /5\.7\.\d/.test(value)) ||
    (code === 554 && /5\.7\.\d/.test(value))
  ) {
    return "server_security_or_policy_restriction";
  }

  if (
    stage === "rcpt" &&
    code === 550 &&
    (/5\.1\.1/.test(value) ||
      /user unknown|unknown user|no such user|mailbox does not exist|recipient address rejected: user unknown/.test(value))
  ) {
    return "mailbox_not_found_signal";
  }

  if ([421, 450, 451, 452].includes(code) || code >= 400 && code < 500) {
    return "temporary_failure";
  }

  if (stage === "rcpt" && code >= 200 && code < 300) {
    return "accepted_unconfirmed";
  }

  return "inconclusive";
}

async function smtpProbe(email, mxHost) {
  const socket = net.createConnection({ host: mxHost, port: 25 });
  socket.setTimeout(SMTP_TIMEOUT);

  const reader = new SmtpLineReader(socket);
  let stage = "connect";

  try {
    await new Promise((resolve, reject) => {
      const onConnect = () => {
        cleanup();
        resolve();
      };
      const onError = (error) => {
        cleanup();
        reject(error);
      };
      const cleanup = () => {
        socket.off("connect", onConnect);
        socket.off("error", onError);
      };

      socket.once("connect", onConnect);
      socket.once("error", onError);
    });

    const command = async (value, nextStage) => {
      stage = nextStage;
      socket.write(`${value}\r\n`);
      return reader.readResponse();
    };

    const greeting = await reader.readResponse();
    if (greeting.code !== 220) {
      return {
        status: classifySmtpResponse("greeting", greeting.code, greeting.response),
        code: greeting.code,
        response: greeting.response
      };
    }

    const ehlo = await command(`EHLO ${HELO_HOSTNAME}`, "ehlo");
    if (ehlo.code !== 250) {
      return {
        status: classifySmtpResponse("ehlo", ehlo.code, ehlo.response),
        code: ehlo.code,
        response: ehlo.response
      };
    }

    const mailFrom = await command(`MAIL FROM:<${SENDER_EMAIL}>`, "mail_from");
    if (mailFrom.code < 200 || mailFrom.code >= 300) {
      return {
        status: classifySmtpResponse("mail_from", mailFrom.code, mailFrom.response),
        code: mailFrom.code,
        response: mailFrom.response
      };
    }

    const rcpt = await command(`RCPT TO:<${email}>`, "rcpt");

    // QUIT is best-effort; the RCPT result is the result we report.
    try {
      await command("QUIT", "quit");
    } catch (_) {}

    return {
      status: classifySmtpResponse("rcpt", rcpt.code, rcpt.response),
      code: rcpt.code,
      response: rcpt.response
    };
  } catch (error) {
    let status = "connection_error";

    if (error.code === "ETIMEDOUT" || /timed out/i.test(error.message)) {
      status = "connection_timeout";
    } else if (["ECONNREFUSED", "EHOSTUNREACH", "ENETUNREACH", "EACCES"].includes(error.code)) {
      status = "connection_blocked";
    } else if (stage !== "connect") {
      status = "inconclusive";
    }

    return {
      status,
      code: error.code || "",
      response: error.message || "SMTP connection failed"
    };
  } finally {
    socket.destroy();
  }
}

async function checkEmail(email) {
  const normalized = String(email || "").trim().toLowerCase();

  const base = {
    email: normalized,
    syntax: "invalid",
    domain: "",
    mx_status: "not_checked",
    mx_hosts: "",
    smtp_status: "not_checked",
    smtp_code: "",
    smtp_response: "",
    overall: "invalid_syntax"
  };

  if (!isValidEmail(normalized)) return base;

  const domain = getDomain(normalized);
  const mx = await lookupMx(domain);

  const result = {
    ...base,
    syntax: "valid",
    domain,
    mx_status: mx.status,
    mx_hosts: mx.hosts.join("; "),
    overall: mx.status
  };

  if (mx.status !== "found" || !mx.primary) {
    result.smtp_status = "skipped_no_mx";
    result.overall = mx.status;
    return result;
  }

  const smtp = await smtpProbe(normalized, mx.primary);
  result.smtp_status = smtp.status;
  result.smtp_code = smtp.code;
  result.smtp_response = smtp.response;
  result.overall = smtp.status;

  return result;
}

function csvEscape(value) {
  const text = String(value ?? "");
  return `"${text.replace(/"/g, '""')}"`;
}

function toCsv(rows) {
  const columns = [
    "email", "syntax", "domain", "mx_status", "mx_hosts",
    "smtp_status", "smtp_code", "smtp_response", "overall"
  ];

  return [
    columns.join(","),
    ...rows.map((row) => columns.map((column) => csvEscape(row[column])).join(","))
  ].join("\r\n");
}

function helpText() {
  return [
    "🔎 *MailLens*",
    "",
    "Inspect email syntax, domain MX records, and SMTP server responses.",
    "",
    "*Commands*",
    "/check email@example.com — check one address",
    "/mx example.com — inspect MX records",
    "/checklist — upload a TXT list",
    "/status — show service status",
    "/about — about MailLens",
    "/cancel — cancel your active bulk check",
    "/help — show this help",
    "",
    "TXT files may separate addresses with newlines, commas, semicolons, spaces, or tabs.",
    `Bulk limit: ${MAX_EMAILS} unique addresses per file.`,
    "",
    "SMTP checks are best-effort diagnostics. Use them only for addresses/domains you own or are authorised to test. Some providers intentionally prevent recipient verification."
  ].join("\n");
}

function formatResult(result) {
  const labels = {
    accepted_unconfirmed: "Accepted by server (mailbox unconfirmed)",
    mailbox_not_found_signal: "Mailbox-not-found signal",
    server_security_or_policy_restriction: "Server security/policy restriction",
    sender_ip_or_domain_blocklisted: "Sending IP/domain appears blocklisted",
    temporary_failure: "Temporary server failure",
    connection_blocked: "Connection blocked/refused",
    connection_timeout: "Connection timed out",
    connection_error: "Connection error",
    inconclusive: "Inconclusive",
    skipped_no_mx: "SMTP not checked (no usable MX)"
  };

  return [
    "🔎 *MailLens result*",
    `Email: ${result.email}`,
    `Syntax: ${result.syntax}`,
    `Domain: ${result.domain || "—"}`,
    `MX status: ${result.mx_status}`,
    `MX hosts: ${result.mx_hosts || "—"}`,
    `SMTP result: ${labels[result.smtp_status] || result.smtp_status}`,
    `SMTP code: ${result.smtp_code || "—"}`,
    `Server response: ${result.smtp_response || "—"}`,
    "",
    "Important: SMTP acceptance does not prove that a mailbox exists. A server may accept all recipients, hide recipient status, or block verification."
  ].join("\n");
}

bot.start((ctx) => ctx.reply(
  "🔎 Welcome to *MailLens*.\n\nInspect email addresses and mail infrastructure. Send /help to see available commands.",
  { parse_mode: "Markdown" }
));

bot.help((ctx) => ctx.reply(helpText(), { parse_mode: "Markdown" }));

bot.command("about", (ctx) => ctx.reply(
  "MailLens checks email syntax, retrieves DNS MX records, and reports SMTP responses. SMTP checks are diagnostic only; provider security controls are respected."
));

bot.command("status", (ctx) => ctx.reply(
  `MailLens is online.\nSMTP checks: enabled for domains with discoverable MX records.\nBulk delay: ${SMTP_DELAY_MS}ms\nMaximum addresses per file: ${MAX_EMAILS}`
));

bot.command("mx", async (ctx) => {
  const domain = (ctx.message.text.split(/\s+/)[1] || "").toLowerCase().replace(/\.$/, "");
  if (!isValidDomain(domain)) return ctx.reply("Usage: /mx example.com");

  await ctx.reply(`Looking up MX records for ${domain}...`);
  const result = await lookupMx(domain);

  if (result.status !== "found") {
    return ctx.reply(`No usable MX records found for ${domain}.\nStatus: ${result.status}`);
  }

  return ctx.reply(
    `📮 *MX records for ${domain}*\n\n${result.hosts.map((host) => `• ${host}`).join("\n")}`,
    { parse_mode: "Markdown" }
  );
});

bot.command("check", async (ctx) => {
  const email = ctx.message.text.split(/\s+/)[1];
  if (!email) return ctx.reply("Usage: /check user@example.com");

  await ctx.reply(`Checking ${email}...`);
  const result = await checkEmail(email);

  return ctx.reply(formatResult(result), { parse_mode: "Markdown" });
});

bot.command("checklist", (ctx) => ctx.reply(
  "Upload a .txt file containing the email addresses. Newlines, commas, semicolons, spaces, and tabs are supported."
));

bot.command("cancel", (ctx) => {
  const job = activeJobs.get(ctx.chat.id);
  if (!job) return ctx.reply("There is no active bulk check to cancel.");
  job.cancelled = true;
  return ctx.reply("Cancellation requested. I'll stop after the current address.");
});

bot.on("document", async (ctx) => {
  const document = ctx.message.document;
  const filename = document.file_name || "";

  if (!filename.toLowerCase().endsWith(".txt")) {
    return ctx.reply("Please upload a .txt file.");
  }

  if (document.file_size && document.file_size > MAX_FILE_BYTES) {
    return ctx.reply(`File is too large. Maximum size is ${MAX_FILE_BYTES} bytes.`);
  }

  if (activeJobs.has(ctx.chat.id)) {
    return ctx.reply("A bulk check is already running in this chat. Use /cancel before starting another.");
  }

  const job = { cancelled: false };
  activeJobs.set(ctx.chat.id, job);

  try {
    const fileUrl = await ctx.telegram.getFileLink(document.file_id);
    const response = await fetch(fileUrl.href);

    if (!response.ok) throw new Error(`Telegram file download failed: HTTP ${response.status}`);

    const buffer = Buffer.from(await response.arrayBuffer());
    if (buffer.length > MAX_FILE_BYTES) {
      throw new Error(`File exceeds the ${MAX_FILE_BYTES}-byte limit.`);
    }

    const emails = extractEmails(buffer.toString("utf8"));

    if (!emails.length) return ctx.reply("I couldn't find any email addresses in that TXT file.");
    if (emails.length > MAX_EMAILS) {
      return ctx.reply(`This file contains ${emails.length} unique addresses. The limit is ${MAX_EMAILS}.`);
    }

    await ctx.reply(
      `Found ${emails.length} unique email addresses. Starting sequential checks.\n\nOnly test addresses/domains you own or are authorised to assess.`
    );

    const results = [];

    for (let i = 0; i < emails.length; i++) {
      if (job.cancelled) break;

      const result = await checkEmail(emails[i]);
      results.push(result);

      if (i < emails.length - 1 && !job.cancelled) {
        await new Promise((resolve) => setTimeout(resolve, SMTP_DELAY_MS));
      }

      if ((i + 1) % 25 === 0 || i + 1 === emails.length) {
        await ctx.reply(`Progress: ${i + 1}/${emails.length}`);
      }
    }

    if (!results.length) return ctx.reply("No addresses were processed.");

    const suffix = job.cancelled ? "partial" : "results";
    const outputName = `maillens-${suffix}-${Date.now()}.csv`;

    await ctx.replyWithDocument(
      Input.fromBuffer(Buffer.from(toCsv(results), "utf8"), outputName),
      { caption: `MailLens ${suffix}: ${results.length} of ${emails.length} addresses processed.` }
    );

    if (job.cancelled) await ctx.reply("Bulk check cancelled.");
  } catch (error) {
    await ctx.reply(`Could not process that file: ${error.message}`);
  } finally {
    activeJobs.delete(ctx.chat.id);
  }
});

bot.catch((error, ctx) => {
  console.error("Telegram update error:", error);
  ctx.reply("Something went wrong while processing that request. Please try again.").catch(() => {});
});

bot.launch().then(() => {
  console.log("MailLens Telegram bot is running.");
}).catch((error) => {
  console.error("Failed to launch MailLens:", error);
  process.exit(1);
});

process.once("SIGINT", () => bot.stop("SIGINT"));
process.once("SIGTERM", () => bot.stop("SIGTERM"));
