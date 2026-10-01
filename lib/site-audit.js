import dns from "node:dns/promises";
import net from "node:net";

const USER_AGENT = "Cyberouter-Lab/1.0 (+authorized defensive security testing)";
const MAX_BODY_CHARS = 750_000;
const MAX_REDIRECTS = 4;
const PROBE_ORIGIN = "https://cyberouter-probe.invalid";

function canonicalHost(hostname = "") {
  return hostname.toLowerCase().replace(/\.$/, "").replace(/^www\./, "");
}

function isPrivateIPv4(address) {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b] = parts;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && (b === 0 || b === 168)) return true;
  if (a === 198 && (b === 18 || b === 19 || b === 51)) return true;
  if (a === 203 && b === 0) return true;
  if (a >= 224) return true;
  return false;
}

function isPrivateIPv6(address) {
  const value = address.toLowerCase();
  if (value === "::" || value === "::1") return true;
  if (value.startsWith("fc") || value.startsWith("fd")) return true;
  if (/^fe[89ab]/.test(value)) return true;
  if (value.startsWith("2001:db8")) return true;
  if (value.startsWith("::ffff:")) {
    const mapped = value.slice(7);
    if (net.isIP(mapped) === 4) return isPrivateIPv4(mapped);
  }
  return false;
}

function isBlockedHostname(hostname) {
  const h = hostname.toLowerCase().replace(/\.$/, "");
  return h === "localhost"
    || h.endsWith(".localhost")
    || h.endsWith(".local")
    || h === "metadata.google.internal"
    || h.endsWith(".internal");
}

async function assertPublicUrl(input, expectedHost = "") {
  let value = String(input || "").trim();
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) value = `https://${value}`;

  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error("Enter a valid website URL.");
  }

  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Only HTTP and HTTPS targets are supported.");
  if (url.username || url.password) throw new Error("Credentials in target URLs are not supported.");
  if (url.port && !["80", "443"].includes(url.port)) throw new Error("Only standard web ports 80 and 443 are supported.");
  if (isBlockedHostname(url.hostname)) throw new Error("Local, private, or internal targets are blocked from the hosted scanner.");
  if (expectedHost && canonicalHost(url.hostname) !== canonicalHost(expectedHost)) {
    throw new Error("The target redirected outside the verified hostname, so the scan stopped.");
  }

  const ipType = net.isIP(url.hostname);
  if (ipType === 4 && isPrivateIPv4(url.hostname)) throw new Error("Private or reserved IP targets are blocked.");
  if (ipType === 6 && isPrivateIPv6(url.hostname)) throw new Error("Private or reserved IP targets are blocked.");

  if (!ipType) {
    let records;
    try {
      records = await dns.lookup(url.hostname, { all: true, verbatim: true });
    } catch {
      throw new Error("The target hostname could not be resolved.");
    }
    if (!records.length) throw new Error("The target hostname did not resolve to a public address.");
    for (const record of records) {
      if ((record.family === 4 && isPrivateIPv4(record.address)) || (record.family === 6 && isPrivateIPv6(record.address))) {
        throw new Error("The target resolves to a private or reserved address, so the hosted scanner will not connect.");
      }
    }
  }

  return url;
}

async function safeFetch(input, { method = "GET", headers = {}, expectedHost = "", timeoutMs = 8_000 } = {}) {
  let current = await assertPublicUrl(input, expectedHost);
  const scopeHost = expectedHost || current.hostname;

  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let response;
    try {
      response = await fetch(current, {
        method,
        headers: {
          "User-Agent": USER_AGENT,
          Accept: "text/html,application/xhtml+xml,text/plain,application/json;q=0.7,*/*;q=0.2",
          ...headers,
        },
        redirect: "manual",
        cache: "no-store",
        signal: controller.signal,
      });
    } catch (error) {
      clearTimeout(timer);
      if (error?.name === "AbortError") throw new Error(`Request timed out for ${current.hostname}.`);
      throw new Error(`Could not connect to ${current.hostname}.`);
    }
    clearTimeout(timer);

    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      if (!location) return { response, url: current };
      const next = new URL(location, current);
      current = await assertPublicUrl(next.toString(), scopeHost);
      continue;
    }

    return { response, url: current };
  }

  throw new Error("Too many redirects.");
}

async function responseTextLimited(response) {
  const text = await response.text();
  return { text: text.slice(0, MAX_BODY_CHARS), truncated: text.length > MAX_BODY_CHARS };
}

function headerSnapshot(headers) {
  const wanted = [
    "content-type", "content-security-policy", "content-security-policy-report-only",
    "strict-transport-security", "x-content-type-options", "x-frame-options",
    "referrer-policy", "permissions-policy", "cross-origin-opener-policy",
    "cross-origin-resource-policy", "cross-origin-embedder-policy",
    "access-control-allow-origin", "access-control-allow-credentials",
    "server", "x-powered-by", "cache-control", "vary",
  ];
  const out = {};
  for (const key of wanted) {
    const value = headers.get(key);
    if (value) out[key] = value.slice(0, 800);
  }
  return out;
}

function safeCookieSummary(headers) {
  let values = [];
  try {
    if (typeof headers.getSetCookie === "function") values = headers.getSetCookie();
  } catch {
    values = [];
  }
  if (!values.length) {
    const combined = headers.get("set-cookie");
    if (combined) values = [combined];
  }
  return values.slice(0, 30).map((cookie) => {
    const parts = cookie.split(";").map((part) => part.trim());
    const name = (parts[0] || "").split("=")[0] || "cookie";
    const attrs = parts.slice(1).map((part) => part.split("=")[0].toLowerCase());
    const sameSitePart = parts.slice(1).find((part) => /^samesite=/i.test(part));
    return {
      name: name.slice(0, 120),
      secure: attrs.includes("secure"),
      httpOnly: attrs.includes("httponly"),
      sameSite: sameSitePart ? sameSitePart.split("=")[1] || "" : "",
    };
  });
}

function attr(tag, name) {
  const pattern = new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i");
  const match = tag.match(pattern);
  return match ? (match[1] ?? match[2] ?? match[3] ?? "") : "";
}

function extractLinks(html, baseUrl) {
  const links = [];
  const seen = new Set();
  const pattern = /<a\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>/gi;
  let match;
  while ((match = pattern.exec(html)) && links.length < 80) {
    const href = match[1] ?? match[2] ?? match[3] ?? "";
    if (!href || href.startsWith("#") || /^(mailto:|tel:|javascript:|data:)/i.test(href)) continue;
    try {
      const url = new URL(href, baseUrl);
      if (!["http:", "https:"].includes(url.protocol)) continue;
      if (canonicalHost(url.hostname) !== canonicalHost(new URL(baseUrl).hostname)) continue;
      if (/\/(logout|log-out|signout|sign-out|delete|remove|unsubscribe|activate|confirm)(\/|$)/i.test(url.pathname)) continue;
      url.hash = "";
      url.search = "";
      const key = url.toString();
      if (!seen.has(key)) {
        seen.add(key);
        links.push(key);
      }
    } catch {
      // Ignore malformed links.
    }
  }
  return links;
}

function extractForms(html, baseUrl) {
  const forms = [];
  const formPattern = /<form\b[^>]*>[\s\S]*?<\/form>/gi;
  let match;
  while ((match = formPattern.exec(html)) && forms.length < 30) {
    const tag = match[0].match(/^<form\b[^>]*>/i)?.[0] || "<form>";
    const method = (attr(tag, "method") || "get").toUpperCase();
    const actionRaw = attr(tag, "action") || baseUrl;
    let action = actionRaw;
    try { action = new URL(actionRaw, baseUrl).toString(); } catch {}
    const hasPassword = /<input\b[^>]*\btype\s*=\s*(?:"password"|'password'|password)/i.test(match[0]);
    const hasFile = /<input\b[^>]*\btype\s*=\s*(?:"file"|'file'|file)/i.test(match[0]);
    forms.push({ method, action, hasPassword, hasFile });
  }
  return forms;
}

function mixedContent(html, pageUrl) {
  if (!String(pageUrl).startsWith("https://")) return [];
  const hits = [];
  const pattern = /<(?:script|img|link|iframe|source)\b[^>]*(?:src|href)\s*=\s*(?:"(http:\/\/[^"]+)"|'(http:\/\/[^']+)'|(http:\/\/[^\s>]+))/gi;
  let match;
  while ((match = pattern.exec(html)) && hits.length < 20) {
    hits.push((match[1] ?? match[2] ?? match[3] ?? "").slice(0, 240));
  }
  return [...new Set(hits)];
}

function titleFromHtml(html) {
  const match = html.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i);
  return match ? match[1].replace(/<[^>]+>/g, "").replace(/\s+/g, " ").trim().slice(0, 180) : "";
}

function technologyHints(html, headers) {
  const hints = new Set();
  const body = html.toLowerCase();
  if (body.includes("/_next/") || headers["x-powered-by"]?.toLowerCase().includes("next")) hints.add("Next.js");
  if (body.includes("/assets/") && body.includes("type=\"module\"")) hints.add("Modern JS/Vite-style frontend");
  if (body.includes("supabase")) hints.add("Supabase reference");
  if (headers.server) hints.add(`Server: ${headers.server}`);
  if (headers["x-powered-by"]) hints.add(`X-Powered-By: ${headers["x-powered-by"]}`);
  return [...hints].slice(0, 12);
}

function finding({ id, title, severity, confidence = "High", page, evidence, recommendation, category, reference }) {
  return { id, title, severity, confidence, page, evidence, recommendation, category, reference };
}

function inspectPage(page) {
  const findings = [];
  const h = page.headers;
  const https = page.url.startsWith("https://");

  if (!https) findings.push(finding({
    id: "WEB-TRANSPORT-01", title: "Page is served over HTTP", severity: "High", page: page.url,
    evidence: "The tested page uses plaintext HTTP.", recommendation: "Redirect all traffic to HTTPS and keep sensitive functionality HTTPS-only.",
    category: "Transport security", reference: "OWASP WSTG configuration/deployment testing",
  }));
  if (https && !h["strict-transport-security"]) findings.push(finding({
    id: "WEB-HSTS-01", title: "HSTS header is missing", severity: "Medium", page: page.url,
    evidence: "Strict-Transport-Security was not present.", recommendation: "Add an HSTS policy after confirming all required subdomains support HTTPS.",
    category: "Security headers", reference: "OWASP WSTG configuration/deployment testing",
  }));
  if (!h["content-security-policy"]) findings.push(finding({
    id: "WEB-CSP-01", title: "Content Security Policy is missing", severity: "Medium", confidence: "Medium", page: page.url,
    evidence: "No Content-Security-Policy header was observed.", recommendation: "Deploy a restrictive CSP appropriate to the application and test it in report-only mode first if needed.",
    category: "Client-side security", reference: "OWASP WSTG client-side testing / ASVS v5 defense in depth",
  }));
  if (!h["x-frame-options"] && !/frame-ancestors/i.test(h["content-security-policy"] || "")) findings.push(finding({
    id: "WEB-FRAME-01", title: "No clickjacking framing policy observed", severity: "Medium", confidence: "Medium", page: page.url,
    evidence: "Neither X-Frame-Options nor CSP frame-ancestors was observed.", recommendation: "Set CSP frame-ancestors and, where compatibility requires it, X-Frame-Options.",
    category: "Client-side security", reference: "OWASP WSTG client-side testing",
  }));
  if (!h["x-content-type-options"]) findings.push(finding({
    id: "WEB-NOSNIFF-01", title: "X-Content-Type-Options is missing", severity: "Low", page: page.url,
    evidence: "X-Content-Type-Options was not present.", recommendation: "Set X-Content-Type-Options: nosniff.",
    category: "Security headers", reference: "OWASP WSTG configuration/deployment testing",
  }));
  if (!h["referrer-policy"]) findings.push(finding({
    id: "WEB-REFERRER-01", title: "Referrer-Policy is missing", severity: "Low", page: page.url,
    evidence: "Referrer-Policy was not present.", recommendation: "Set a policy appropriate to the application, commonly strict-origin-when-cross-origin or stricter.",
    category: "Privacy / browser policy", reference: "OWASP WSTG client-side testing",
  }));
  if (h.server || h["x-powered-by"]) findings.push(finding({
    id: "WEB-BANNER-01", title: "Technology banner is exposed", severity: "Low", confidence: "Medium", page: page.url,
    evidence: [h.server ? `Server: ${h.server}` : "", h["x-powered-by"] ? `X-Powered-By: ${h["x-powered-by"]}` : ""].filter(Boolean).join("; "),
    recommendation: "Remove unnecessary version/product banners where practical. Treat this as minor information exposure, not a vulnerability by itself.",
    category: "Information gathering", reference: "OWASP WSTG information gathering",
  }));

  for (const cookie of page.cookies) {
    const likelySensitive = /session|auth|token|jwt|sid|login/i.test(cookie.name);
    if (https && !cookie.secure) findings.push(finding({
      id: `WEB-COOKIE-SECURE-${cookie.name}`, title: `Cookie ${cookie.name} lacks Secure`, severity: likelySensitive ? "Medium" : "Low", page: page.url,
      evidence: `Set-Cookie for ${cookie.name} did not include Secure.`, recommendation: "Mark cookies Secure when they should only travel over HTTPS.",
      category: "Session management", reference: "OWASP WSTG session management testing",
    }));
    if (likelySensitive && !cookie.httpOnly) findings.push(finding({
      id: `WEB-COOKIE-HTTPONLY-${cookie.name}`, title: `Sensitive-looking cookie ${cookie.name} lacks HttpOnly`, severity: "Medium", confidence: "Medium", page: page.url,
      evidence: `The cookie name suggests authentication/session use and HttpOnly was not observed.`, recommendation: "Use HttpOnly for session/authentication cookies unless client-side script access is explicitly required.",
      category: "Session management", reference: "OWASP WSTG session management testing",
    }));
    if (!cookie.sameSite) findings.push(finding({
      id: `WEB-COOKIE-SAMESITE-${cookie.name}`, title: `Cookie ${cookie.name} has no SameSite attribute`, severity: "Low", confidence: "Medium", page: page.url,
      evidence: "SameSite was not observed on the Set-Cookie header.", recommendation: "Set SameSite=Lax or Strict where compatible, or SameSite=None; Secure only where cross-site use is required.",
      category: "Session management", reference: "OWASP WSTG session management testing",
    }));
  }

  for (const form of page.forms) {
    if (form.hasPassword && !https) findings.push(finding({
      id: "WEB-FORM-PASSWORD-HTTP", title: "Password form is exposed over HTTP", severity: "Critical", page: page.url,
      evidence: `A password input was found on ${page.url}.`, recommendation: "Serve the entire authentication flow over HTTPS only.",
      category: "Authentication", reference: "OWASP WSTG authentication testing",
    }));
    if (form.hasPassword && form.method === "GET") findings.push(finding({
      id: "WEB-FORM-PASSWORD-GET", title: "Password form uses GET", severity: "High", page: page.url,
      evidence: `Password form action: ${form.action}`, recommendation: "Submit credentials with POST over HTTPS and prevent sensitive values from entering URLs and logs.",
      category: "Authentication", reference: "OWASP WSTG authentication testing",
    }));
    if (https && /^http:\/\//i.test(form.action)) findings.push(finding({
      id: "WEB-FORM-DOWNGRADE", title: "HTTPS page submits a form to HTTP", severity: "High", page: page.url,
      evidence: `Form action: ${form.action}`, recommendation: "Submit forms only to HTTPS endpoints.",
      category: "Transport security", reference: "OWASP WSTG configuration/deployment testing",
    }));
  }

  if (page.mixedContent.length) findings.push(finding({
    id: "WEB-MIXED-CONTENT", title: "HTTPS page references HTTP resources", severity: "Medium", page: page.url,
    evidence: page.mixedContent.slice(0, 5).join(", "), recommendation: "Load active and passive resources over HTTPS.",
    category: "Transport security", reference: "OWASP WSTG configuration/deployment testing",
  }));

  return findings;
}

function dedupeFindings(findings) {
  const seen = new Set();
  return findings.filter((item) => {
    const key = `${item.id}|${item.page}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

async function fetchPage(url, expectedHost, extraHeaders = {}) {
  const { response, url: finalUrl } = await safeFetch(url, { expectedHost, headers: extraHeaders });
  const headers = headerSnapshot(response.headers);
  const contentType = response.headers.get("content-type") || "";
  let html = "";
  let truncated = false;

  if (/text\/html|application\/xhtml\+xml/i.test(contentType)) {
    const body = await responseTextLimited(response);
    html = body.text;
    truncated = body.truncated;
  } else {
    try { await response.body?.cancel(); } catch {}
  }

  return {
    requestedUrl: url,
    url: finalUrl.toString(),
    status: response.status,
    contentType,
    headers,
    cookies: safeCookieSummary(response.headers),
    title: html ? titleFromHtml(html) : "",
    links: html ? extractLinks(html, finalUrl) : [],
    forms: html ? extractForms(html, finalUrl) : [],
    mixedContent: html ? mixedContent(html, finalUrl) : [],
    technologies: html ? technologyHints(html, headers) : technologyHints("", headers),
    truncated,
  };
}

async function smallProbe(url, expectedHost) {
  try {
    const { response, url: finalUrl } = await safeFetch(url, { expectedHost, timeoutMs: 6_000 });
    const { text } = await responseTextLimited(response);
    return { url: finalUrl.toString(), status: response.status, text: text.slice(0, 40_000), headers: headerSnapshot(response.headers) };
  } catch (error) {
    return { url, status: 0, error: error.message };
  }
}

async function verifyOwnership(target, token) {
  if (!/^cyberouter-[a-z0-9-]{16,120}$/i.test(String(token || ""))) {
    return { ok: false, reason: "Create a verification token in the browser first." };
  }
  const root = await assertPublicUrl(target);
  const verificationUrl = new URL("/.well-known/cyberouter-lab.txt", root);
  const probe = await smallProbe(verificationUrl.toString(), root.hostname);
  if (probe.status < 200 || probe.status >= 300) {
    return { ok: false, reason: `Verification file returned HTTP ${probe.status || "error"}.`, url: verificationUrl.toString() };
  }
  if (probe.text.trim() !== token.trim()) {
    return { ok: false, reason: "Verification file content did not match the token.", url: verificationUrl.toString() };
  }
  return { ok: true, url: verificationUrl.toString() };
}

export async function auditPublicSite(target, { mode = "passive", authorizationToken = "", authorized = false } = {}) {
  const root = await assertPublicUrl(target);
  const rootUrl = root.toString();
  const expectedHost = root.hostname;
  const active = mode === "active";

  let verification = { required: active, ok: !active };
  if (active) {
    if (!authorized) throw new Error("Active checks require an explicit authorization confirmation.");
    verification = { required: true, ...(await verifyOwnership(rootUrl, authorizationToken)) };
    if (!verification.ok) {
      return {
        target: rootUrl,
        mode,
        verification,
        pages: [],
        findings: [],
        probes: {},
        summary: { pagesScanned: 0, critical: 0, high: 0, medium: 0, low: 0 },
      };
    }
  }

  const maxPages = active ? 10 : 6;
  const queue = [rootUrl];
  const visited = new Set();
  const pages = [];

  while (queue.length && pages.length < maxPages) {
    const next = queue.shift();
    if (visited.has(next)) continue;
    visited.add(next);
    try {
      const page = await fetchPage(next, expectedHost);
      pages.push(page);
      for (const link of page.links) {
        if (pages.length + queue.length >= maxPages * 3) break;
        if (!visited.has(link) && !queue.includes(link)) queue.push(link);
      }
    } catch (error) {
      pages.push({
        requestedUrl: next,
        url: next,
        status: 0,
        error: error.message,
        headers: {},
        cookies: [],
        links: [],
        forms: [],
        mixedContent: [],
        technologies: [],
      });
    }
  }

  const findings = dedupeFindings(pages.flatMap((page) => page.status ? inspectPage(page) : []));

  const probes = {
    securityTxt: await smallProbe(new URL("/.well-known/security.txt", root).toString(), expectedHost),
    robotsTxt: await smallProbe(new URL("/robots.txt", root).toString(), expectedHost),
  };

  if (probes.securityTxt.status === 404 || probes.securityTxt.status === 0) {
    findings.push(finding({
      id: "WEB-SECURITYTXT-01", title: "security.txt was not found", severity: "Low", confidence: "High", page: rootUrl,
      evidence: `/.well-known/security.txt returned ${probes.securityTxt.status || "no response"}.`,
      recommendation: "Consider publishing a security.txt file with a monitored security contact and disclosure policy.",
      category: "Security operations", reference: "RFC 9116 / vulnerability disclosure hygiene",
    }));
  }

  if (active) {
    try {
      const cors = await fetchPage(rootUrl, expectedHost, { Origin: PROBE_ORIGIN });
      const acao = cors.headers["access-control-allow-origin"] || "";
      const acac = (cors.headers["access-control-allow-credentials"] || "").toLowerCase();
      probes.cors = { status: cors.status, allowOrigin: acao, allowCredentials: acac };
      if (acao === PROBE_ORIGIN && acac === "true") {
        findings.push(finding({
          id: "WEB-CORS-REFLECT-01", title: "Arbitrary Origin appears trusted with credentials", severity: "High", confidence: "High", page: rootUrl,
          evidence: `Probe Origin ${PROBE_ORIGIN} was reflected and Access-Control-Allow-Credentials was true.`,
          recommendation: "Use an explicit CORS allowlist and never reflect untrusted Origin values when credentials are allowed.",
          category: "Authorization / browser boundary", reference: "OWASP WSTG configuration and client-side testing",
        }));
      } else if (acao === PROBE_ORIGIN) {
        findings.push(finding({
          id: "WEB-CORS-REFLECT-02", title: "Arbitrary Origin appears to be reflected", severity: "Medium", confidence: "High", page: rootUrl,
          evidence: `Probe Origin ${PROBE_ORIGIN} was returned in Access-Control-Allow-Origin.`,
          recommendation: "Review whether arbitrary origins should be allowed to read responses and replace reflection with an explicit allowlist where appropriate.",
          category: "Authorization / browser boundary", reference: "OWASP WSTG configuration and client-side testing",
        }));
      }
    } catch (error) {
      probes.cors = { error: error.message };
    }

    try {
      const { response } = await safeFetch(rootUrl, { method: "OPTIONS", expectedHost, timeoutMs: 6_000 });
      const allow = response.headers.get("allow") || response.headers.get("access-control-allow-methods") || "";
      probes.methods = { status: response.status, allow: allow.slice(0, 300) };
      if (/\bTRACE\b/i.test(allow)) {
        findings.push(finding({
          id: "WEB-METHOD-TRACE", title: "TRACE is advertised as an allowed method", severity: "Low", confidence: "Medium", page: rootUrl,
          evidence: `Allow/Access-Control-Allow-Methods: ${allow}`, recommendation: "Disable TRACE unless there is a documented operational requirement.",
          category: "HTTP configuration", reference: "OWASP WSTG configuration/deployment testing",
        }));
      }
    } catch (error) {
      probes.methods = { error: error.message };
    }
  }

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const item of findings) {
    const key = item.severity.toLowerCase();
    if (counts[key] !== undefined) counts[key] += 1;
  }

  return {
    target: rootUrl,
    finalUrl: pages[0]?.url || rootUrl,
    mode,
    verification,
    scope: {
      hostname: expectedHost,
      maxPages,
      methods: active ? ["GET", "HEAD/redirect handling", "OPTIONS"] : ["GET", "HEAD/redirect handling"],
      privateNetworkTargetsBlocked: true,
      formSubmission: false,
      credentialAttacks: false,
      exploitPayloads: false,
    },
    pages,
    findings,
    probes,
    summary: { pagesScanned: pages.filter((page) => page.status).length, ...counts },
  };
}
