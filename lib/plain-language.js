// Plain-English translation layer for non-technical users.
// Pure, client-safe helpers: no network, no secrets.

const WEIGHTS = { critical: 25, high: 12, medium: 5, low: 1.5 };

const PLAIN = {
  "WEB-TRANSPORT-01": {
    title: "Your site is not using a secure connection",
    meaning: "Some pages load over plain HTTP. Anything typed there — passwords, messages, card details — can be read or changed by someone on the same network.",
    fix: "Turn on HTTPS for every page and automatically send visitors from the old http:// address to the secure https:// one.",
    effort: "Important",
  },
  "WEB-HSTS-01": {
    title: "Browsers are not told to always use the secure version",
    meaning: "Your site works over HTTPS, but a browser has no instruction to refuse an insecure connection next time. An attacker on the network could try to downgrade a first visit.",
    fix: "Ask your host or developer to add the Strict-Transport-Security header after confirming every subdomain supports HTTPS.",
    effort: "Easy",
  },
  "WEB-CSP-01": {
    title: "Extra protection against injected code is missing",
    meaning: "A Content-Security-Policy tells the browser which scripts are allowed. Without it, if someone ever slips malicious code onto a page, the browser has fewer limits on running it.",
    fix: "Add a Content-Security-Policy. Test it in report-only mode first so you do not break the site.",
    effort: "Medium",
  },
  "WEB-FRAME-01": {
    title: "Another site could try to hide your page inside theirs",
    meaning: "Without a framing rule, a scammer could place your page in an invisible frame and trick visitors into clicking things they did not mean to click.",
    fix: "Set frame-ancestors 'none' in the Content-Security-Policy (and X-Frame-Options for older browsers).",
    effort: "Easy",
  },
  "WEB-NOSNIFF-01": {
    title: "Browsers may guess the wrong file type",
    meaning: "A missing X-Content-Type-Options: nosniff lets a browser misread a downloaded file, which can occasionally turn an upload into a script.",
    fix: "Add the header X-Content-Type-Options: nosniff.",
    effort: "Easy",
  },
  "WEB-REFERRER-01": {
    title: "Your page addresses may leak when visitors click links",
    meaning: "Without a Referrer-Policy, the full address of your page (sometimes including private IDs) can be shared with other sites when a visitor follows a link.",
    fix: "Add a Referrer-Policy such as strict-origin-when-cross-origin.",
    effort: "Easy",
  },
  "WEB-BANNER-01": {
    title: "Your servers announce what software they run",
    meaning: "Response headers reveal the server software or framework version. That does not break anything by itself, but it helps an attacker pick the right exploit.",
    fix: "Turn off unnecessary version banners where your platform makes it easy. This is a minor improvement, not an emergency.",
    effort: "Optional",
  },
  "WEB-FORM-PASSWORD-HTTP": {
    title: "A password box is on an insecure page",
    meaning: "A login or password field appears on a plain HTTP page. Passwords typed there can be captured in transit. This is the most serious kind of finding.",
    fix: "Serve the entire login and sign-up flow over HTTPS only, and redirect the insecure version immediately.",
    effort: "Urgent",
  },
  "WEB-FORM-PASSWORD-GET": {
    title: "A password form sends data the insecure way",
    meaning: "The password form uses GET, so the password can end up in the address bar, browser history, and server logs.",
    fix: "Change the form to POST over HTTPS so passwords never appear in a URL.",
    effort: "Urgent",
  },
  "WEB-FORM-DOWNGRADE": {
    title: "A secure page sends a form to an insecure address",
    meaning: "Even though the page is HTTPS, the form posts to an http:// address. The submitted data can be read or altered on the way.",
    fix: "Point the form action at an https:// address.",
    effort: "Important",
  },
  "WEB-MIXED-CONTENT": {
    title: "A secure page loads some insecure files",
    meaning: "The page is HTTPS but pulls in images, scripts, or styles over http://. Those parts can be tampered with, and browsers may warn visitors.",
    fix: "Load every script, image, and stylesheet over HTTPS.",
    effort: "Important",
  },
  "WEB-SECURITYTXT-01": {
    title: "No security contact is published",
    meaning: "A security.txt file tells researchers where to report a problem. Without it, a good-faith report may never reach you.",
    fix: "Publish a security.txt at /.well-known/security.txt with a monitored contact.",
    effort: "Optional",
  },
  "WEB-CORS-REFLECT-01": {
    title: "Your site trusts any website, including credentials",
    meaning: "Your server appears to accept requests from any website and also allows logged-in credentials. A malicious page could read private data from a signed-in visitor's session.",
    fix: "Restrict CORS to a short allowlist of origins you control, and never reflect an arbitrary Origin when credentials are allowed.",
    effort: "Urgent",
  },
  "WEB-CORS-REFLECT-02": {
    title: "Your site accepts requests from any website",
    meaning: "Your server returned the request's own origin, meaning any site may be allowed to read responses. Check whether that is intended.",
    fix: "Replace the reflected origin with an explicit allowlist of trusted sites.",
    effort: "Important",
  },
  "WEB-METHOD-TRACE": {
    title: "An old debugging method is enabled",
    meaning: "The TRACE method is advertised. It is rarely needed and has historically exposed request contents.",
    fix: "Disable TRACE unless you have a documented reason to keep it.",
    effort: "Optional",
  },
};

function cookiePlain(id) {
  if (id.startsWith("WEB-COOKIE-SECURE-")) {
    const name = id.slice("WEB-COOKIE-SECURE-".length);
    return {
      title: `Login cookie "${name}" can travel over an insecure connection`,
      meaning: "This cookie is not marked Secure, so the browser might send it over plain HTTP where it can be intercepted.",
      fix: `Mark the "${name}" cookie as Secure so it only travels over HTTPS.`,
      effort: "Easy",
    };
  }
  if (id.startsWith("WEB-COOKIE-HTTPONLY-")) {
    const name = id.slice("WEB-COOKIE-HTTPONLY-".length);
    return {
      title: `Login cookie "${name}" can be read by page scripts`,
      meaning: "This cookie looks like a session or login cookie but is not HttpOnly, so a script injected into the page could read it.",
      fix: `Add HttpOnly to the "${name}" cookie unless a script genuinely needs it.`,
      effort: "Easy",
    };
  }
  if (id.startsWith("WEB-COOKIE-SAMESITE-")) {
    const name = id.slice("WEB-COOKIE-SAMESITE-".length);
    return {
      title: `Cookie "${name}" has no cross-site protection`,
      meaning: "Without SameSite, the cookie can be sent when a visitor arrives from another website, which weakens protection against certain request-forgery bugs.",
      fix: `Set SameSite=Lax (or Strict) on the "${name}" cookie unless cross-site use is required.`,
      effort: "Easy",
    };
  }
  return null;
}

/** Translate a deterministic website finding into owner-friendly language. */
export function plainFinding(finding) {
  const id = String(finding?.id || "");
  const mapped = PLAIN[id] || cookiePlain(id);
  const severity = String(finding?.severity || "Medium");
  return {
    id,
    severity,
    title: mapped?.title || finding?.title || "Security observation",
    meaning: mapped?.meaning || "The scanner observed something worth a closer look. Ask your developer to review the technical detail.",
    fix: mapped?.fix || finding?.recommendation || "Review the technical detail and decide on the smallest safe fix.",
    effort: mapped?.effort || effortForSeverity(severity),
    technical: {
      category: finding?.category || "Web security",
      evidence: finding?.evidence || "",
      confidence: finding?.confidence || "Medium",
      reference: finding?.reference || "",
      page: finding?.page || "",
      recommendation: finding?.recommendation || "",
    },
  };
}

function effortForSeverity(severity) {
  const key = severity.toLowerCase();
  if (key === "critical" || key === "high") return "Important";
  if (key === "medium") return "Medium";
  return "Optional";
}

/** Compute a 0–100 score and letter grade from deterministic severity counts. */
export function assessmentScore(summary = {}) {
  const counts = {
    critical: Number(summary.critical) || 0,
    high: Number(summary.high) || 0,
    medium: Number(summary.medium) || 0,
    low: Number(summary.low) || 0,
  };
  const penalty = counts.critical * WEIGHTS.critical + counts.high * WEIGHTS.high + counts.medium * WEIGHTS.medium + counts.low * WEIGHTS.low;
  const score = Math.max(0, Math.min(100, Math.round(100 - penalty)));
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
  const total = counts.critical + counts.high + counts.medium + counts.low;
  let verdict;
  if (total === 0) verdict = "No common web security problems were found in the pages we checked. That is a good result, but it is not a guarantee — keep the site updated and check again after changes.";
  else if (counts.critical > 0) verdict = "Something serious needs fixing now. This can put visitors' passwords or data at risk.";
  else if (counts.high > 0) verdict = "Important problems were found. They should be fixed soon, before more people use the site.";
  else if (counts.medium > 0) verdict = "The site is mostly in good shape, with a few worthwhile fixes.";
  else verdict = "The site looks good. There are only minor, optional improvements.";
  return { score, grade, counts, total, verdict };
}

/** Build an ordered, de-duplicated "what to do next" list. */
export function nextSteps(findings = []) {
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  const seen = new Set();
  const steps = [];
  const sorted = [...findings].sort((a, b) => (order[String(a.severity).toLowerCase()] ?? 9) - (order[String(b.severity).toLowerCase()] ?? 9));
  for (const finding of sorted) {
    const plain = plainFinding(finding);
    if (seen.has(plain.fix)) continue;
    seen.add(plain.fix);
    steps.push({ title: plain.title, fix: plain.fix, effort: plain.effort, severity: plain.severity });
    if (steps.length >= 12) break;
  }
  return steps;
}

export const GRADE_LABEL = {
  A: "Excellent",
  B: "Good",
  C: "Needs attention",
  D: "Poor",
  F: "At risk",
};

/** A prompt used to rewrite a technical report for a non-technical owner. */
export const PLAIN_REPORT_SYSTEM_PROMPT = "You rewrite a security report for a non-technical business owner. Keep every real finding but remove jargon. Structure the reply in Markdown with: a one-paragraph summary in plain words, then a numbered list titled 'What to fix and why' where each item says what is wrong, why it matters to the business, and the single next action. Then a short 'Good news' section if there is anything positive, and a one-line note that this is a bounded check, not a full guarantee. Never invent findings, dates, or guarantees. Do not use security acronyms without a plain-language explanation.";
