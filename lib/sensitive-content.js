const SENSITIVE_ASSIGNMENT = /\b(api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|secret(?:[_-]?access[_-]?key|[_-]?key)?|password|passwd|authorization|private[_-]?key|github[_-]?token|gh[_-]?token)\b(\s*[:=]\s*)(?:"([^"\r\n]{8,})"|'([^'\r\n]{8,})'|`([^`\r\n]{8,})`|([^\s,;#}\]]{8,}))/gi;
const SENSITIVE_ASSIGNMENT_TEST = /\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|secret(?:[_-]?access[_-]?key|[_-]?key)?|password|passwd|authorization|private[_-]?key|github[_-]?token|gh[_-]?token)\b\s*[:=]\s*(?:"[^"\r\n]{8,}"|'[^'\r\n]{8,}'|`[^`\r\n]{8,}`|[^\s,;#}\]]{8,})/i;
const TOKEN_PATTERN = /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|sk-[A-Za-z0-9_-]{20,}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9_-]{12,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g;
const TOKEN_PATTERN_TEST = /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|sk-[A-Za-z0-9_-]{20,}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9_-]{12,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/;
const PRIVATE_KEY_BLOCK = /-----BEGIN ((?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY)-----[\s\S]*?-----END \1-----/gi;
const BEARER_TOKEN = /(\bBearer\s+)([A-Za-z0-9._~+/-]{12,}={0,2})/gi;
const BASIC_AUTH_URL = /(https?:\/\/[^:\s/@]+:)([^@\s/]{8,})(@)/gi;

function isPlaceholder(value) {
  const normalized = String(value || "").trim().toLowerCase();
  return !normalized
    || /^(?:\$\{?[^}]+\}?|process\.env\.[a-z0-9_]+|<[^>]+>|\[redacted\])$/i.test(normalized)
    || /^(?:your|replace|example|placeholder|changeme|redacted)[-_\s]/i.test(normalized)
    || /^(?:none|null|undefined|dummy)$/i.test(normalized);
}

function assignmentKind(line) {
  if (/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/i.test(line)) return "Private key block";
  if (TOKEN_PATTERN_TEST.test(line)) return "Recognized token format";
  if (/\bBearer\s+[A-Za-z0-9._~+/-]{12,}={0,2}/i.test(line)) return "Bearer credential";
  if (/https?:\/\/[^:\s/@]+:[^@\s/]{8,}@/i.test(line)) return "Credential in URL";
  if (SENSITIVE_ASSIGNMENT_TEST.test(line)) return "Credential assignment";
  return "";
}

/** Return only locations and signal types; never return the matched value. */
export function detectSensitiveSignals(input) {
  return String(input || "").split(/\r?\n/).flatMap((line, index) => {
    const kind = assignmentKind(line);
    return kind ? [{ line: index + 1, kind }] : [];
  });
}

/** Remove common credential formats before code or evidence is sent to a model. */
export function redactSensitiveText(input) {
  let text = String(input || "");
  let redactionCount = 0;

  text = text.replace(PRIVATE_KEY_BLOCK, (match, label) => {
    redactionCount += 1;
    return `-----BEGIN ${label}-----\n[REDACTED PRIVATE KEY]\n-----END ${label}-----`;
  });

  text = text.replace(SENSITIVE_ASSIGNMENT, (match, name, separator, doubleQuoted, singleQuoted, backtickQuoted, bare) => {
    const value = doubleQuoted ?? singleQuoted ?? backtickQuoted ?? bare ?? "";
    if (isPlaceholder(value)) return match;
    redactionCount += 1;
    const quote = doubleQuoted !== undefined ? '"' : singleQuoted !== undefined ? "'" : backtickQuoted !== undefined ? "`" : "";
    return `${name}${separator}${quote}[REDACTED]${quote}`;
  });

  text = text.replace(TOKEN_PATTERN, () => {
    redactionCount += 1;
    return "[REDACTED TOKEN]";
  });
  text = text.replace(BEARER_TOKEN, (_match, prefix) => {
    redactionCount += 1;
    return `${prefix}[REDACTED]`;
  });
  text = text.replace(BASIC_AUTH_URL, (_match, prefix, _password, suffix) => {
    redactionCount += 1;
    return `${prefix}[REDACTED]${suffix}`;
  });

  return { text, redactionCount };
}
