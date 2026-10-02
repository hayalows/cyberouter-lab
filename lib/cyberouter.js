const BASE_URL = "https://router.enclave.ai/v1";
const MAX_PROMPT_CHARS = 120_000;
const MAX_OUTPUT_TOKENS = 8_192;

export function keyFromRequest(request) {
  const direct = request.headers.get("x-cyberouter-key")?.trim();
  if (direct) return direct;

  const authorization = request.headers.get("authorization") || "";
  if (authorization.toLowerCase().startsWith("bearer ")) {
    return authorization.slice(7).trim();
  }

  return "";
}

export function validateKey(key) {
  return typeof key === "string" && key.length >= 12 && key.length <= 4096;
}

export function validateMessages(messages) {
  if (!Array.isArray(messages) || messages.length === 0 || messages.length > 40) {
    return false;
  }

  let totalChars = 0;
  for (const message of messages) {
    if (!message || !["system", "user", "assistant"].includes(message.role)) return false;
    if (typeof message.content !== "string") return false;
    totalChars += message.content.length;
  }

  return totalChars <= MAX_PROMPT_CHARS;
}

export async function cyberouterFetch(path, { key, method = "GET", body, timeoutMs = 55000 } = {}) {
  if (!validateKey(key)) {
    return {
      ok: false,
      status: 401,
      data: { error: { message: "Missing or invalid Cyberouter API key." } },
    };
  }

  const controller = new AbortController();
  const deadline = Math.min(55000, Math.max(1000, Number(timeoutMs) || 55000));
  const timer = setTimeout(() => controller.abort(), deadline);

  try {
    const response = await fetch(`${BASE_URL}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: body ? JSON.stringify(body) : undefined,
      cache: "no-store",
      signal: controller.signal,
    });

    const raw = await response.text();
    let data;
    try {
      data = raw ? JSON.parse(raw) : {};
    } catch {
      data = { error: { message: raw || `Cyberouter returned HTTP ${response.status}.` } };
    }

    return { ok: response.ok, status: response.status, data };
  } catch (error) {
    const message = error?.name === "AbortError"
      ? `Cyberouter request timed out after ${Math.round(deadline / 1000)} seconds.`
      : "Could not reach Cyberouter.";
    return { ok: false, status: 502, data: { error: { message } } };
  } finally {
    clearTimeout(timer);
  }
}

export function buildChatBody({ model, messages, maxTokens, temperature }) {
  const safeMax = Math.min(Math.max(Number(maxTokens) || 2048, 64), MAX_OUTPUT_TOKENS);
  const safeTemperature = Math.min(Math.max(Number(temperature) || 0, 0), 2);

  return {
    model: String(model || "").trim(),
    messages,
    max_tokens: safeMax,
    temperature: safeTemperature,
  };
}

export function errorMessage(data, fallback = "Cyberouter request failed.") {
  return data?.error?.message || data?.message || fallback;
}
