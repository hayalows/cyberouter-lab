import { NextResponse } from "next/server";
import {
  buildChatBody,
  cyberouterFetch,
  errorMessage,
  keyFromRequest,
  validateMessages,
} from "@/lib/cyberouter";
import { redactSensitiveText } from "@/lib/sensitive-content";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";
export const maxDuration = 60;

export async function POST(request) {
  const key = keyFromRequest(request);

  let payload;
  try {
    payload = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const { model, messages, maxTokens = 2048, temperature = 0.1 } = payload || {};
  if (!model || typeof model !== "string") {
    return NextResponse.json({ error: "Choose a model first." }, { status: 400 });
  }
  if (!validateMessages(messages)) {
    return NextResponse.json({ error: "Messages are missing, invalid, or too large." }, { status: 400 });
  }

  const redactedMessages = messages.map((message) => ({
    ...message,
    content: redactSensitiveText(message.content).text,
  }));
  const body = buildChatBody({ model, messages: redactedMessages, maxTokens, temperature });
  const result = await cyberouterFetch("/chat/completions", {
    key,
    method: "POST",
    body,
  });

  return NextResponse.json(result.ok ? result.data : {
    error: errorMessage(result.data),
    upstreamStatus: result.status,
  }, {
    status: result.ok ? 200 : result.status,
    headers: { "Cache-Control": "no-store, max-age=0" },
  });
}
