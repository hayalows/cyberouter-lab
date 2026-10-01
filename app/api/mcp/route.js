import { createMcpHandler, withMcpAuth } from "mcp-handler";
import { z } from "zod";
import { buildChatBody, cyberouterFetch, errorMessage, validateKey } from "@/lib/cyberouter";
import { auditPublicSite } from "@/lib/site-audit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

function tokenFromContext(ctx) {
  return ctx?.http?.authInfo?.token || "";
}

async function callChat(key, { model, system, prompt, maxTokens = 2400 }) {
  const messages = [];
  if (system) messages.push({ role: "system", content: system });
  messages.push({ role: "user", content: prompt });

  const result = await cyberouterFetch("/chat/completions", {
    key,
    method: "POST",
    body: buildChatBody({ model, messages, maxTokens, temperature: 0.1 }),
  });

  if (!result.ok) throw new Error(errorMessage(result.data));
  const responseText = result.data?.choices?.[0]?.message?.content || "No text response returned.";
  const usage = result.data?.usage;

  return {
    content: [{
      type: "text",
      text: usage
        ? `${responseText}\n\nUsage: ${JSON.stringify(usage)}`
        : responseText,
    }],
  };
}

const handler = createMcpHandler((server) => {
  server.registerTool(
    "cyberouter_list_models",
    {
      title: "List Cyberouter models",
      description: "List the live models available to the supplied Cyberouter API key.",
      inputSchema: z.object({}),
    },
    async (_args, ctx) => {
      const result = await cyberouterFetch("/models", { key: tokenFromContext(ctx) });
      if (!result.ok) throw new Error(errorMessage(result.data));
      return {
        content: [{ type: "text", text: JSON.stringify(result.data, null, 2) }],
      };
    },
  );

  server.registerTool(
    "cyberouter_security_review",
    {
      title: "Cyberouter security review",
      description: "Run an evidence-focused defensive security review of authorized code or a diff using a chosen Cyberouter model.",
      inputSchema: z.object({
        model: z.string().min(1),
        code: z.string().min(1).max(100000),
        context: z.string().max(12000).optional(),
        maxTokens: z.number().int().min(256).max(8192).optional(),
      }),
    },
    async ({ model, code, context, maxTokens }, ctx) => callChat(tokenFromContext(ctx), {
      model,
      maxTokens,
      system: "You are a defensive application-security reviewer. Analyze only the authorized code and context supplied. Focus on concrete vulnerabilities, attack preconditions, exact evidence, false-positive checks, realistic impact, and minimal remediation. Do not invent findings. Clearly separate confirmed issues from hypotheses.",
      prompt: `${context ? `Context:\n${context}\n\n` : ""}Code or diff to review:\n\n${code}`,
    }),
  );

  server.registerTool(
    "cyberouter_triage_finding",
    {
      title: "Triage a security finding",
      description: "Ask a chosen Cyberouter model to assess whether a suspected security issue is supported by the supplied evidence.",
      inputSchema: z.object({
        model: z.string().min(1),
        finding: z.string().min(1).max(30000),
        evidence: z.string().min(1).max(70000),
        maxTokens: z.number().int().min(256).max(8192).optional(),
      }),
    },
    async ({ model, finding, evidence, maxTokens }, ctx) => callChat(tokenFromContext(ctx), {
      model,
      maxTokens,
      system: "You are a defensive security triage analyst. Test the claimed issue against the supplied evidence. Identify assumptions, attack preconditions, disconfirming evidence, confidence, likely impact, and the smallest safe remediation. Do not claim exploitability without evidence.",
      prompt: `Suspected finding:\n${finding}\n\nEvidence:\n${evidence}`,
    }),
  );

  server.registerTool(
    "cyberouter_passive_web_audit",
    {
      title: "Passive website security audit",
      description: "Perform a bounded, read-only security assessment of a public website using GET requests only, then ask a chosen Cyberouter model to interpret the evidence. Private/internal network targets, form submission, credential attacks, and exploit payloads are blocked.",
      inputSchema: z.object({
        model: z.string().min(1),
        url: z.string().min(4).max(2000),
        maxTokens: z.number().int().min(256).max(8192).optional(),
      }),
    },
    async ({ model, url, maxTokens }, ctx) => {
      const evidence = await auditPublicSite(url, { mode: "passive" });
      return callChat(tokenFromContext(ctx), {
        model,
        maxTokens: maxTokens || 3200,
        system: "You are a defensive web application security reviewer. Interpret only the supplied bounded passive scan evidence. Use OWASP WSTG and ASVS concepts as a taxonomy, not as a claim of compliance. Separate confirmed observations from risks that require authenticated or active testing. Return clean Markdown with severity, confidence, evidence, likely impact, remediation, and a short follow-up test plan. Do not invent endpoints or exploitability.",
        prompt: `Target: ${evidence.target}\n\nPassive scan evidence:\n${JSON.stringify(evidence).slice(0, 85000)}`,
      });
    },
  );

  server.registerTool(
    "cyberouter_ask",
    {
      title: "Ask Cyberouter",
      description: "Send a general authorized cybersecurity or code-analysis prompt to a chosen Cyberouter model.",
      inputSchema: z.object({
        model: z.string().min(1),
        prompt: z.string().min(1).max(100000),
        maxTokens: z.number().int().min(64).max(8192).optional(),
      }),
    },
    async ({ model, prompt, maxTokens }, ctx) => callChat(tokenFromContext(ctx), {
      model,
      maxTokens,
      system: "You are a cybersecurity and secure-software engineering assistant. Work only with authorized systems and code. Be concrete, evidence-driven, and explicit about uncertainty.",
      prompt,
    }),
  );
}, {
  serverInfo: { name: "cyberouter-lab", version: "1.0.0" },
});

const verifyToken = async (_request, bearerToken) => {
  if (!validateKey(bearerToken || "")) return undefined;
  return {
    token: bearerToken,
    scopes: ["cyberouter:use"],
    clientId: "cyberouter-user",
  };
};

const authHandler = withMcpAuth(handler, verifyToken, {
  required: true,
  requiredScopes: ["cyberouter:use"],
  resourceMetadataPath: "/.well-known/oauth-protected-resource",
});

export { authHandler as GET, authHandler as POST };
