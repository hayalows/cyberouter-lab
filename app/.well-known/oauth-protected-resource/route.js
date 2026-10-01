import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export async function GET(request) {
  const url = new URL(request.url);
  const resource = `${url.protocol}//${url.host}/api/mcp`;

  return NextResponse.json(
    {
      resource,
      resource_name: "Cyberouter Lab MCP",
      scopes_supported: ["cyberouter:use"],
      bearer_methods_supported: ["header"],
      resource_documentation: `${url.protocol}//${url.host}/`,
    },
    {
      headers: {
        "Cache-Control": "public, max-age=300",
      },
    },
  );
}
