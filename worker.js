// worker.js - Cloudflare Worker for SEOSiri DB Infra MCP
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

const BACKEND_ENDPOINT = "https://hubappapi.seosiri.com/db-infra";

async function handleRequest(request) {
  const url = new URL(request.url);

  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization, x-seosiri-key",
      },
    });
  }

  if (url.pathname === "/health") {
    return new Response(JSON.stringify({
      status: "HEALTHY",
      service: "SEOSiri DB Infra MCP Edge Gateway",
      version: "1.0.0",
      timestamp: new Date().toISOString()
    }), {
      status: 200,
      headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
    });
  }

  const acceptHeader = request.headers.get("Accept") || "";
  if ((url.pathname === "/" || url.pathname === "") && acceptHeader.includes("text/html")) {
    return Response.redirect("https://www.seosiri.com/2026/08/seosiri-db-infra-mcp.html", 301);
  }

  try {
    const modifiedRequest = new Request(BACKEND_ENDPOINT + url.pathname + url.search, {
      method: request.method,
      headers: request.headers,
      body: request.body,
    });

    const response = await fetch(modifiedRequest);
    const newHeaders = new Headers(response.headers);
    newHeaders.set("Access-Control-Allow-Origin", "*");

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders,
    });
  } catch (err) {
    return new Response(
      JSON.stringify({ error: "GATEWAY_TIMEOUT", details: err.message }),
      { status: 504, headers: { "Content-Type": "application/json" } }
    );
  }
}