
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const {
  McpServer
} = require("@modelcontextprotocol/sdk/server/mcp.js");
const {
  StreamableHTTPServerTransport
} = require("@modelcontextprotocol/sdk/server/streamableHttp.js");
const { z } = require("zod");

const app = express();
app.set("trust proxy", 1);
app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));
app.use((req, res, next) => {
  console.log(`[REQUEST] ${req.method} ${req.path}`);

  res.on("finish", () => {
    console.log(`[RESPONSE] ${req.method} ${req.path} ${res.statusCode}`);
  });

  next();
});
const SHOP = "1s2r4k-tt.myshopify.com";
const SHOPIFY_CLIENT_ID = "cdf6d98c8611f9b990097bb60195295f";

const SHOPIFY_CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;
const PUBLIC_BASE_URL =
  (process.env.PUBLIC_BASE_URL ||
    "https://shopify-mcp-claude.onrender.com").replace(/\/+$/, "");

const RESOURCE = `${PUBLIC_BASE_URL}/mcp`;

// In-memory OAuth state. A server restart clears active authorizations.
const clients = new Map();
const codes = new Map();
const tokens = new Map();

function randomToken() {
  return crypto.randomBytes(32).toString("base64url");
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function validRedirect(uri) {
  try {
    const u = new URL(uri);
    return (
      u.protocol === "https:" ||
      (u.protocol === "http:" &&
        ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname))
    );
  } catch {
    return false;
  }
}

function htmlEscape(value = "") {
  return String(value).replace(/[&<>"']/g, c => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[c]);
}

function getClientCredentials(req) {
  const header = req.get("authorization") || "";

  if (header.startsWith("Basic ")) {
    try {
      const decoded = Buffer.from(header.slice(6), "base64").toString();
      const i = decoded.indexOf(":");

      if (i >= 0) {
        return {
          clientId: decodeURIComponent(decoded.slice(0, i)),
          clientSecret: decodeURIComponent(decoded.slice(i + 1))
        };
      }
    } catch {}
  }

  return {
    clientId: req.body?.client_id,
    clientSecret: req.body?.client_secret
  };
}

// OAuth authorization-server metadata
app.get("/.well-known/oauth-authorization-server", (req, res) => {
  res.json({
    issuer: PUBLIC_BASE_URL,
    authorization_endpoint: `${PUBLIC_BASE_URL}/oauth/authorize`,
    token_endpoint: `${PUBLIC_BASE_URL}/oauth/token`,
    registration_endpoint: `${PUBLIC_BASE_URL}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: ["shopify"]
  });
});

// MCP protected-resource metadata
function resourceMetadata() {
  return {
    resource: RESOURCE,
    authorization_servers: [PUBLIC_BASE_URL],
    bearer_methods_supported: ["header"],
    scopes_supported: ["shopify"]
  };
}

app.get("/.well-known/oauth-protected-resource", (req, res) => {
  res.json(resourceMetadata());
});

app.get("/.well-known/oauth-protected-resource/mcp", (req, res) => {
  res.json(resourceMetadata());
});

// Dynamic Client Registration (public OAuth clients using PKCE)
app.post("/register", (req, res) => {
  const body = req.body || {};
  const redirectUris = body.redirect_uris;

  if (
    !Array.isArray(redirectUris) ||
    redirectUris.length === 0 ||
    redirectUris.length > 20 ||
    !redirectUris.every(uri =>
      typeof uri === "string" && validRedirect(uri)
    )
  ) {
    return res.status(400).json({
      error: "invalid_redirect_uri",
      error_description: "Provide valid HTTPS or loopback redirect URIs."
    });
  }

  const clientId = randomToken();

  clients.set(clientId, {
    redirectUris,
    name: String(body.client_name || "MCP client").slice(0, 100),
    created: Date.now()
  });

  res.status(201).json({
    client_id: clientId,
    client_name: String(body.client_name || "MCP client").slice(0, 100),
    redirect_uris: redirectUris,
    grant_types: ["authorization_code"],
    response_types: ["code"],
    token_endpoint_auth_method: "none"
  });
});

// Authorization: show a consent page
app.get("/oauth/authorize", (req, res) => {
  const {
    response_type,
    client_id,
    redirect_uri,
    state,
    code_challenge,
    code_challenge_method,
    resource
  } = req.query;

  const client = clients.get(client_id);

  if (
    response_type !== "code" ||
    !client ||
    !client.redirectUris.includes(redirect_uri) ||
    typeof state !== "string" ||
    !state ||
    typeof code_challenge !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(code_challenge) ||
    code_challenge_method !== "S256" ||
    (resource && resource !== RESOURCE)
  ) {
    return res.status(400).send("Invalid OAuth authorization request.");
  }

  res.type("html").send(`<!doctype html>
<html>
<head><meta charset="utf-8"><title>Shopify connection</title></head>
<body style="font-family:Arial;max-width:560px;margin:50px auto;padding:20px">
<h2>Connect Gemini to Shopify</h2>
<p>You're authorizing an MCP client to access your Shopify store.</p>
<p>This connection can read or modify store data within your Shopify API permissions.
Changes to products, prices, inventory and orders may have lasting effects.</p>
<form method="POST" action="/oauth/authorize">
<input type="hidden" name="client_id" value="${htmlEscape(client_id)}">
<input type="hidden" name="redirect_uri" value="${htmlEscape(redirect_uri)}">
<input type="hidden" name="state" value="${htmlEscape(state)}">
<input type="hidden" name="code_challenge" value="${htmlEscape(code_challenge)}">
<input type="hidden" name="code_challenge_method" value="S256">
<input type="hidden" name="resource" value="${htmlEscape(resource || RESOURCE)}">
<button type="submit" style="padding:12px 18px">Approve connection</button>
</form>
</body></html>`);
});

app.post("/oauth/authorize", (req, res) => {
  const {
    client_id,
    redirect_uri,
    state,
    code_challenge,
    code_challenge_method,
    resource
  } = req.body;

  const client = clients.get(client_id);

  if (
    !client ||
    !client.redirectUris.includes(redirect_uri) ||
    typeof state !== "string" ||
    !state ||
    typeof code_challenge !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(code_challenge) ||
    code_challenge_method !== "S256" ||
    (resource && resource !== RESOURCE)
  ) {
    return res.status(400).send("Invalid OAuth authorization request.");
  }

  const code = randomToken();

  codes.set(code, {
    clientId: client_id,
    redirectUri: redirect_uri,
    challenge: code_challenge,
    resource: resource || RESOURCE,
    expires: Date.now() + 5 * 60 * 1000
  });

  const callback = new URL(redirect_uri);
  callback.searchParams.set("code", code);
  callback.searchParams.set("state", state);

  res.redirect(302, callback.toString());
});

// Exchange authorization code for an access token
app.post("/oauth/token", (req, res) => {
  res.set("Cache-Control", "no-store");
  res.set("Pragma", "no-cache");

  const {
    grant_type,
    code,
    redirect_uri,
    code_verifier,
    resource
  } = req.body || {};

  if (grant_type !== "authorization_code") {
    return res.status(400).json({
      error: "unsupported_grant_type"
    });
  }

  const credentials = getClientCredentials(req);
  const clientId = credentials.clientId;
  const client = clients.get(clientId);
  const record = codes.get(code);

  if (
    !client ||
    credentials.clientSecret ||
    !record ||
    record.clientId !== clientId ||
    record.redirectUri !== redirect_uri ||
    record.expires < Date.now() ||
    (resource && resource !== record.resource) ||
    typeof code_verifier !== "string" ||
    code_verifier.length < 43 ||
    code_verifier.length > 128
  ) {
    if (code) codes.delete(code);
    return res.status(400).json({ error: "invalid_grant" });
  }

  codes.delete(code);

  const challenge = crypto
    .createHash("sha256")
    .update(code_verifier)
    .digest("base64url");

  if (!safeEqual(challenge, record.challenge)) {
    return res.status(400).json({ error: "invalid_grant" });
  }

  const accessToken = randomToken();

  tokens.set(accessToken, {
    clientId,
    resource: record.resource,
    expires: Date.now() + 60 * 60 * 1000
  });

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
    scope: "shopify"
  });
});

function authenticate(req, res, next) {
  const header = req.get("authorization") || "";
  const match = header.match(/^Bearer\s+(.+)$/i);
  const token = match?.[1];
  const record = token && tokens.get(token);

  if (
    !record ||
    record.expires <= Date.now() ||
    record.resource !== RESOURCE
  ) {
    if (token) tokens.delete(token);

    res.set(
      "WWW-Authenticate",
      `Bearer resource_metadata="${PUBLIC_BASE_URL}/.well-known/oauth-protected-resource"`
    );

    return res.status(401).json({ error: "unauthorized" });
  }

  next();
}

// Get a Shopify Admin API access token and execute GraphQL.
// Shopify's own app configuration and scopes still determine access.
async function shopifyGraphQL(query, variables = {}) {
  if (!SHOPIFY_CLIENT_SECRET) {
    throw new Error("SHOPIFY_CLIENT_SECRET is missing in Render.");
  }

  const authResponse = await fetch(
    `https://${SHOP}/admin/oauth/access_token`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: SHOPIFY_CLIENT_ID,
        client_secret: SHOPIFY_CLIENT_SECRET,
        grant_type: "client_credentials"
      })
    }
  );

  const authData = await authResponse.json();

  if (!authResponse.ok || !authData.access_token) {
    console.error("Shopify authentication failed:", authResponse.status);
    throw new Error(
      "Shopify authentication failed. Check app setup and Render logs."
    );
  }

  const apiResponse = await fetch(
    `https://${SHOP}/admin/api/2026-10/graphql.json`,
    {
      method: "POST",
      headers: {
        "X-Shopify-Access-Token": authData.access_token,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ query, variables })
    }
  );

  const data = await apiResponse.json();

  if (!apiResponse.ok) {
    console.error("Shopify API returned:", apiResponse.status);
    throw new Error(
      "Shopify API request failed. Check API version, scopes and logs."
    );
  }

  return data;
}

// MCP endpoint: Streamable HTTP
app.post("/mcp", authenticate, async (req, res) => {
  const server = new McpServer({
    name: "onyx-oak-shopify",
    version: "1.3.0"
  });

  server.tool(
    "shopify_graphql",
    "Execute Shopify Admin GraphQL queries or mutations. Can read and modify store data permitted by the Shopify app's granted API scopes. Mutations may have lasting effects.",
    {
      query: z.string().min(1).max(20000),
      variables: z.record(z.string(), z.unknown()).optional()
    },
    async ({ query, variables }) => {
      try {
        const result = await shopifyGraphQL(query, variables || {});

        return {
          content: [{
            type: "text",
            text: JSON.stringify(result, null, 2)
          }],
          ...(result.errors ? { isError: true } : {})
        };
      } catch (error) {
        return {
          isError: true,
          content: [{
            type: "text",
            text: error.message || "Shopify request failed."
          }]
        };
      }
    }
  );

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined
  });

  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    console.error("MCP request failed:", error.message);

    if (!res.headersSent) {
      res.status(500).json({ error: "MCP request failed." });
    }
  } finally {
    try {
      await transport.close();
    } catch {}

    try {
      await server.close();
    } catch {}
  }
});

app.get("/mcp", (req, res) => {
  res.set("Allow", "POST");
  res.status(405).send("Use POST for MCP requests.");
});

app.get("/", (req, res) => {
  res.type("text").send("Onyx & Oak Shopify MCP server is running.");
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log("Onyx & Oak Shopify MCP server started.");
});
