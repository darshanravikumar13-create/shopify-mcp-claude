
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");
const { StreamableHTTPServerTransport } = require("@modelcontextprotocol/sdk/server/streamableHttp.js");
const { z } = require("zod");

const app = express();
app.set("trust proxy", 1);
app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));

const SHOP = "1s2r4k-tt.myshopify.com";
const SHOPIFY_CLIENT_ID = "cdf6d98c8611f9b990097bb60195295f";

const SHOPIFY_CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;
const MCP_CLIENT_ID = process.env.MCP_CLIENT_ID;
const MCP_CLIENT_SECRET = process.env.MCP_CLIENT_SECRET;
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL;

const authorizationCodes = new Map();
const accessTokens = new Map();

function baseUrl(req) {
  return (PUBLIC_BASE_URL || `${req.protocol}://${req.get("host")}`)
    .replace(/\/+$/, "");
}

function randomToken() {
  return crypto.randomBytes(32).toString("base64url");
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function getCredentials(req) {
  const header = req.get("authorization") || "";

  if (header.startsWith("Basic ")) {
    try {
      const decoded = Buffer.from(header.slice(6), "base64").toString();
      const index = decoded.indexOf(":");

      if (index >= 0) {
        return {
          id: decodeURIComponent(decoded.slice(0, index)),
          secret: decodeURIComponent(decoded.slice(index + 1))
        };
      }
    } catch (_) {}
  }

  return {
    id: req.body?.client_id,
    secret: req.body?.client_secret
  };
}

function validClient(req) {
  const credentials = getCredentials(req);

  return safeEqual(credentials.id, MCP_CLIENT_ID) &&
    safeEqual(credentials.secret, MCP_CLIENT_SECRET);
}

function validRedirect(uri) {
  try {
    return new URL(uri).protocol === "https:";
  } catch (_) {
    return false;
  }
}

function escapeHtml(value = "") {
  return String(value).replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[char]);
}

function protectedResource(req) {
  const base = baseUrl(req);

  return {
    resource: `${base}/mcp`,
    authorization_servers: [base],
    bearer_methods_supported: ["header"],
    scopes_supported: ["shopify"]
  };
}

app.get("/.well-known/oauth-protected-resource", (req, res) => {
  res.json(protectedResource(req));
});

app.get("/.well-known/oauth-protected-resource/mcp", (req, res) => {
  res.json(protectedResource(req));
});

app.get("/.well-known/oauth-authorization-server", (req, res) => {
  const base = baseUrl(req);

  res.json({
    issuer: base,
    authorization_endpoint: `${base}/oauth/authorize`,
    token_endpoint: `${base}/oauth/token`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: [
      "client_secret_post",
      "client_secret_basic"
    ],
    scopes_supported: ["shopify"]
  });
});

// OAuth authorization page
app.get("/oauth/authorize", (req, res) => {
  const {
    response_type,
    client_id,
    redirect_uri,
    state,
    code_challenge,
    code_challenge_method
  } = req.query;

  if (
    response_type !== "code" ||
    !safeEqual(client_id, MCP_CLIENT_ID) ||
    !validRedirect(redirect_uri) ||
    typeof state !== "string" ||
    !state ||
    typeof code_challenge !== "string" ||
    !code_challenge ||
    code_challenge_method !== "S256"
  ) {
    return res.status(400).send("Invalid OAuth request.");
  }

  res.type("html").send(`<!doctype html>
<html>
<head><meta charset="utf-8"><title>Shopify authorization</title></head>
<body style="font-family:Arial;max-width:520px;margin:60px auto;padding:20px">
<h2>Connect Gemini to Shopify</h2>
<p>This connection can run Shopify Admin GraphQL queries and mutations
permitted by your Shopify app's access scopes.</p>
<p>Mutations may change or delete store data. Only approve if you trust
the Gemini connection.</p>
<form method="POST" action="/oauth/authorize">
<input type="hidden" name="client_id" value="${escapeHtml(client_id)}">
<input type="hidden" name="redirect_uri" value="${escapeHtml(redirect_uri)}">
<input type="hidden" name="state" value="${escapeHtml(state)}">
<input type="hidden" name="code_challenge" value="${escapeHtml(code_challenge)}">
<input type="hidden" name="code_challenge_method" value="S256">
<button type="submit" style="padding:12px 20px">Approve connection</button>
</form>
</body></html>`);
});

app.post("/oauth/authorize", (req, res) => {
  const {
    client_id,
    redirect_uri,
    state,
    code_challenge,
    code_challenge_method
  } = req.body;

  if (
    !safeEqual(client_id, MCP_CLIENT_ID) ||
    !validRedirect(redirect_uri) ||
    typeof state !== "string" ||
    !state ||
    typeof code_challenge !== "string" ||
    !code_challenge ||
    code_challenge_method !== "S256"
  ) {
    return res.status(400).send("Invalid authorization request.");
  }

  const code = randomToken();

  authorizationCodes.set(code, {
    clientId: client_id,
    redirectUri: redirect_uri,
    challenge: code_challenge,
    expires: Date.now() + 5 * 60 * 1000
  });

  const callback = new URL(redirect_uri);
  callback.searchParams.set("code", code);
  callback.searchParams.set("state", state);

  res.redirect(302, callback.toString());
});

// OAuth token endpoint
app.post("/oauth/token", (req, res) => {
  res.set("Cache-Control", "no-store");

  if (!MCP_CLIENT_ID || !MCP_CLIENT_SECRET || !validClient(req)) {
    return res.status(401).json({ error: "invalid_client" });
  }

  const { grant_type, code, redirect_uri, code_verifier } = req.body;

  if (grant_type !== "authorization_code") {
    return res.status(400).json({
      error: "unsupported_grant_type"
    });
  }

  const record = authorizationCodes.get(code);

  if (!record) {
    return res.status(400).json({ error: "invalid_grant" });
  }

  authorizationCodes.delete(code);

  if (
    record.expires < Date.now() ||
    record.clientId !== MCP_CLIENT_ID ||
    record.redirectUri !== redirect_uri ||
    typeof code_verifier !== "string"
  ) {
    return res.status(400).json({ error: "invalid_grant" });
  }

  const challenge = crypto
    .createHash("sha256")
    .update(code_verifier)
    .digest("base64url");

  if (challenge !== record.challenge) {
    return res.status(400).json({ error: "invalid_grant" });
  }

  const token = randomToken();
  accessTokens.set(token, Date.now() + 60 * 60 * 1000);

  return res.json({
    access_token: token,
    token_type: "Bearer",
    expires_in: 3600,
    scope: "shopify"
  });
});

function requireBearer(req, res, next) {
  const header = req.get("authorization") || "";
  const match = header.match(/^Bearer\s+(.+)$/i);
  const token = match?.[1];
  const expires = token && accessTokens.get(token);

  if (!expires || expires < Date.now()) {
    if (token) accessTokens.delete(token);

    res.set(
      "WWW-Authenticate",
      `Bearer resource_metadata="${baseUrl(req)}/.well-known/oauth-protected-resource"`
    );

    return res.status(401).json({ error: "unauthorized" });
  }

  next();
}

// Shopify Admin GraphQL: queries AND mutations
async function runShopifyGraphQL(query, variables) {
  if (!SHOPIFY_CLIENT_SECRET) {
    throw new Error("SHOPIFY_CLIENT_SECRET is not configured.");
  }

  const tokenResponse = await fetch(
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

  const tokenData = await tokenResponse.json();

  if (!tokenResponse.ok || !tokenData.access_token) {
    console.error("Shopify token request failed:", tokenResponse.status);
    throw new Error("Shopify authentication failed. Check Render logs.");
  }

  const response = await fetch(
    `https://${SHOP}/admin/api/2026-10/graphql.json`,
    {
      method: "POST",
      headers: {
        "X-Shopify-Access-Token": tokenData.access_token,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ query, variables })
    }
  );

  const data = await response.json();

  if (!response.ok) {
    console.error("Shopify GraphQL request failed:", response.status);
    throw new Error("Shopify API request failed. Check Render logs.");
  }

  return data;
}

app.post("/mcp", requireBearer, async (req, res) => {
  const server = new McpServer({
    name: "onyx-oak-shopify",
    version: "1.2.0"
  });

  server.tool(
    "shopify_graphql",
    "Execute Shopify Admin GraphQL queries or mutations. Supports reading and changing store data allowed by the Shopify app's API scopes. Mutations can have irreversible effects; verify important changes.",
    {
      query: z.string().min(1).max(20000),
      variables: z.record(z.string(), z.unknown()).optional()
    },
    async ({ query, variables }) => {
      try {
        const data = await runShopifyGraphQL(query, variables || {});

        return {
          content: [{
            type: "text",
            text: JSON.stringify(data, null, 2)
          }],
          ...(data.errors ? { isError: true } : {})
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
    sessionIdGenerator: undefined,
    enableJsonResponse: true
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
    await transport.close().catch(() => {});
    await server.close().catch(() => {});
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
