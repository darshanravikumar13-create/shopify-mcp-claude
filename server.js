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
    console.log(
      `[RESPONSE] ${req.method} ${req.path} ${res.statusCode}`
    );
  });

  next();
});

const SHOP = "1s2r4k-tt.myshopify.com";
const SHOPIFY_CLIENT_ID =
  "cdf6d98c8611f9b990097bb60195295f";

const SHOPIFY_CLIENT_SECRET =
  process.env.SHOPIFY_CLIENT_SECRET;

const PUBLIC_BASE_URL = (
  process.env.PUBLIC_BASE_URL ||
  "https://shopify-mcp-claude.onrender.com"
).replace(/\/+$/, "");

const RESOURCE = `${PUBLIC_BASE_URL}/mcp`;

const clients = new Map();
const codes = new Map();
const tokens = new Map();

function randomToken() {
  return crypto.randomBytes(32).toString("base64url");
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }

  const x = Buffer.from(a);
  const y = Buffer.from(b);

  return (
    x.length === y.length &&
    crypto.timingSafeEqual(x, y)
  );
}

function validRedirect(uri) {
  try {
    const u = new URL(uri);

    return (
      u.protocol === "https:" ||
      (
        u.protocol === "http:" &&
        ["localhost", "127.0.0.1", "[::1]"].includes(
          u.hostname
        )
      )
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
      const decoded = Buffer.from(
        header.slice(6),
        "base64"
      ).toString();

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

app.get(
  "/.well-known/oauth-authorization-server",
  (req, res) => {
    res.json({
      issuer: PUBLIC_BASE_URL,
      authorization_endpoint:
        `${PUBLIC_BASE_URL}/oauth/authorize`,
      token_endpoint: `${PUBLIC_BASE_URL}/oauth/token`,
      registration_endpoint: `${PUBLIC_BASE_URL}/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
      scopes_supported: ["shopify"]
    });
  }
);

function resourceMetadata() {
  return {
    resource: RESOURCE,
    authorization_servers: [PUBLIC_BASE_URL],
    bearer_methods_supported: ["header"],
    scopes_supported: ["shopify"]
  };
}

app.get(
  "/.well-known/oauth-protected-resource",
  (req, res) => {
    res.json(resourceMetadata());
  }
);

app.get(
  "/.well-known/oauth-protected-resource/mcp",
  (req, res) => {
    res.json(resourceMetadata());
  }
);

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
      error_description:
        "Provide valid HTTPS or loopback redirect URIs."
    });
  }

  const clientId = randomToken();
  const name = String(
    body.client_name || "MCP client"
  ).slice(0, 100);

  clients.set(clientId, {
    redirectUris,
    name,
    created: Date.now()
  });

  res.status(201).json({
    client_id: clientId,
    client_name: name,
    redirect_uris: redirectUris,
    grant_types: ["authorization_code"],
    response_types: ["code"],
    token_endpoint_auth_method: "none"
  });
});

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
    return res.status(400).send(
      "Invalid OAuth authorization request."
    );
  }

  res.type("html").send(`<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Shopify connection</title>
</head>
<body style="font-family:Arial;max-width:560px;margin:50px auto;padding:20px">
<h2>Connect Gemini to Shopify</h2>
<p>You're authorizing an MCP client to access your Shopify store.</p>
<p>This connection can read or modify store data within your Shopify API permissions. Changes to products, prices, inventory and orders may have lasting effects.</p>
<form method="POST" action="/oauth/authorize">
<input type="hidden" name="client_id" value="${htmlEscape(client_id)}">
<input type="hidden" name="redirect_uri" value="${htmlEscape(redirect_uri)}">
<input type="hidden" name="state" value="${htmlEscape(state)}">
<input type="hidden" name="code_challenge" value="${htmlEscape(code_challenge)}">
<input type="hidden" name="code_challenge_method" value="S256">
<input type="hidden" name="resource" value="${htmlEscape(resource || RESOURCE)}">
<button type="submit" style="padding:12px 18px">Approve connection</button>
</form>
</body>
</html>`);
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
    return res.status(400).send(
      "Invalid OAuth authorization request."
    );
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

    return res.status(400).json({
      error: "invalid_grant"
    });
  }

  codes.delete(code);

  const challenge = crypto
    .createHash("sha256")
    .update(code_verifier)
    .digest("base64url");

  if (!safeEqual(challenge, record.challenge)) {
    return res.status(400).json({
      error: "invalid_grant"
    });
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
  const accessToken = match?.[1];
  const record = accessToken && tokens.get(accessToken);

  if (
    !record ||
    record.expires <= Date.now() ||
    record.resource !== RESOURCE
  ) {
    if (accessToken) tokens.delete(accessToken);

    res.set(
      "WWW-Authenticate",
      `Bearer resource_metadata="${PUBLIC_BASE_URL}/.well-known/oauth-protected-resource"`
    );

    return res.status(401).json({
      error: "unauthorized"
    });
  }

  next();
}

async function shopifyGraphQL(query, variables = {}) {
  if (!SHOPIFY_CLIENT_SECRET) {
    throw new Error(
      "SHOPIFY_CLIENT_SECRET is missing in Render."
    );
  }

  const authResponse = await fetch(
    `https://${SHOP}/admin/oauth/access_token`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        client_id: SHOPIFY_CLIENT_ID,
        client_secret: SHOPIFY_CLIENT_SECRET,
        grant_type: "client_credentials"
      })
    }
  );

  const authData = await authResponse.json();

  if (!authResponse.ok || !authData.access_token) {
    console.error(
      "Shopify authentication failed:",
      authResponse.status
    );

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
      body: JSON.stringify({
        query,
        variables
      }),
      signal: AbortSignal.timeout(60000)
    }
  );

  const data = await apiResponse.json();

  if (!apiResponse.ok) {
    console.error(
      "Shopify API returned:",
      apiResponse.status
    );

    throw new Error(
      "Shopify API request failed. Check API version, scopes and logs."
    );
  }

  return data;
}

async function browserAgentRequest(agentPath, options = {}) {
  const baseUrl = process.env.BROWSER_AGENT_URL;
  const agentToken = process.env.BROWSER_AGENT_TOKEN;

  if (!baseUrl || !agentToken) {
    throw new Error(
      "BROWSER_AGENT_URL or BROWSER_AGENT_TOKEN is missing in Render."
    );
  }

  const {
    timeoutMs = 60000,
    ...fetchOptions
  } = options;

  const response = await fetch(
    `${baseUrl.replace(/\/+$/, "")}${agentPath}`,
    {
      ...fetchOptions,
      headers: {
        Authorization: `Bearer ${agentToken}`,
        "Content-Type": "application/json",
        ...fetchOptions.headers
      },
      signal: AbortSignal.timeout(timeoutMs)
    }
  );

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      data.error ||
      `Browser agent returned HTTP ${response.status}`
    );
  }

  return data;
}

function toolResult(data) {
  return {
    content: [{
      type: "text",
      text: JSON.stringify(data, null, 2)
    }]
  };
}

function toolError(error) {
  return {
    isError: true,
    content: [{
      type: "text",
      text: error.message || "The operation failed."
    }]
  };
}

function registerBrowserTool(
  server,
  name,
  description,
  schema,
  endpoint,
  method = "POST"
) {
  server.tool(
    name,
    description,
    schema,
    async args => {
      try {
        const options = method === "GET"
          ? {}
          : {
              method,
              body: JSON.stringify(args || {})
            };

        const result = await browserAgentRequest(
          endpoint,
          options
        );

        return toolResult(result);
      } catch (error) {
        return toolError(error);
      }
    }
  );
}

const targetSchema = {
  selector: z.string().optional(),
  role: z.string().optional(),
  label: z.string().optional(),
  placeholder: z.string().optional(),
  text: z.string().optional(),
  testId: z.string().optional(),
  name: z.string().optional(),
  exact: z.boolean().optional(),
  index: z.number().int().nonnegative().optional()
};

const workflowTargetSchema = z.object({
  selector: z.string().optional(),
  role: z.string().optional(),
  label: z.string().optional(),
  placeholder: z.string().optional(),
  text: z.string().optional(),
  testId: z.string().optional(),
  name: z.string().optional(),
  exact: z.boolean().optional(),
  index: z.number().int().nonnegative().optional()
}).optional();

const workflowStepSchema = z.discriminatedUnion("action", [
  z.object({
    action: z.literal("navigate"),
    url: z.string().min(1).max(2048)
  }),

  z.object({
    action: z.literal("inspect")
  }),

  z.object({
    action: z.literal("click"),
    target: workflowTargetSchema,
    selector: z.string().optional(),
    role: z.string().optional(),
    label: z.string().optional(),
    placeholder: z.string().optional(),
    text: z.string().optional(),
    testId: z.string().optional(),
    name: z.string().optional(),
    exact: z.boolean().optional(),
    index: z.number().int().nonnegative().optional(),
    timeoutMs: z.number().int().min(1000).max(60000).optional()
  }),

  z.object({
    action: z.literal("fill"),
    target: workflowTargetSchema,
    selector: z.string().optional(),
    role: z.string().optional(),
    label: z.string().optional(),
    placeholder: z.string().optional(),
    text: z.string().optional(),
    testId: z.string().optional(),
    name: z.string().optional(),
    exact: z.boolean().optional(),
    index: z.number().int().nonnegative().optional(),
    value: z.string().max(100000),
    timeoutMs: z.number().int().min(1000).max(60000).optional()
  }),

  z.object({
    action: z.literal("select"),
    target: workflowTargetSchema,
    selector: z.string().optional(),
    role: z.string().optional(),
    label: z.string().optional(),
    placeholder: z.string().optional(),
    text: z.string().optional(),
    testId: z.string().optional(),
    name: z.string().optional(),
    exact: z.boolean().optional(),
    index: z.number().int().nonnegative().optional(),
    option: z.object({
      value: z.string().optional(),
      label: z.string().optional(),
      index: z.number().int().nonnegative().optional()
    }),
    timeoutMs: z.number().int().min(1000).max(60000).optional()
  }),

  z.object({
    action: z.literal("check"),
    target: workflowTargetSchema,
    selector: z.string().optional(),
    role: z.string().optional(),
    label: z.string().optional(),
    placeholder: z.string().optional(),
    text: z.string().optional(),
    testId: z.string().optional(),
    name: z.string().optional(),
    exact: z.boolean().optional(),
    index: z.number().int().nonnegative().optional(),
    checked: z.boolean().optional(),
    timeoutMs: z.number().int().min(1000).max(60000).optional()
  }),

  z.object({
    action: z.literal("press"),
    target: workflowTargetSchema,
    selector: z.string().optional(),
    role: z.string().optional(),
    label: z.string().optional(),
    placeholder: z.string().optional(),
    text: z.string().optional(),
    testId: z.string().optional(),
    name: z.string().optional(),
    exact: z.boolean().optional(),
    index: z.number().int().nonnegative().optional(),
    key: z.string().min(1).max(50),
    timeoutMs: z.number().int().min(1000).max(60000).optional()
  }),

  z.object({
    action: z.literal("scroll"),
    target: workflowTargetSchema,
    selector: z.string().optional(),
    index: z.number().int().nonnegative().optional(),
    deltaY: z.number().min(-10000).max(10000).optional()
  }),

  z.object({
    action: z.literal("wait"),
    target: workflowTargetSchema,
    selector: z.string().optional(),
    role: z.string().optional(),
    label: z.string().optional(),
    placeholder: z.string().optional(),
    text: z.string().optional(),
    testId: z.string().optional(),
    name: z.string().optional(),
    exact: z.boolean().optional(),
    index: z.number().int().nonnegative().optional(),
    state: z.enum([
      "visible",
      "hidden",
      "attached",
      "detached"
    ]).optional(),
    timeoutMs: z.number().int().min(1000).max(60000).optional()
  }),

  z.object({
    action: z.literal("screenshot"),
    fullPage: z.boolean().optional()
  })
]);

app.post("/mcp", authenticate, async (req, res) => {
  const server = new McpServer({
    name: "onyx-oak-shopify",
    version: "2.1.0"
  });

  server.tool(
    "shopify_graphql",
    "Execute Shopify Admin GraphQL queries or mutations. Access is limited by the Shopify app's granted API scopes. Mutations may have lasting effects.",
    {
      query: z.string().min(1).max(20000),
      variables: z.record(z.string(), z.unknown()).optional()
    },
    async ({ query, variables }) => {
      try {
        const result = await shopifyGraphQL(
          query,
          variables || {}
        );

        return {
          content: [{
            type: "text",
            text: JSON.stringify(result, null, 2)
          }],
          ...(result.errors ? { isError: true } : {})
        };
      } catch (error) {
        return toolError(error);
      }
    }
  );

  registerBrowserTool(
    server,
    "shopify_browser_status",
    "Check whether the local Shopify browser agent is reachable.",
    {},
    "/health",
    "GET"
  );

  registerBrowserTool(
    server,
    "shopify_browser_navigate",
    "Navigate the selected Opera tab to a trusted Shopify Admin URL.",
    {
      url: z.string().min(1).max(2048)
    },
    "/navigate"
  );

  registerBrowserTool(
    server,
    "shopify_browser_inspect",
    "Inspect the current Shopify Admin page. Returns URL, title, page text, visible buttons, links and form controls.",
    {},
    "/inspect"
  );

  registerBrowserTool(
    server,
    "shopify_browser_click",
    "Click one Shopify Admin element. Provide exactly one locator strategy. Inspect before clicking and verify afterward.",
    targetSchema,
    "/click"
  );

  registerBrowserTool(
    server,
    "shopify_browser_fill",
    "Fill a Shopify Admin field. Inspect before editing. Do not submit consequential changes without appropriate confirmation.",
    {
      ...targetSchema,
      value: z.string().max(100000)
    },
    "/fill"
  );

  registerBrowserTool(
    server,
    "shopify_browser_select",
    "Select an option in a native Shopify Admin dropdown.",
    {
      ...targetSchema,
      option: z.object({
        value: z.string().optional(),
        label: z.string().optional(),
        index: z.number().int().nonnegative().optional()
      }).refine(option =>
        ["value", "label", "index"].filter(
          key => option[key] !== undefined
        ).length === 1
      )
    },
    "/select"
  );

  registerBrowserTool(
    server,
    "shopify_browser_check",
    "Check or uncheck a Shopify Admin checkbox.",
    {
      ...targetSchema,
      checked: z.boolean().optional()
    },
    "/check"
  );

  registerBrowserTool(
    server,
    "shopify_browser_press",
    "Press a keyboard key on a Shopify Admin element.",
    {
      ...targetSchema,
      key: z.string().min(1).max(50)
    },
    "/press"
  );

  registerBrowserTool(
    server,
    "shopify_browser_scroll",
    "Scroll the current Shopify Admin page or scroll an element into view.",
    {
      deltaY: z.number().min(-10000).max(10000).optional(),
      selector: z.string().optional(),
      index: z.number().int().nonnegative().optional()
    },
    "/scroll"
  );

  registerBrowserTool(
    server,
    "shopify_browser_wait",
    "Wait for a Shopify Admin element to become visible, hidden, attached or detached.",
    {
      ...targetSchema,
      state: z.enum([
        "visible",
        "hidden",
        "attached",
        "detached"
      ]).optional()
    },
    "/wait"
  );

  registerBrowserTool(
    server,
    "shopify_browser_screenshot",
    "Capture a screenshot of the current Shopify Admin page as base64 PNG.",
    {
      fullPage: z.boolean().optional()
    },
    "/screenshot"
  );

  // New tool: execute multiple browser actions in one MCP call.
  server.tool(
    "shopify_browser_workflow",
    "Execute 1 to 12 Shopify Admin browser actions sequentially in one MCP call. Supported actions: navigate, inspect, click, fill, select, check, press, scroll, wait, screenshot. Stops at the first failed step and returns results completed so far. Inspect before editing. No automatic saving is performed by the workflow itself; save only when explicitly requested.",
    {
      steps: z.array(workflowStepSchema).min(1).max(12)
    },
    async ({ steps }) => {
      try {
        const result = await browserAgentRequest(
          "/workflow",
          {
            method: "POST",
            body: JSON.stringify({ steps }),
            timeoutMs: 120000
          }
        );

        return {
          content: [{
            type: "text",
            text: JSON.stringify(result, null, 2)
          }],
          ...(result.ok === false ? { isError: true } : {})
        };
      } catch (error) {
        return toolError(error);
      }
    }
  );

  server.tool(
    "get_shopify_email_template",
    "Read a Shopify notification email template from its open Edit code page in Opera.",
    {
      template: z.string()
        .regex(/^[a-z0-9_]+$/)
        .default("return_declined")
    },
    async ({ template }) => {
      try {
        const result = await browserAgentRequest(
          `/template?template=${encodeURIComponent(template)}`
        );

        return toolResult(result);
      } catch (error) {
        return toolError(error);
      }
    }
  );

  server.tool(
    "edit_shopify_email_template",
    "Replace the code in an open Shopify notification email editor. Supply the template slug and complete replacement code. The browser agent attempts to save and verify the change.",
    {
      template: z.string().regex(/^[a-z0-9_]+$/),
      code: z.string().min(1).max(100000)
    },
    async ({ template, code }) => {
      try {
        const result = await browserAgentRequest(
          "/template",
          {
            method: "PUT",
            body: JSON.stringify({
              template,
              code
            })
          }
        );

        return toolResult(result);
      } catch (error) {
        return toolError(error);
      }
    }
  );

  server.tool(
    "get_return_declined_template",
    "Read the Return request declined email template from its open editor.",
    {},
    async () => {
      try {
        const result = await browserAgentRequest("/template");
        return toolResult(result);
      } catch (error) {
        return toolError(error);
      }
    }
  );

  server.tool(
    "edit_return_declined_template",
    "Replace the Return request declined template code. Supply the complete replacement code. The browser agent attempts to save and verify the change.",
    {
      code: z.string().min(1).max(100000)
    },
    async ({ code }) => {
      try {
        const result = await browserAgentRequest(
          "/template",
          {
            method: "PUT",
            body: JSON.stringify({ code })
          }
        );

        return toolResult(result);
      } catch (error) {
        return toolError(error);
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
    console.error(
      "MCP request failed:",
      error.message
    );

    if (!res.headersSent) {
      res.status(500).json({
        error: "MCP request failed."
      });
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

app.head("/mcp", (req, res) => {
  res.set(
    "WWW-Authenticate",
    `Bearer resource_metadata="${PUBLIC_BASE_URL}/.well-known/oauth-protected-resource/mcp"`
  );

  res.status(401).end();
});

app.get("/mcp", (req, res) => {
  res.set("Allow", "POST");
  res.status(405).send("Use POST for MCP requests.");
});

app.get("/", (req, res) => {
  res.type("text").send(
    "Onyx & Oak Shopify MCP server is running."
  );
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(
    "Onyx & Oak Shopify MCP server started."
  );
});
