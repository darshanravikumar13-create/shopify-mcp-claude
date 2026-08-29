const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const sessions = new Map();

const domain = process.env.SHOPIFY_DOMAIN || "1s2r4k-tt.myshopify.com";
const clientId = process.env.SHOPIFY_CLIENT_ID;
const clientSecret = process.env.SHOPIFY_CLIENT_SECRET;

// Handle SSE connections on both root / and /sse
const handleSse = (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*'
  });

  const sessionId = Date.now().toString();
  sessions.set(sessionId, res);

  const messageUrl = `https://${req.get('host')}/message?sessionId=${sessionId}`;
  res.write(`event: endpoint\ndata: ${messageUrl}\n\n`);

  req.on('close', () => {
    sessions.delete(sessionId);
  });
};

app.get('/', handleSse);
app.get('/sse', handleSse);

// Message handler for MCP tool execution
app.post('/message', async (req, res) => {
  const sessionId = req.query.sessionId;
  const client = sessions.get(sessionId);

  res.status(202).send('Accepted');
  if (!client) return;

  const body = req.body;
  const id = body.id;
  let responsePayload = { jsonrpc: "2.0", id: id };

  try {
    if (body.method === 'initialize') {
      responsePayload.result = {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "Shopify MCP", version: "1.0.0" }
      };
    } else if (body.method === 'notifications/initialized') {
      responsePayload.result = {};
    } else if (body.method === 'tools/list') {
      responsePayload.result = {
        tools: [{
          name: "shopify_graphql",
          description: "Execute GraphQL queries on Shopify",
          inputSchema: { 
            type: "object", 
            properties: { 
              query: { type: "string", description: "GraphQL query to run against Shopify Admin API" } 
            }, 
            required: ["query"] 
          }
        }]
      };
    } else if (body.method === 'tools/call') {
      const tokenRes = await fetch(`https://${domain}/admin/oauth/access_token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
          client_id: clientId, 
          client_secret: clientSecret, 
          grant_type: "client_credentials" 
        })
      });
      const tokenData = await tokenRes.json();

      const shopifyRes = await fetch(`https://${domain}/admin/api/2026-01/graphql.json`, {
        method: "POST",
        headers: { 
          "X-Shopify-Access-Token": tokenData.access_token, 
          "Content-Type": "application/json" 
        },
        body: JSON.stringify({ query: body.params.arguments.query })
      });
      const shopifyData = await shopifyRes.json();

      responsePayload.result = {
        content: [{ type: "text", text: JSON.stringify(shopifyData, null, 2) }]
      };
    } else {
      responsePayload.result = {};
    }
  } catch (err) {
    responsePayload.error = { code: -32603, message: err.message };
  }

  client.write(`event: message\ndata: ${JSON.stringify(responsePayload)}\n\n`);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
