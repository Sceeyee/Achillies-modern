// Netlify Function — proxies to Anthropic API
// Set ANTHROPIC_API_KEY in Netlify dashboard → Site config → Environment variables

const https = require('https');

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type'
};

function httpsPost(options, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: CORS, body: '' };
  }

  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers: { 'content-type': 'application/json', ...CORS }, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return { statusCode: 500, headers: { 'content-type': 'application/json', ...CORS }, body: JSON.stringify({ error: 'ANTHROPIC_API_KEY not set in Netlify environment variables' }) };
  }

  try {
    const body = JSON.parse(event.body);
    const { system, messages, max_tokens = 1500, model = 'claude-sonnet-4-6' } = body;
    const payload = JSON.stringify({ model, max_tokens, system, messages });

    const result = await httpsPost({
      hostname: 'api.anthropic.com',
      path: '/v1/messages',
      method: 'POST',
      headers: {
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload)
      }
    }, payload);

    return {
      statusCode: result.status,
      headers: { 'content-type': 'application/json', ...CORS },
      body: result.body
    };
  } catch (err) {
    return {
      statusCode: 500,
      headers: { 'content-type': 'application/json', ...CORS },
      body: JSON.stringify({ error: err.message || 'Internal server error' })
    };
  }
};
