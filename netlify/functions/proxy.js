const https = require('https');
const http  = require('http');
const { URL } = require('url');
const zlib = require('zlib');

/* ── BLOCKED HOSTS (abuse prevention) ── */
const BLOCKED = new Set([
  'localhost', '127.0.0.1', '0.0.0.0', '::1',
  '169.254.169.254', // AWS metadata
  '100.100.100.200', // Alibaba metadata
]);

/* ── HEADERS TO STRIP FROM UPSTREAM RESPONSE ── */
const STRIP_RES = new Set([
  'content-security-policy',
  'content-security-policy-report-only',
  'x-frame-options',
  'x-content-type-options',
  'strict-transport-security',
  'permissions-policy',
  'cross-origin-embedder-policy',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
  'expect-ct',
  'feature-policy',
  'referrer-policy',
]);

/* ── HEADERS TO STRIP FROM FORWARDED REQUEST ── */
const STRIP_REQ = new Set([
  'host', 'connection', 'upgrade', 'http2-settings',
  'transfer-encoding', 'te', 'trailer',
  'proxy-authorization', 'proxy-connection',
]);

/* ── CORS HEADERS (added to every response) ── */
const CORS = {
  'access-control-allow-origin':   '*',
  'access-control-allow-methods':  'GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD',
  'access-control-allow-headers':  '*',
  'access-control-expose-headers': '*',
  'access-control-max-age':        '86400',
};

/* ════════════════════════════════════════════════════
   REWRITE HELPER
   Rewrites absolute URLs inside HTML/CSS/JS so
   they route back through this proxy.
   ════════════════════════════════════════════════════ */
function rewriteUrl(targetUrl, resourceUrl) {
  if (!resourceUrl || resourceUrl.startsWith('data:') || resourceUrl.startsWith('blob:') || resourceUrl.startsWith('javascript:') || resourceUrl.startsWith('#')) {
    return resourceUrl;
  }
  try {
    const absolute = new URL(resourceUrl, targetUrl).href;
    // Don't re-proxy if it already goes through us
    if (absolute.includes('/.netlify/functions/proxy')) return resourceUrl;
    return `/.netlify/functions/proxy?url=${encodeURIComponent(absolute)}`;
  } catch (e) {
    return resourceUrl;
  }
}

function rewriteHtml(html, targetUrl) {
  const base = new URL(targetUrl);

  // Inject <base> tag so relative paths resolve correctly in-frame
  html = html.replace(/(<head[^>]*>)/i, `$1<base href="${base.origin}/">`);

  // Rewrite src / href / action / data attributes
  html = html.replace(
    /(src|href|action|data-src|data-href|poster|srcset)\s*=\s*["']([^"']+)["']/gi,
    (match, attr, val) => {
      if (attr.toLowerCase() === 'srcset') {
        const rewritten = val.split(',').map(part => {
          const pieces = part.trim().split(/\s+/);
          pieces[0] = rewriteUrl(targetUrl, pieces[0]);
          return pieces.join(' ');
        }).join(', ');
        return `${attr}="${rewritten}"`;
      }
      return `${attr}="${rewriteUrl(targetUrl, val)}"`;
    }
  );

  // Rewrite url() in inline styles
  html = html.replace(
    /url\(\s*["']?([^"')]+)["']?\s*\)/gi,
    (match, val) => `url("${rewriteUrl(targetUrl, val)}")`
  );

  // Rewrite window.location / fetch / XMLHttpRequest via injected script
  const injectedScript = `
<script>
(function(){
  const PROXY = '/.netlify/functions/proxy?url=';
  const BASE  = '${base.origin}';

  // Intercept fetch
  const _fetch = window.fetch;
  window.fetch = function(input, init) {
    let url = typeof input === 'string' ? input : input.url;
    try {
      if (!/^\\.netlify/.test(url) && !/^data:|^blob:/.test(url)) {
        const abs = new URL(url, BASE).href;
        if (!abs.includes('/.netlify/functions/proxy')) {
          url = PROXY + encodeURIComponent(abs);
          if (typeof input !== 'string') input = new Request(url, input);
          else input = url;
        }
      }
    } catch(e) {}
    return _fetch.call(this, input, init);
  };

  // Intercept XHR
  const _open = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, ...rest) {
    try {
      if (url && !/^\\.netlify/.test(url) && !/^data:|^blob:/.test(url)) {
        const abs = new URL(url, BASE).href;
        if (!abs.includes('/.netlify/functions/proxy')) {
          url = PROXY + encodeURIComponent(abs);
        }
      }
    } catch(e) {}
    return _open.call(this, method, url, ...rest);
  };
})();
</script>`;

  html = html.replace(/(<head[^>]*>)/i, `$1${injectedScript}`);

  return html;
}

function rewriteCss(css, targetUrl) {
  return css.replace(
    /url\(\s*["']?([^"')]+)["']?\s*\)/gi,
    (match, val) => `url("${rewriteUrl(targetUrl, val)}")`
  );
}

/* ════════════════════════════════════════════════════
   DECOMPRESS helper
   ════════════════════════════════════════════════════ */
function decompress(buffer, encoding) {
  return new Promise((resolve, reject) => {
    if (!encoding) return resolve(buffer);
    const enc = encoding.toLowerCase();
    if (enc.includes('br')) {
      zlib.brotliDecompress(buffer, (e, r) => e ? reject(e) : resolve(r));
    } else if (enc.includes('gzip')) {
      zlib.gunzip(buffer, (e, r) => e ? reject(e) : resolve(r));
    } else if (enc.includes('deflate')) {
      zlib.inflate(buffer, (e, r) => e ? reject(e) : resolve(r));
    } else {
      resolve(buffer);
    }
  });
}

/* ════════════════════════════════════════════════════
   FETCH UPSTREAM
   ════════════════════════════════════════════════════ */
function fetchUpstream(targetUrl, method, headers, body, redirectCount = 0) {
  return new Promise((resolve, reject) => {
    if (redirectCount > 10) return reject(new Error('Too many redirects'));

    let parsed;
    try { parsed = new URL(targetUrl); } catch(e) { return reject(new Error('Invalid URL: ' + targetUrl)); }

    if (BLOCKED.has(parsed.hostname)) return reject(new Error('Blocked host'));
    if (!['http:', 'https:'].includes(parsed.protocol)) return reject(new Error('Protocol not allowed'));

    // Build clean request headers
    const reqHeaders = { 'accept-encoding': 'gzip, deflate, br' };
    for (const [k, v] of Object.entries(headers)) {
      const lk = k.toLowerCase();
      if (!STRIP_REQ.has(lk) && !lk.startsWith('x-forwarded') && !lk.startsWith('cf-') && !lk.startsWith('netlify-')) {
        reqHeaders[lk] = v;
      }
    }
    // Spoof origin/referer so sites don't block us
    reqHeaders['host']    = parsed.host;
    reqHeaders['origin']  = parsed.origin;
    reqHeaders['referer'] = parsed.origin + '/';
    if (!reqHeaders['user-agent']) {
      reqHeaders['user-agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
    }

    const options = {
      hostname: parsed.hostname,
      port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path:     parsed.pathname + parsed.search,
      method:   method || 'GET',
      headers:  reqHeaders,
      timeout:  15000,
      rejectUnauthorized: false, // allow self-signed certs
    };

    const lib = parsed.protocol === 'https:' ? https : http;
    const req = lib.request(options, (res) => {
      // Follow redirects
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers['location']) {
        let loc = res.headers['location'];
        try { loc = new URL(loc, targetUrl).href; } catch(e) {}
        res.resume();
        return resolve(fetchUpstream(loc, method === 'POST' && res.statusCode === 303 ? 'GET' : method, headers, body, redirectCount + 1));
      }

      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ res, buffer: Buffer.concat(chunks), finalUrl: targetUrl }));
      res.on('error', reject);
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });

    if (body && method !== 'GET' && method !== 'HEAD') req.write(body);
    req.end();
  });
}

/* ════════════════════════════════════════════════════
   MAIN HANDLER
   ════════════════════════════════════════════════════ */
exports.handler = async function(event) {
  /* ── CORS preflight ── */
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: CORS, body: '' };
  }

  /* ── Parse target URL ── */
  const params = event.queryStringParameters || {};
  const targetUrl = params.url || params.URL || params.u;

  if (!targetUrl) {
    return {
      statusCode: 400,
      headers: { ...CORS, 'content-type': 'text/plain' },
      body: 'Missing ?url= parameter. Usage: /.netlify/functions/proxy?url=https://example.com',
    };
  }

  let parsedTarget;
  try {
    parsedTarget = new URL(decodeURIComponent(targetUrl));
  } catch(e) {
    return {
      statusCode: 400,
      headers: { ...CORS, 'content-type': 'text/plain' },
      body: 'Invalid URL: ' + targetUrl,
    };
  }

  /* ── Fetch upstream ── */
  let upstreamRes, upstreamBuffer, finalUrl;
  try {
    const result = await fetchUpstream(
      parsedTarget.href,
      event.httpMethod,
      event.headers || {},
      event.body ? Buffer.from(event.body, event.isBase64Encoded ? 'base64' : 'utf8') : null
    );
    upstreamRes    = result.res;
    upstreamBuffer = result.buffer;
    finalUrl       = result.finalUrl;
  } catch(e) {
    return {
      statusCode: 502,
      headers: { ...CORS, 'content-type': 'text/plain' },
      body: 'Proxy error: ' + e.message,
    };
  }

  /* ── Build response headers ── */
  const resHeaders = { ...CORS };
  for (const [k, v] of Object.entries(upstreamRes.headers)) {
    const lk = k.toLowerCase();
    if (!STRIP_RES.has(lk) && lk !== 'set-cookie' && lk !== 'transfer-encoding' && lk !== 'content-encoding') {
      resHeaders[lk] = Array.isArray(v) ? v.join(', ') : v;
    }
  }

  const contentType = (upstreamRes.headers['content-type'] || '').toLowerCase();
  const contentEncoding = upstreamRes.headers['content-encoding'] || '';

  /* ── Decompress & optionally rewrite ── */
  let body;
  let isBase64 = false;

  const isText = contentType.includes('text/') || contentType.includes('javascript') || contentType.includes('json') || contentType.includes('xml') || contentType.includes('svg');

  if (isText) {
    try {
      const decompressed = await decompress(upstreamBuffer, contentEncoding);
      let text = decompressed.toString('utf8');

      if (contentType.includes('text/html')) {
        text = rewriteHtml(text, finalUrl);
      } else if (contentType.includes('text/css')) {
        text = rewriteCss(text, finalUrl);
      }

      body = text;
      resHeaders['content-type'] = contentType.includes('charset') ? contentType : contentType + '; charset=utf-8';
      delete resHeaders['content-length'];
    } catch(e) {
      // Fall back to raw binary
      body = upstreamBuffer.toString('base64');
      isBase64 = true;
    }
  } else {
    // Binary (images, fonts, videos, etc.) — pass through as-is
    // Decompress first if needed so Netlify can send it clean
    try {
      const decompressed = contentEncoding ? await decompress(upstreamBuffer, contentEncoding) : upstreamBuffer;
      body = decompressed.toString('base64');
    } catch(e) {
      body = upstreamBuffer.toString('base64');
    }
    isBase64 = true;
    delete resHeaders['content-length'];
  }

  return {
    statusCode: upstreamRes.statusCode || 200,
    headers: resHeaders,
    body,
    isBase64Encoded: isBase64,
  };
};
