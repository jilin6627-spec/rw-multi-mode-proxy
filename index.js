const http = require('http');
const net = require('net');
const url = require('url');
const { SocksClient } = require('socks');
const basicAuth = require('basic-auth');
const { Writable } = require('stream');

// ========== Configuration ==========
const PORT = process.env.PORT || process.env.RAILWAY_TCP_APPLICATION_PORT || 3000;
const SOCKS5_PORT = process.env.SOCKS5_PORT || 3001;
const TARGET_HOST = process.env.TARGET_HOST || 'localhost';
const TARGET_PORT = parseInt(process.env.TARGET_PORT || '3000', 10);
const PROXY_USER = process.env.PROXY_USER || 'admin';
const PROXY_PASS = process.env.PROXY_PASS || 'glm123456';
const ARGO_AUTH = process.env.ARGO_AUTH || '';
const ARGO_DOMAIN = process.env.ARGO_DOMAIN || '';

// ========== Fixed payload for WebSocket camouflage ==========
const CAMOUFLAGE_HTML = `<!DOCTYPE html>
<html>
<head><title>Monitoring Service</title></head>
<body style="font-family:Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#1a1a2e;color:#eee">
<div style="text-align:center">
<h1>Service Online</h1>
<p>All systems operational · v2.1.6</p>
</div>
</body></html>`;

// ========== Camouflage endpoint (anti-detection) ==========
function setupCamouflage() {
  if (!ARGO_AUTH || !ARGO_DOMAIN) return null;
  
  const options = {
    key: ARGO_AUTH.split(':').length === 3 ? `-----BEGIN RSA PRIVATE KEY-----\n${ARGO_AUTH.split(':')[1]}\n-----END RSA PRIVATE KEY-----` : null,
    cert: ARGO_AUTH.split(':').length === 3 ? `-----BEGIN CERTIFICATE-----\n${ARGO_AUTH.split(':')[2]}\n-----END CERTIFICATE-----` : null,
    ca: ARGO_AUTH.split(':').length === 3 ? `-----BEGIN CERTIFICATE-----\n${ARGO_AUTH.split(':')[0]}\n-----END CERTIFICATE-----` : null
  };
  
  try {
    const srv = require('https').createServer(options, (req, res) => {
      if (req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'healthy', timestamp: Date.now() }));
      } else if (req.url === '/sub') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ 
          subscribers: Math.floor(Math.random() * 100) + 1,
          active: true,
          uptime: process.uptime().toFixed(0)
        }));
      } else {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(CAMOUFLAGE_HTML);
      }
    });
    return srv;
  } catch (e) {
    console.error('[CAMOUFLAGE] Init failed:', e.message);
    return null;
  }
}

// ========== Basic authentication ==========
function checkAuth(req) {
  const credentials = basicAuth(req);
  if (!credentials || credentials.name !== PROXY_USER || credentials.pass !== PROXY_PASS) {
    return false;
  }
  return true;
}

// ========== HTTP Proxy Request Handler ==========
function handleHttpProxy(req, res, clientSocket) {
  if (!checkAuth(req)) {
    res.writeHead(407, { 
      'Proxy-Authenticate': 'Basic realm="Secure Proxy"',
      'Content-Type': 'text/plain' 
    });
    res.end('Proxy Authentication Required\n');
    return;
  }

  // Non-CONNECT requests: direct HTTP relay (forward)
  if (req.method !== 'CONNECT') {
    console.log(`[HTTP] ${req.method} ${req.url}`);
    
    const options = {
      hostname: TARGET_HOST,
      port: TARGET_PORT,
      path: req.url,
      method: req.method,
      headers: { ...req.headers, host: `${TARGET_HOST}:${TARGET_PORT}` }
    };

    const proxyReq = http.request(options, (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res);
    });

    proxyReq.on('error', (err) => {
      console.error('[HTTP] Relay error:', err.message);
      res.writeHead(502);
      res.end('Bad Gateway\n');
    });

    req.pipe(proxyReq);
    return;
  }

  // CONNECT method: HTTPS tunnel
  const [targetHost, targetPortStr] = req.url.split(':');
  const targetPort = parseInt(targetPortStr, 10) || 443;

  console.log(`[CONNECT] ${targetHost}:${targetPort}`);

  const serverSocket = net.createConnection({ host: targetHost, port: targetPort }, () => {
    res.writeHead(200, { 'Connection': 'Establish' });
    res.end();

    serverSocket.pipe(clientSocket);
    clientSocket.pipe(serverSocket);
  });

  serverSocket.on('error', (err) => {
    console.error('[CONNECT] Error:', err.message);
    res.writeHead(502);
    res.end('Connection failed\n');
  });
}

// ========== HTTP Server ==========
const server = http.createServer((req, res) => {
  handleHttpProxy(req, res, null);
});

server.on('connect', (req, clientSocket, head) => {
  handleHttpProxy(req, { writeHead: (code, headers) => {
    clientSocket.write(`HTTP/1.1 ${code} ${http.STATUS_CODES[code] || ''}\r\n`);
    for (const [k, v] of Object.entries(headers || {})) {
      clientSocket.write(`${k}: ${v}\r\n`);
    }
    clientSocket.write('\r\n');
    if (head && head.length) clientSocket.write(head);
  }, end: (data) => { if (data) clientSocket.write(data); clientSocket.end(); } }, clientSocket);
});

// ========== SOCKS5 Server ==========
const SOCKS5_VERSION = 0x05;

const SOCKS5_CMD = {
  CONNECT: 0x01,
  BIND: 0x02,
  UDP: 0x03
};

const SOCKS5_ATYP = {
  IPV4: 0x01,
  DOMAIN: 0x03,
  IPV6: 0x04
};

let socksServer;

function startSocks5() {
  socksServer = net.createServer((clientSocket) => {
    console.log('[SOCKS5] New connection');

    let stage = 'greeting';
    const buffer = [];

    clientSocket.on('data', (data) => {
      if (stage === 'greeting') {
        if (data[0] !== SOCKS5_VERSION) {
          clientSocket.write(Buffer.from([0x05, 0xFF]));
          clientSocket.destroy();
          return;
        }

        const nmethods = data[1];
        const methods = Array.from(data.slice(2, 2 + nmethods));

        // Support: 0x00 (no auth), 0x02 (username/password)
        if (methods.includes(0x00)) {
          clientSocket.write(Buffer.from([0x05, 0x00]));
          stage = 'request';
        } else if (methods.includes(0x02)) {
          clientSocket.write(Buffer.from([0x05, 0x02]));
          stage = 'auth';
        } else {
          clientSocket.write(Buffer.from([0x05, 0xFF]));
          clientSocket.destroy();
        }
      } else if (stage === 'auth') {
        if (data[0] === 0x01 && data[1] > 0) {
          const uLen = data[1];
          const username = data.slice(2, 2 + uLen).toString();
          const pLen = data[2 + uLen];
          const password = data.slice(3 + uLen, 3 + uLen + pLen).toString();

          if (username === PROXY_USER && password === PROXY_PASS) {
            clientSocket.write(Buffer.from([0x01, 0x00]));
            stage = 'request';
          } else {
            clientSocket.write(Buffer.from([0x01, 0x01]));
            clientSocket.destroy();
          }
        } else {
          clientSocket.destroy();
        }
      } else if (stage === 'request') {
        if (data[0] !== SOCKS5_VERSION) {
          clientSocket.destroy();
          return;
        }

        const cmd = data[1];
        const atyp = data[3];

        let targetAddress, targetPort;
        let offset = 4;

        if (atyp === SOCKS5_ATYP.IPV4) {
          targetAddress = data.slice(offset, offset + 4).join('.');
          offset += 4;
        } else if (atyp === SOCKS5_ATYP.DOMAIN) {
          const domainLen = data[offset];
          targetAddress = data.slice(offset + 1, offset + 1 + domainLen).toString();
          offset += 1 + domainLen;
        } else if (atyp === SOCKS5_ATYP.IPV6) {
          targetAddress = data.slice(offset, offset + 16).map(b => b.toString(16).padStart(2, '0')).join(':');
          offset += 16;
        } else {
          clientSocket.write(Buffer.from([0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
          clientSocket.destroy();
          return;
        }

        targetPort = (data[offset] << 8) | data[offset + 1];

        if (cmd === SOCKS5_CMD.CONNECT) {
          console.log(`[SOCKS5] CONNECT ${targetAddress}:${targetPort}`);

          const serverSocket = net.createConnection({ host: targetAddress, port: targetPort }, () => {
            const reply = Buffer.from([
              0x05, 0x00, 0x00, 0x01,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]);
            clientSocket.write(reply);

            serverSocket.pipe(clientSocket);
            clientSocket.pipe(serverSocket);

            clientSocket.removeAllListeners('data');
            clientSocket.on('close', () => serverSocket.destroy());
            serverSocket.on('close', () => clientSocket.destroy());
          });

          serverSocket.on('error', () => {
            clientSocket.write(Buffer.from([0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
            clientSocket.destroy();
          });

          clientSocket.on('error', () => serverSocket.destroy());
        } else {
          console.log(`[SOCKS5] Unsupported CMD: 0x${cmd.toString(16)}`);
          clientSocket.write(Buffer.from([0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
          clientSocket.destroy();
        }
      }
    });

    clientSocket.on('error', () => {});
    clientSocket.on('close', () => {});
  });

  socksServer.listen(SOCKS5_PORT, '0.0.0.0', () => {
    console.log(`[SOCKS5] SOCKS5 proxy listening on port ${SOCKS5_PORT}`);
  });

  socksServer.on('error', (err) => {
    console.error(`[SOCKS5] Error: ${err.message}`);
  });
}

// ========== Start ==========
const camouflage = setupCamouflage();
if (camouflage) {
  camouflage.listen(3002, '::', () => {
    console.log('[CAMOUFLAGE] HTTPS tunnel listening on port 3002');
  });
}

startSocks5();

server.listen(PORT, '::', () => {
  console.log(`[SECURE PROXY] Multi-mode server active on port ${PORT}`);
  console.log(`[MODES] HTTP/HTTPS Proxy + SOCKS5 on ${PORT}`);
  if (ARGO_DOMAIN) {
    console.log(`[TUNNEL] ${ARGO_DOMAIN} (port 3002)`);
  }
  console.log(`[AUTH] ${PROXY_USER}:${PROXY_PASS}`);
});

server.on('error', (err) => {
  console.error('[PROXY] Error:', err.message);
  if (err.code === 'EADDRINUSE') {
    console.error(`[FATAL] Port ${PORT} already in use`);
    process.exit(1);
  }
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('[SHUTDOWN] Graceful stop...');
  server.close(() => process.exit(0));
});
