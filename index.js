const http = require('http');
const net = require('net');
const url = require('url');
const auth = require('basic-auth');
const express = require('express');

// ========== 环境变量与伪装配置 ==========
const PORT = process.env.PORT || 3000;
const PROXY_USER = process.env.PROXY_USER || 'admin';
const PROXY_PASS = process.env.PROXY_PASS || 'glm123456';
const CAMOUFLAGE_URL = process.env.CAMOUFLAGE_URL || 'https://www.wikipedia.org';

/**
 * 多模式代理引擎 (Multi-mode Proxy Engine)
 * 支持协议：
 * 1. HTTP Proxy (Auth)
 * 2. HTTPS CONNECT (Auth)
 * 3. 流量探测分流与 Web 伪装 (Anti-detection)
 */

const app = express();

// 1. Web 伪装层 - 任何非代理请求将看到正常的网页内容或被重定向
app.get('/', (req, res) => {
    res.send('<html><body style="background:#000;color:#0f0;font-family:monospace;"><h1>System Diagnostic Tool</h1><p>Status: All systems operational.</p></body></html>');
});

// 2. 核心认证函数 - 同时支持 HTTP 代理(PROXY-AUTH)和 HTTPS CONNECT(AUTHORIZATION)
function checkAuth(req) {
    // 优先检查 URL 参数（备用认证方式）
    if (req.url.includes(`user=${PROXY_USER}`) && req.url.includes(`pass=${PROXY_PASS}`)) return true;
    
    // HTTP 代理请求使用 Proxy-Authorization 头
    let credentials = null;
    if (req.headers['proxy-authorization']) {
        credentials = auth.parse(req.headers['proxy-authorization']);
    } else if (req.headers['authorization']) {
        // HTTPS CONNECT 使用 Authorization 头（已在 connect 事件单独处理）
        credentials = auth(req);
    }
    return (credentials && credentials.name === PROXY_USER && credentials.pass === PROXY_PASS);
}

const server = http.createServer((req, res) => {
    // 识别 CONNECT 请求 (HTTPS 隧道)
    if (req.method === 'CONNECT') return; // 由 server.on('connect') 处理

    // 常规 HTTP 请求检查认证
    if (!checkAuth(req)) {
        res.statusCode = 407;
        res.setHeader('Proxy-Authenticate', 'Basic realm="System Access"');
        res.end('Access Denied');
        return;
    }

    // 处理标准 HTTP 代理请求
    const parsedUrl = url.parse(req.url);
    if (!parsedUrl.hostname) {
        // 如果没有 hostname，说明是直接通过浏览器访问的而非代理
        return app(req, res);
    }

    const options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || 80,
        path: parsedUrl.path,
        method: req.method,
        headers: req.headers
    };

    const proxyReq = http.request(options, (proxyRes) => {
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(res);
    });

    proxyReq.on('error', () => {
        res.statusCode = 502;
        res.end();
    });

    req.pipe(proxyReq);
});

// 3. 处理 HTTPS CONNECT
server.on('connect', (req, clientSocket, head) => {
    // 防探测：认证检查
    const authHeader = req.headers['proxy-authorization'];
    const credentials = auth.parse(authHeader);

    if (!credentials || credentials.name !== PROXY_USER || credentials.pass !== PROXY_PASS) {
        clientSocket.write('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="System Access"\r\n\r\n');
        clientSocket.destroy();
        return;
    }

    const { port, hostname } = url.parse(`http://${req.url}`);
    const serverSocket = net.connect(port || 443, hostname, () => {
        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        serverSocket.write(head);
        serverSocket.pipe(clientSocket);
        clientSocket.pipe(serverSocket);
    });

    serverSocket.on('error', () => clientSocket.destroy());
    clientSocket.on('error', () => serverSocket.destroy());
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`[SECURE PROXY] Multi-mode server active on port ${PORT}`);
    console.log(`[CAMOUFLAGE] Web interface enabled for anti-detection`);
});
