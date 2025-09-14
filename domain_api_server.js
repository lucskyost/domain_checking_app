const express = require('express');
const cors = require('cors');
const axios = require('axios');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
app.use(cors());

// Tạo HTTP server từ Express
const server = http.createServer(app);

// Gắn Socket.IO vào server
const io = new Server(server, {
  cors: {
    origin: "*",
  }
});

// ==================== API ROUTES ====================
// WHOIS lookup(whois.net.vn)
app.get('/api/whois/:domain', async (req, res) => {
    try {
        const { domain } = req.params;
        const url = `https://whois.net.vn/whois.php?domain=${domain}&act=getwhois`;
        const response = await axios.get(url, { responseType: 'text' });
        res.set('Content-Type', 'text/plain; charset=utf-8');
        res.send(response.data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// IP info(ip-api.com)
app.get('/api/ip/:domain', async (req, res) => {
    try {
        const { domain } = req.params;
        const response = await axios.get(`http://ip-api.com/json/${domain}`);
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// SSL info(ssl-checker.io)
app.get('/api/ssl-summary/:domain', async (req, res) => {
    try {
        const { domain } = req.params;
        const url = `https://ssl-checker.io/api/v1/check/${domain}`;
        const { data } = await axios.get(url);

        if (!data.result) {
            return res.status(404).json({ error: 'No SSL data found for this domain.' });
        }

        const result = data.result;
        res.json({
            domain: result.host,
            ip: result.resolved_ip,
            issued_to: result.issued_to,
            issued_org: result.issued_o,
            issuer_org: result.issuer_o,
            issuer_cn: result.issuer_cn,
            valid_from: result.valid_from,
            valid_to: result.valid_till,
            days_remaining: result.days_left,
            is_valid: result.cert_valid
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== SOCKET.IO ====================
const activeUsers = new Map(); // userId -> số tab đang mở

function broadcastOnlineCount() {
  io.emit("onlineCount", activeUsers.size);
}

io.on("connection", (socket) => {
  socket.on("join", ({ userId }) => {
    if (!activeUsers.has(userId)) {
      activeUsers.set(userId, 0);
    }
    activeUsers.set(userId, activeUsers.get(userId) + 1);
    socket.userId = userId;
    broadcastOnlineCount();
  });

  socket.on("leave", ({ userId }) => {
    if (activeUsers.has(userId)) {
      const tabs = activeUsers.get(userId) - 1;
      if (tabs <= 0) {
        activeUsers.delete(userId);
      } else {
        activeUsers.set(userId, tabs);
      }
      broadcastOnlineCount();
    }
  });

  socket.on("disconnect", () => {
    const userId = socket.userId;
    if (userId && activeUsers.has(userId)) {
      const tabs = activeUsers.get(userId) - 1;
      if (tabs <= 0) {
        activeUsers.delete(userId);
      } else {
        activeUsers.set(userId, tabs);
      }
      broadcastOnlineCount();
    }
  });
});

// ==================== START ====================
server.listen(3001, () => {
  console.log('✓ API + Socket.IO server running at http://localhost:3001');
});
