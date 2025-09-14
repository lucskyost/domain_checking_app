const express = require('express');
const cors = require('cors');
const axios = require('axios');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
app.use(cors());

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" }
});

// Quản lý user và tab
let users = {}; 
// users = { userId: { tabCount: 2 } }

io.on('connection', (socket) => {
  let currentUserId = null;

  socket.on('user_connected', (userId) => {
    currentUserId = userId;

    if (!users[userId]) {
      users[userId] = { tabCount: 0 };
    }
    users[userId].tabCount++;

    io.emit('online_count', Object.keys(users).length);
  });

  socket.on('disconnect', () => {
    if (currentUserId && users[currentUserId]) {
      users[currentUserId].tabCount--;
      if (users[currentUserId].tabCount <= 0) {
        delete users[currentUserId];
      }
      io.emit('online_count', Object.keys(users).length);
    }
  });
});

// API WHOIS
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

// API IP
app.get('/api/ip/:domain', async (req, res) => {
  try {
    const { domain } = req.params;
    const response = await axios.get(`http://ip-api.com/json/${domain}`);
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// API SSL
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

server.listen(3001, () => {
  console.log('✓ Proxy server with socket.io running at http://localhost:3001');
});
