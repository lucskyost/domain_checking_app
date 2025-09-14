const express = require("express");
const cors = require("cors");
const axios = require("axios");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
app.use(cors());

// =======================
//  Các API cũ
// =======================

// WHOIS lookup (whois.net.vn)
app.get("/api/whois/:domain", async (req, res) => {
  try {
    const { domain } = req.params;
    const url = `https://whois.net.vn/whois.php?domain=${domain}&act=getwhois`;
    const response = await axios.get(url, { responseType: "text" });
    res.set("Content-Type", "text/plain; charset=utf-8");
    res.send(response.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// IP info (ip-api.com)
app.get("/api/ip/:domain", async (req, res) => {
  try {
    const { domain } = req.params;
    const response = await axios.get(`http://ip-api.com/json/${domain}`);
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// SSL info (ssl-checker.io)
app.get("/api/ssl-summary/:domain", async (req, res) => {
  try {
    const { domain } = req.params;
    const url = `https://ssl-checker.io/api/v1/check/${domain}`;
    const { data } = await axios.get(url);

    if (!data.result) {
      return res.status(404).json({ error: "No SSL data found for this domain." });
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
      is_valid: result.cert_valid,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =======================
//  WebSocket với Socket.IO
// =======================

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" },
});

// Lưu danh sách user đang online (theo userId duy nhất)
const onlineUsers = new Set();

io.on("connection", (socket) => {
  console.log("🔌 New client connected:", socket.id);

  socket.on("join", ({ userId }) => {
    onlineUsers.add(userId);
    console.log("User joined:", userId, "=> Online:", onlineUsers.size);
    io.emit("onlineCount", onlineUsers.size);
  });

  socket.on("leave", ({ userId }) => {
    onlineUsers.delete(userId);
    console.log("User left:", userId, "=> Online:", onlineUsers.size);
    io.emit("onlineCount", onlineUsers.size);
  });

  socket.on("disconnect", () => {
    console.log("❌ Client disconnected:", socket.id);
    io.emit("onlineCount", onlineUsers.size);
  });
});

// =======================
//  Start server
// =======================

const PORT = 3001;
server.listen(PORT, () => {
  console.log(`✓ API + WebSocket server running at http://localhost:${PORT}`);
});
