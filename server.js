"use strict";

const express = require("express");
const path = require("path");
const dns = require("dns").promises;
const net = require("net");

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

const MAX_BYTES = 20 * 1024 * 1024;
const FETCH_TIMEOUT_MS = 12000;

// ---------- SSRF guard ----------
// The image-URL and Figma proxies fetch server-side on the user's behalf, so
// arbitrary hostnames must be resolved and checked before we ever hit them.
function isDisallowedIP(ip) {
  if (net.isIPv4(ip)) {
    const p = ip.split(".").map(Number);
    if (p[0] === 127 || p[0] === 10 || p[0] === 0) return true;
    if (p[0] === 169 && p[1] === 254) return true;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    return false;
  }
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    if (lower === "::1") return true;
    if (lower.startsWith("fe80:") || lower.startsWith("fc") || lower.startsWith("fd")) return true;
    return false;
  }
  return true;
}

async function assertSafeUrl(rawUrl) {
  let u;
  try {
    u = new URL(rawUrl);
  } catch (e) {
    throw new Error("Invalid URL.");
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new Error("Only http/https URLs are allowed.");
  }
  let addresses;
  try {
    addresses = await dns.lookup(u.hostname, { all: true });
  } catch (e) {
    throw new Error("Could not resolve host.");
  }
  for (const a of addresses) {
    if (isDisallowedIP(a.address)) throw new Error("Refusing to fetch a private/internal address.");
  }
  return u;
}

async function fetchImageWithLimit(url) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: controller.signal, redirect: "follow" });
    if (!res.ok) throw new Error("Upstream returned " + res.status);
    const contentType = res.headers.get("content-type") || "application/octet-stream";
    if (!contentType.startsWith("image/")) {
      throw new Error("That URL did not return an image (got " + contentType + ").");
    }
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length > MAX_BYTES) throw new Error("Image exceeds the 20MB limit.");
    return { buf, contentType };
  } finally {
    clearTimeout(timeout);
  }
}

// ---------- Generic image proxy (fixes CORS for the URL / Figma-vs-URL tabs) ----------
app.get("/api/fetch-image", async (req, res) => {
  try {
    const rawUrl = req.query.url;
    if (!rawUrl || typeof rawUrl !== "string") {
      return res.status(400).json({ error: "Missing url parameter." });
    }
    const safeUrl = await assertSafeUrl(rawUrl);
    const { buf, contentType } = await fetchImageWithLimit(safeUrl.toString());
    res.set("Content-Type", contentType);
    res.set("Cache-Control", "no-store");
    res.send(buf);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

// ---------- Figma frame proxy ----------
// Keeps the personal access token off the wire to any host except Figma's own
// API, and out of any response the browser has to hold onto beyond this call.
function parseFigmaUrl(url) {
  const fileMatch = url.match(/figma\.com\/(?:file|design)\/([a-zA-Z0-9]+)/);
  if (!fileMatch) return null;
  const fileKey = fileMatch[1];
  let nodeId = null;
  const nodeMatch = url.match(/node-id=([^&]+)/);
  if (nodeMatch) nodeId = decodeURIComponent(nodeMatch[1]).replace(/-/g, ":");
  return { fileKey, nodeId };
}

app.post("/api/figma/frame", async (req, res) => {
  try {
    const { figmaUrl, token } = req.body || {};
    if (!figmaUrl || !token) {
      return res.status(400).json({ error: "figmaUrl and token are required." });
    }
    const parsed = parseFigmaUrl(figmaUrl);
    if (!parsed || !parsed.nodeId) {
      return res.status(400).json({ error: "Could not parse a file key and node-id from that URL." });
    }

    const apiUrl =
      "https://api.figma.com/v1/images/" +
      parsed.fileKey +
      "?ids=" +
      encodeURIComponent(parsed.nodeId) +
      "&format=png&scale=2";

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    let data;
    try {
      const apiRes = await fetch(apiUrl, { headers: { "X-Figma-Token": token }, signal: controller.signal });
      if (!apiRes.ok) {
        throw new Error("Figma API returned " + apiRes.status + ". Check the token and file access.");
      }
      data = await apiRes.json();
    } finally {
      clearTimeout(timeout);
    }
    if (data.err) throw new Error("Figma API error: " + data.err);
    const imgUrl = data.images && data.images[parsed.nodeId];
    if (!imgUrl) throw new Error("Figma didn't return a rendered image for that node.");

    const { buf, contentType } = await fetchImageWithLimit(imgUrl);
    res.set("Content-Type", contentType);
    res.set("Cache-Control", "no-store");
    res.send(buf);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Coral running at http://localhost:" + PORT);
});
