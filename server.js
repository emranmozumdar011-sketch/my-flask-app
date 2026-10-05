// EM Fast 4K — Render Web Service
// Server-side streaming downloader.
// API keys belong in Render Environment Variables.
// SaveAPI is used only when the submitted URL is not already a direct video file.

const express = require("express");
const helmet = require("helmet");
const { rateLimit } = require("express-rate-limit");
const dns = require("node:dns").promises;
const net = require("node:net");
const path = require("node:path");
const fs = require("node:fs");

const app = express();
const PORT = process.env.PORT || 3000;
const SAVEAPI_KEY = process.env.SAVEAPI_KEY || process.env.SAVEAPI_API_KEY || "";

const MAX_FILE_BYTES = 5 * 1024 * 1024 * 1024;
const MAX_REDIRECTS = 5;
const SAVEAPI_BASE = "https://api.saveapi.org/v1";

app.disable("x-powered-by");
app.set("trust proxy", 1);

app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: null
    }
  }
}));

app.use(express.json({ limit: "8kb" }));

const PUBLIC_DIR = path.join(__dirname, "public");
const ROOT_INDEX = path.join(__dirname, "index.html");
const PUBLIC_INDEX = path.join(PUBLIC_DIR, "index.html");
const INDEX_FILE = fs.existsSync(PUBLIC_INDEX) ? PUBLIC_INDEX : ROOT_INDEX;

app.use(express.static(
  fs.existsSync(PUBLIC_DIR) ? PUBLIC_DIR : __dirname,
  { extensions: ["html"] }
));

app.use("/api/prepare", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 120,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many requests. Please try again later." }
}));

// ---------------- SECURITY ----------------

function isPrivateIPv4(ip) {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b] = p;
  return (
    a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51) ||
    (a === 203 && b === 0)
  );
}

function isPrivateIPv6(ip) {
  const v = ip.toLowerCase().split("%")[0];
  return (
    v === "::" || v === "::1" ||
    v.startsWith("fc") || v.startsWith("fd") ||
    v.startsWith("fe80:") || v.startsWith("ff") ||
    v.startsWith("::ffff:127.") ||
    v.startsWith("::ffff:10.") ||
    v.startsWith("::ffff:192.168.")
  );
}

async function assertPublicHttpUrl(input) {
  let u;
  try { u = new URL(input); }
  catch { throw new Error("Please provide a valid video link."); }

  if (!["http:", "https:"].includes(u.protocol) || u.username || u.password) {
    throw new Error("Only normal HTTP/HTTPS links are supported.");
  }

  const host = u.hostname.toLowerCase().replace(/^\\[|\\]$/g, "");

  if (!host || host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) {
    throw new Error("This address cannot be used.");
  }

  const ipType = net.isIP(host);

  if (ipType === 4 && isPrivateIPv4(host)) {
    throw new Error("This address cannot be used.");
  }

  if (ipType === 6 && isPrivateIPv6(host)) {
    throw new Error("This address cannot be used.");
  }

  if (!ipType) {
    let records;
    try {
      records = await dns.lookup(host, { all: true, verbatim: true });
    } catch {
      throw new Error("The site address could not be found.");
    }

    if (!records.length || records.some(r =>
      r.family === 4 ? isPrivateIPv4(r.address) : isPrivateIPv6(r.address)
    )) {
      throw new Error("This site address is not safe to use.");
    }
  }

  return u;
}

async function fetchWithSafeRedirects(inputUrl, options = {}, maxRedirects = MAX_REDIRECTS) {
  let current = inputUrl;

  for (let i = 0; i <= maxRedirects; i++) {
    await assertPublicHttpUrl(current);

    const response = await fetch(current, {
      ...options,
      redirect: "manual",
      signal: options.signal || AbortSignal.timeout(30000),
      headers: {
        "user-agent": "EMFast4K/2.0",
        ...(options.headers || {})
      }
    });

    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      await response.body?.cancel().catch(() => {});

      if (!location || i === maxRedirects) {
        throw new Error("The site redirect could not be completed.");
      }

      current = new URL(location, current).toString();
      continue;
    }

    return { response, finalUrl: current };
  }

  throw new Error("Too many redirects.");
}

// ---------------- VIDEO HELPERS ----------------

const VIDEO_EXT = /\.(mp4|m4v|mov|webm|mkv|avi|mpeg|mpg|3gp|ogv)(?:$|[?#])/i;

function looksLikeVideoResponse(response, url) {
  const type = (response.headers.get("content-type") || "").toLowerCase();
  let pathname = "";
  try { pathname = new URL(url).pathname; } catch {}

  return (
    type.startsWith("video/") ||
    type.includes("mp4") ||
    type.includes("quicktime") ||
    type.includes("webm") ||
    type === "application/octet-stream" ||
    VIDEO_EXT.test(pathname)
  );
}

function parseContentLength(response) {
  const n = Number(response.headers.get("content-length"));
  return Number.isFinite(n) && n >= 0 ? n : null;
}

function parseTotalSize(response) {
  const length = parseContentLength(response);
  if (length != null) return length;

  const range = response.headers.get("content-range") || "";
  const m = range.match(/\/([0-9]+)$/);
  return m ? Number(m[1]) : null;
}

function tooLarge(size) {
  return Number.isFinite(size) && size > MAX_FILE_BYTES;
}

function cleanFileName(value) {
  const cleaned = String(value || "EM-Fast-4K-Video")
    .replace(/[<>:"/\\|?*\u0000-\u001F]/g, "_")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 120);

  return cleaned || "EM-Fast-4K-Video";
}

function titleFromUrl(value) {
  try {
    const u = new URL(value);
    const last = decodeURIComponent(
      u.pathname.split("/").filter(Boolean).pop() || ""
    );

    return cleanFileName(
      last.replace(/\\.[a-z0-9]{2,5}$/i, "") || u.hostname
    );
  } catch {
    return "EM-Fast-4K-Video";
  }
}

function isYouTubeUrl(input) {
  try {
    const host = new URL(input).hostname.toLowerCase().replace(/^www\\./, "");
    return host === "youtube.com" ||
      host.endsWith(".youtube.com") ||
      host === "youtu.be";
  } catch {
    return false;
  }
}

function numberFromQuality(value) {
  const m = String(value || "").match(/(\\d{3,4})p/i);
  return m ? Number(m[1]) : 0;
}

function getFormatSize(format) {
  const raw =
    format?.file_size ??
    format?.filesize ??
    format?.size ??
    format?.size_mb;

  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0) return null;

  if (
    format?.size_mb != null &&
    format?.file_size == null &&
    format?.filesize == null &&
    format?.size == null
  ) {
    return n * 1024 * 1024;
  }

  return n;
}

// Read a small amount only for validation.
// The bytes are returned so the real download stream does not lose them.
async function readFirstChunk(body, maxBytes = 64 * 1024) {
  const reader = body.getReader();
  let received = new Uint8Array(0);

  try {
    while (received.byteLength < maxBytes) {
      const { value, done } = await reader.read();
      if (done) break;
      if (!value || !value.byteLength) continue;

      const room = maxBytes - received.byteLength;
      const part = value.byteLength <= room ? value : value.slice(0, room);

      const merged = new Uint8Array(received.byteLength + part.byteLength);
      merged.set(received, 0);
      merged.set(part, received.byteLength);
      received = merged;

      // One chunk is enough for media signature validation.
      if (received.byteLength >= 4096) break;
    }
  } catch (e) {
    try { await reader.cancel(); } catch {}
    throw e;
  }

  return { reader, first: received };
}

function looksLikeMediaBytes(bytes) {
  if (!bytes || !bytes.byteLength) return false;

  const max = Math.min(bytes.byteLength, 64 * 1024);
  const text = Buffer.from(bytes.slice(0, max)).toString("latin1").toLowerCase();

  // MP4 / MOV / M4V normally contain an ftyp box near the beginning.
  if (text.includes("ftyp")) return true;

  // WebM / Matroska EBML signature.
  if (
    bytes.byteLength >= 4 &&
    bytes[0] === 0x1a &&
    bytes[1] === 0x45 &&
    bytes[2] === 0xdf &&
    bytes[3] === 0xa3
  ) return true;

  // MPEG-TS / MPEG audio-ish binary streams: reject obvious HTML/JSON only.
  const trimmed = text.trimStart();
  if (
    trimmed.startsWith("<!doctype") ||
    trimmed.startsWith("<html") ||
    trimmed.startsWith("{\"") ||
    trimmed.startsWith("{'")
  ) {
    return false;
  }

  // If it is binary and not an obvious text error, allow octet-stream.
  let printable = 0;
  for (let i = 0; i < Math.min(bytes.length, 1024); i++) {
    const c = bytes[i];
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c <= 126)) printable++;
  }

  return printable < Math.min(bytes.length, 1024) * 0.90;
}

// ---------------- SAVEAPI ----------------

function saveApiErrorMessage(response, data) {
  const code = data?.error?.code || "";

  if (response.status === 429 || code === "RATE_LIMITED") {
    return "SaveAPI rate limit reached. Please try again later.";
  }

  if (
    response.status === 401 ||
    code === "INVALID_API_KEY" ||
    code === "MISSING_API_KEY"
  ) {
    return "SaveAPI key is invalid. Check Render → Environment Variables.";
  }

  if (code === "QUOTA_EXCEEDED") {
    return "SaveAPI credit balance is empty. Please add credits and try again.";
  }

  if (code === "PRIVATE_CONTENT") {
    return "This video is private and cannot be downloaded.";
  }

  if (code === "MEDIA_NOT_FOUND") {
    return "The video was deleted, restricted, or has no downloadable media.";
  }

  if (code === "UNSUPPORTED_PLATFORM") {
    return "This video site is not supported by SaveAPI.";
  }

  if (code === "INVALID_FORMAT") {
    return "The requested YouTube quality is not available.";
  }

  if (code === "LINK_EXPIRED") {
    return "The download link expired. Please try again.";
  }

  if (code === "UPSTREAM_TIMEOUT" || code === "UPSTREAM_ERROR") {
    return "The video site did not respond. Please try again.";
  }

  return data?.error?.message ||
    `SaveAPI request failed (HTTP ${response.status}).`;
}

async function callSaveApi(endpoint, params, timeoutMs = 30000) {
  if (!SAVEAPI_KEY) {
    throw new Error(
      "SAVEAPI_KEY is not configured in Render → Environment Variables."
    );
  }

  const url = new URL(`${SAVEAPI_BASE}${endpoint}`);

  for (const [key, value] of Object.entries(params || {})) {
    url.searchParams.set(key, String(value));
  }

  const response = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${SAVEAPI_KEY}`,
      Accept: "application/json"
    },
    signal: AbortSignal.timeout(timeoutMs)
  });

  let data = null;
  try { data = await response.json(); } catch {}

  if (!response.ok || data?.success === false) {
    const error = new Error(saveApiErrorMessage(response, data));
    error.httpStatus = response.status;
    error.saveApiCode = data?.error?.code || "";
    throw error;
  }

  return data;
}

async function prepareYouTube(inputUrl) {
  const info = await callSaveApi(
    "/youtube/info",
    { url: inputUrl },
    30000
  );

  const formats = Array.isArray(info?.formats)
    ? info.formats.filter(f => numberFromQuality(f?.quality) > 0)
    : [];

  if (!formats.length) {
    throw new Error(
      "SaveAPI did not return a downloadable YouTube video quality."
    );
  }

  const usable = formats
    .map(f => ({
      format: f,
      height: numberFromQuality(f.quality),
      size: getFormatSize(f)
    }))
    .filter(x => !tooLarge(x.size))
    .sort((a, b) =>
      b.height - a.height ||
      ((b.size || 0) - (a.size || 0))
    );

  if (!usable.length) {
    throw new Error(
      "All available YouTube video qualities are larger than the 5 GB limit."
    );
  }

  const chosen = usable[0];

  const made = await callSaveApi(
    "/youtube/create",
    {
      url: inputUrl,
      quality: chosen.format.quality
    },
    60000
  );

  if (!made?.url || typeof made.url !== "string") {
    throw new Error(
      "SaveAPI did not return a valid YouTube download stream."
    );
  }

  const madeSize = Number(made.file_size);
  const size =
    Number.isFinite(madeSize) && madeSize >= 0
      ? madeSize
      : chosen.size;

  if (tooLarge(size)) return { tooLarge: true };

  return {
    url: made.url,
    title: cleanFileName(
      made.filename ||
      made.title ||
      info.title ||
      titleFromUrl(inputUrl)
    ),
    size: Number.isFinite(size) ? size : null,
    quality: chosen.format.quality
  };
}

// ---------------- HEALTH ----------------

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    service: "EM Fast 4K",
    saveApiConfigured: Boolean(SAVEAPI_KEY),
    maxFileBytes: MAX_FILE_BYTES,
    downloadMode: "server-stream-validated"
  });
});

// ---------------- PREPARE ----------------

app.post("/api/prepare", async (req, res) => {
  const inputUrl = String(req.body?.url || "").trim();

  if (!inputUrl || inputUrl.length > 3000) {
    return res.status(400).json({
      error: "Please provide a valid video link."
    });
  }

  try {
    await assertPublicHttpUrl(inputUrl);

    // 1. Direct video URL: do not spend SaveAPI credits.
    const direct = await probeDirectVideo(inputUrl);

    if (direct.direct) {
      if (tooLarge(direct.size)) {
        return res.status(413).json({
          error: "Maximum file size is 5 GB."
        });
      }

      const title = cleanFileName(titleFromUrl(direct.url));

      return res.json({
        ok: true,
        directUrl:
          `/api/download?url=${encodeURIComponent(direct.url)}` +
          `&name=${encodeURIComponent(title)}`,
        title,
        method: "direct",
        size: direct.size
      });
    }

    if (!SAVEAPI_KEY) {
      return res.status(503).json({
        error:
          "This link is not a direct video file. Add SAVEAPI_KEY in Render → Environment Variables."
      });
    }

    // 2. YouTube special flow.
    if (isYouTubeUrl(inputUrl)) {
      const yt = await prepareYouTube(inputUrl);

      if (yt.tooLarge) {
        return res.status(413).json({
          error: "Maximum file size is 5 GB."
        });
      }

      return res.json({
        ok: true,
        directUrl:
          `/api/download?url=${encodeURIComponent(yt.url)}` +
          `&name=${encodeURIComponent(yt.title)}`,
        title: yt.title,
        method: "saveapi-youtube",
        quality: yt.quality,
        size: yt.size
      });
    }

    // 3. Other supported platforms.
    let data;

    try {
      data = await callSaveApi(
        "/download",
        { url: inputUrl },
        30000
      );
    } catch (error) {
      return res.status(error.httpStatus === 429 ? 429 : 502).json({
        error: error.message
      });
    }

    const candidates = [
      ...(Array.isArray(data?.formats) ? data.formats : []),
      ...(Array.isArray(data?.medias) ? data.medias : [])
    ].filter(item =>
      item &&
      item.type !== "audio" &&
      typeof item.url === "string" &&
      /^https?:\/\//i.test(item.url) &&
      (
        item.type === "video" ||
        VIDEO_EXT.test(item.url) ||
        /mp4|video/i.test(
          String(item.ext || item.mime || item.content_type || "")
        )
      )
    );

    candidates.sort((a, b) => {
      const aq = Number(a?.height || a?.quality_height || 0);
      const bq = Number(b?.height || b?.quality_height || 0);

      if (aq !== bq) return bq - aq;

      const as = Number(
        a?.file_size ??
        a?.filesize ??
        a?.size ??
        a?.size_mb ??
        0
      );

      const bs = Number(
        b?.file_size ??
        b?.filesize ??
        b?.size ??
        b?.size_mb ??
        0
      );

      return bs - as;
    });

    const media = candidates[0] || null;

    if (!media) {
      return res.status(422).json({
        error:
          "SaveAPI did not return a downloadable video for this link."
      });
    }

    await assertPublicHttpUrl(media.url);

    let size = Number(
      media.file_size ??
      media.filesize ??
      media.size ??
      media.content_length
    );

    if (
      !Number.isFinite(size) &&
      Number.isFinite(Number(media.size_mb))
    ) {
      size = Number(media.size_mb) * 1024 * 1024;
    }

    if (!Number.isFinite(size)) size = null;

    if (tooLarge(size)) {
      return res.status(413).json({
        error: "Maximum file size is 5 GB."
      });
    }

    const title = cleanFileName(
      data?.meta?.title ||
      data?.title ||
      media?.title ||
      titleFromUrl(inputUrl)
    );

    return res.json({
      ok: true,
      directUrl:
        `/api/download?url=${encodeURIComponent(media.url)}` +
        `&name=${encodeURIComponent(title)}`,
      title,
      method: "saveapi",
      size
    });
  } catch (error) {
    const message =
      error?.name === "TimeoutError"
        ? "The site took too long to respond. Please try again."
        : (error.message || "The link could not be processed.");

    return res.status(error.httpStatus === 429 ? 429 : 400).json({
      error: message
    });
  }
});

// ---------------- REAL STREAM ----------------
//
// Important fixes:
// 1. Never send Content-Length from an untrusted API size.
// 2. Read and validate the first media bytes BEFORE creating the download.
// 3. Do not create a 0-byte/HTML file when the upstream server returns an error.
// 4. Stream chunks directly; never buffer the whole video in Render RAM.
// 5. Abort cleanly if the upstream ends unexpectedly.

app.get("/api/download", async (req, res) => {
  const inputUrl = String(req.query?.url || "").trim();

  if (!inputUrl || inputUrl.length > 16000) {
    return res.status(400).json({
      error: "The download link is not valid."
    });
  }

  let upstreamBody = null;
  let upstreamReader = null;

  try {
    await assertPublicHttpUrl(inputUrl);

    const { response, finalUrl } = await fetchWithSafeRedirects(
      inputUrl,
      {
        method: "GET",
        headers: {
          accept: "video/*,application/octet-stream;q=0.9,*/*;q=0.5",
          "accept-encoding": "identity"
        },
        signal: AbortSignal.timeout(180000)
      }
    );

    upstreamBody = response.body;

    if (!response.ok || !upstreamBody) {
      await upstreamBody?.cancel().catch(() => {});
      return res.status(502).json({
        error:
          `The video server could not provide the download (HTTP ${response.status}).`
      });
    }

    const upstreamType =
      (response.headers.get("content-type") || "").toLowerCase();

    const upstreamSize = parseTotalSize(response);

    if (tooLarge(upstreamSize)) {
      await upstreamBody.cancel().catch(() => {});
      return res.status(413).json({
        error: "Maximum file size is 5 GB."
      });
    }

    // Get first bytes before sending ANY download headers.
    const firstRead = await readFirstChunk(upstreamBody, 64 * 1024);
    upstreamReader = firstRead.reader;
    const firstBytes = firstRead.first;

    if (!firstBytes.byteLength) {
      try { await upstreamReader.cancel(); } catch {}
      return res.status(502).json({
        error:
          "The video server returned an empty file. No download was created."
      });
    }

    const typeLooksVideo =
      upstreamType.startsWith("video/") ||
      upstreamType.includes("mp4") ||
      upstreamType.includes("quicktime") ||
      upstreamType.includes("webm");

    const bytesLookMedia = looksLikeMediaBytes(firstBytes);

    const obviouslyText =
      /^(<!doctype|<html|\\{\\s*["']?(error|message|success)|access denied|forbidden)/i.test(
        Buffer.from(firstBytes.slice(0, 4096)).toString("utf8").trim()
      );

    if (obviouslyText || (!typeLooksVideo && !bytesLookMedia)) {
      try { await upstreamReader.cancel(); } catch {}

      return res.status(502).json({
        error:
          "The video server returned an invalid file instead of video. Please try again."
      });
    }

    const requestedName = cleanFileName(
      String(req.query?.name || "").trim()
    );

    const fallbackName = titleFromUrl(finalUrl);

    const fileName =
      cleanFileName(requestedName || fallbackName) ||
      "EM-Fast-4K-Video";

    // Preserve the real media type where possible.
    let contentType = upstreamType;

    if (!contentType ||
        contentType === "application/octet-stream" ||
        contentType === "binary/octet-stream") {
      if (/webm|matroska/i.test(upstreamType) || /\.webm$/i.test(finalUrl)) {
        contentType = "video/webm";
      } else {
        contentType = "video/mp4";
      }
    }

    // Do NOT send upstream Content-Length.
    // A stale/mismatched Content-Length is a common cause of broken 0:00 files.
    res.status(200);
    res.setHeader("Content-Type", contentType);
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${fileName.replace(/"/g, "")}.mp4"`
    );
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Accept-Ranges", "none");

    let totalBytes = 0;

    // Send the validated first bytes.
    totalBytes += firstBytes.byteLength;

    if (totalBytes > MAX_FILE_BYTES) {
      res.destroy();
      return;
    }

    if (!res.write(Buffer.from(firstBytes))) {
      await new Promise(resolve => res.once("drain", resolve));
    }

    // Continue from the same reader. Nothing was lost.
    while (true) {
      const { value, done } = await upstreamReader.read();

      if (done) break;

      if (!value || !value.byteLength) continue;

      totalBytes += value.byteLength;

      if (totalBytes > MAX_FILE_BYTES) {
        try { await upstreamReader.cancel(); } catch {}
        if (!res.destroyed) res.destroy();
        return;
      }

      const chunk = Buffer.from(value);

      if (!res.write(chunk)) {
        await new Promise(resolve => res.once("drain", resolve));
      }
    }

    if (totalBytes <= 0) {
      if (!res.destroyed) res.destroy();
      return;
    }

    if (!res.destroyed) res.end();
  } catch (error) {
    try {
      if (upstreamReader) await upstreamReader.cancel();
    } catch {}

    if (res.headersSent) {
      if (!res.destroyed) res.destroy();
      return;
    }

    const message =
      error?.name === "TimeoutError"
        ? "The video server took too long to respond. Please try again."
        : (error.message || "The video could not be downloaded.");

    return res.status(502).json({ error: message });
  }
});

// ---------------- SPA FALLBACK ----------------

app.get("/{*splat}", (req, res, next) => {
  if (req.path.startsWith("/api/")) return next();

  res.sendFile(INDEX_FILE, err => {
    if (err && !res.headersSent) {
      res.status(404).send(
        "index.html could not be found. Put index.html in the project root or public/index.html."
      );
    }
  });
});

// ---------------- ERROR HANDLER ----------------

app.use((err, _req, res, _next) => {
  console.error("Unhandled error:", err.message);

  if (!res.headersSent) {
    res.status(500).json({
      error: "A server error occurred. Please try again later."
    });
  }
});

// ---------------- START ----------------

app.listen(PORT, () => {
  console.log(`EM Fast 4K running on port ${PORT}`);
  console.log(`Maximum file size: ${MAX_FILE_BYTES} bytes (5 GB)`);
  console.log(
    `SaveAPI configured: ${SAVEAPI_KEY ? "YES" : "NO"}`
  );
});
