// EM Fast 4K — Render Web Service
// API keys belong in Render Environment Variables, never in public HTML.
// Direct video first. SaveAPI is used only when direct detection fails.
// YouTube uses SaveAPI's special /youtube/info + /youtube/create flow.

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

app.use(
  helmet({
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
  })
);

app.use(express.json({ limit: "8kb" }));

const PUBLIC_DIR = path.join(__dirname, "public");
const ROOT_INDEX = path.join(__dirname, "index.html");
const PUBLIC_INDEX = path.join(PUBLIC_DIR, "index.html");
const INDEX_FILE = fs.existsSync(PUBLIC_INDEX) ? PUBLIC_INDEX : ROOT_INDEX;

app.use(express.static(fs.existsSync(PUBLIC_DIR) ? PUBLIC_DIR : __dirname, { extensions: ["html"] }));

const prepareLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 120,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many requests. Please try again later." }
});

app.use("/api/prepare", prepareLimiter);

// ----------------------------------------------------
// SECURITY HELPERS
// ----------------------------------------------------

function isPrivateIPv4(ip) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b] = parts;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    a >= 224 ||
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
  const value = ip.toLowerCase().split("%")[0];
  return (
    value === "::" ||
    value === "::1" ||
    value.startsWith("fc") ||
    value.startsWith("fd") ||
    value.startsWith("fe80:") ||
    value.startsWith("ff") ||
    value.startsWith("::ffff:127.") ||
    value.startsWith("::ffff:10.") ||
    value.startsWith("::ffff:192.168.")
  );
}

async function assertPublicHttpUrl(input) {
  let u;
  try {
    u = new URL(input);
  } catch {
    throw new Error("Please provide a valid video link.");
  }

  if (!["http:", "https:"].includes(u.protocol) || u.username || u.password) {
    throw new Error("Only normal HTTP/HTTPS links are supported.");
  }

  const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, "");

  if (!host || host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) {
    throw new Error("This address cannot be used.");
  }

  const ipType = net.isIP(host);
  if (ipType === 4 && isPrivateIPv4(host)) throw new Error("This address cannot be used.");
  if (ipType === 6 && isPrivateIPv6(host)) throw new Error("This address cannot be used.");

  if (!ipType) {
    let records;
    try {
      records = await dns.lookup(host, { all: true, verbatim: true });
    } catch {
      throw new Error("The site address could not be found.");
    }
    if (!records.length || records.some(r => r.family === 4 ? isPrivateIPv4(r.address) : isPrivateIPv6(r.address))) {
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
      signal: options.signal || AbortSignal.timeout(20000),
      headers: {
        "user-agent": "EMFast4K/1.2",
        ...(options.headers || {})
      }
    });

    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      await response.body?.cancel().catch(() => {});
      if (!location || i === maxRedirects) throw new Error("The site redirect could not be completed.");
      current = new URL(location, current).toString();
      continue;
    }

    return { response, finalUrl: current };
  }

  throw new Error("Too many redirects.");
}

// ----------------------------------------------------
// VIDEO DETECTION
// ----------------------------------------------------

const VIDEO_EXT = /\.(mp4|m4v|mov|webm|mkv|avi|mpeg|mpg|3gp|ogv)(?:$|[?#])/i;

function looksLikeVideo(response, url) {
  const type = (response.headers.get("content-type") || "").toLowerCase();
  let pathname = "";
  try { pathname = new URL(url).pathname; } catch {}

  return (
    type.startsWith("video/") ||
    (type === "application/octet-stream" && VIDEO_EXT.test(pathname)) ||
    VIDEO_EXT.test(pathname)
  );
}

function parseTotalSize(response) {
  const length = Number(response.headers.get("content-length"));
  if (Number.isFinite(length) && length >= 0) return length;

  const range = response.headers.get("content-range") || "";
  const match = range.match(/\/([0-9]+)$/);
  return match ? Number(match[1]) : null;
}

async function probeDirectVideo(url) {
  try {
    const { response, finalUrl } = await fetchWithSafeRedirects(url, { method: "HEAD" });
    const direct = response.ok && looksLikeVideo(response, finalUrl);
    const size = parseTotalSize(response);
    await response.body?.cancel().catch(() => {});
    if (direct) {
      return {
        direct: true,
        url: finalUrl,
        type: response.headers.get("content-type") || "video/mp4",
        size
      };
    }
  } catch {}

  try {
    const { response, finalUrl } = await fetchWithSafeRedirects(url, {
      method: "GET",
      headers: { Range: "bytes=0-0" }
    });
    const direct = (response.ok || response.status === 206) && looksLikeVideo(response, finalUrl);
    const size = parseTotalSize(response);
    const type = response.headers.get("content-type") || "video/mp4";
    await response.body?.cancel().catch(() => {});
    if (direct) return { direct: true, url: finalUrl, type, size };
  } catch {}

  return { direct: false };
}

// ----------------------------------------------------
// FILE NAME / SIZE
// ----------------------------------------------------

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
    const last = decodeURIComponent(u.pathname.split("/").filter(Boolean).pop() || "");
    return cleanFileName(last.replace(/\.[a-z0-9]{2,5}$/i, "") || u.hostname);
  } catch {
    return "EM-Fast-4K-Video";
  }
}

function tooLarge(size) {
  return Number.isFinite(size) && size > MAX_FILE_BYTES;
}

function isYouTubeUrl(input) {
  try {
    const host = new URL(input).hostname.toLowerCase().replace(/^www\./, "");
    return host === "youtube.com" || host.endsWith(".youtube.com") || host === "youtu.be";
  } catch {
    return false;
  }
}

function numberFromQuality(value) {
  const match = String(value || "").match(/(\d{3,4})p/i);
  return match ? Number(match[1]) : 0;
}

function getFormatSize(format) {
  const raw = format?.file_size ?? format?.filesize ?? format?.size ?? format?.size_mb;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0) return null;
  // SaveAPI formats normally use bytes for file_size/size and MB for size_mb.
  if (format?.size_mb != null && format?.file_size == null && format?.filesize == null && format?.size == null) {
    return n * 1024 * 1024;
  }
  return n;
}

function saveApiErrorMessage(apiResponse, data) {
  const code = data?.error?.code || "";
  if (apiResponse.status === 429 || code === "RATE_LIMITED") return "SaveAPI rate limit reached. Please try again later.";
  if (apiResponse.status === 401 || code === "INVALID_API_KEY" || code === "MISSING_API_KEY") return "SaveAPI key is invalid. Check Render → Environment Variables.";
  if (code === "QUOTA_EXCEEDED") return "SaveAPI credit balance is empty. Please add credits and try again.";
  if (code === "PRIVATE_CONTENT") return "This video is private and cannot be downloaded.";
  if (code === "MEDIA_NOT_FOUND") return "The video was deleted, restricted, or has no downloadable media.";
  if (code === "UNSUPPORTED_PLATFORM") return "This video site is not supported by SaveAPI.";
  if (code === "INVALID_FORMAT") return "The requested YouTube quality is not available.";
  if (code === "LINK_EXPIRED") return "The download link expired. Please try again.";
  if (code === "UPSTREAM_TIMEOUT" || code === "UPSTREAM_ERROR") return "The video site did not respond. Please try again.";
  return data?.error?.message || `SaveAPI request failed (HTTP ${apiResponse.status}).`;
}

async function callSaveApi(pathname, params, timeoutMs = 30000) {
  const url = new URL(`${SAVEAPI_BASE}${pathname}`);
  for (const [key, value] of Object.entries(params || {})) url.searchParams.set(key, String(value));

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

// ----------------------------------------------------
// YOUTUBE — SaveAPI special two-step flow
// ----------------------------------------------------

async function prepareYouTube(inputUrl) {
  const info = await callSaveApi("/youtube/info", { url: inputUrl }, 30000);

  const formats = Array.isArray(info?.formats)
    ? info.formats.filter(f => numberFromQuality(f?.quality) > 0)
    : [];

  if (!formats.length) {
    throw new Error("SaveAPI did not return a downloadable YouTube video quality.");
  }

  // Pick the highest available quality that stays within the 5 GB limit.
  const usable = formats
    .map(f => ({ format: f, height: numberFromQuality(f.quality), size: getFormatSize(f) }))
    .filter(x => !tooLarge(x.size))
    .sort((a, b) => b.height - a.height || ((b.size || 0) - (a.size || 0)));

  if (!usable.length) {
    throw new Error("All available YouTube video qualities are larger than the 5 GB limit.");
  }

  const chosen = usable[0];
  const size = chosen.size;

  return {
    title: cleanFileName(info.title || titleFromUrl(inputUrl)),
    size: Number.isFinite(size) ? size : null,
    quality: chosen.format.quality
  };
}

// ----------------------------------------------------
// HEALTH CHECK
// ----------------------------------------------------

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    service: "EM Fast 4K",
    saveApiConfigured: Boolean(SAVEAPI_KEY),
    maxFileBytes: MAX_FILE_BYTES,
    downloadMode: "server-stream"
  });
});

// ----------------------------------------------------
// PREPARE DOWNLOAD
// ----------------------------------------------------

app.post("/api/prepare", async (req, res) => {
  const inputUrl = String(req.body?.url || "").trim();

  if (!inputUrl || inputUrl.length > 3000) {
    return res.status(400).json({ error: "Please provide a valid video link." });
  }

  try {
    await assertPublicHttpUrl(inputUrl);

    // 1) Direct file first — this avoids SaveAPI when the submitted URL is already a video file.
    const direct = await probeDirectVideo(inputUrl);

    if (direct.direct) {
      if (tooLarge(direct.size)) return res.status(413).json({ error: "Maximum file size is 5 GB." });

      if (direct.size == null) {
        try {
          const verified = await fetchWithSafeRedirects(direct.url, { method: "HEAD" });
          const verifiedSize = parseTotalSize(verified.response);
          await verified.response.body?.cancel().catch(() => {});
          if (tooLarge(verifiedSize)) return res.status(413).json({ error: "Maximum file size is 5 GB." });
          if (Number.isFinite(verifiedSize)) direct.size = verifiedSize;
        } catch {}
      }

      const title = cleanFileName(titleFromUrl(direct.url));
      return res.json({
        ok: true,
        directUrl: `/api/download?url=${encodeURIComponent(direct.url)}&name=${encodeURIComponent(title)}`,
        title,
        method: "direct",
        size: direct.size
      });
    }

    if (!SAVEAPI_KEY) {
      return res.status(503).json({
        error: "This link is not a direct video file. Add SAVEAPI_KEY in Render → Environment Variables."
      });
    }

    // 2) YouTube must use SaveAPI's dedicated two-step API.
    if (isYouTubeUrl(inputUrl)) {
      const yt = await prepareYouTube(inputUrl);

      if (yt.tooLarge) {
        return res.status(413).json({ error: "Maximum file size is 5 GB." });
      }

      // IMPORTANT: Do not create the signed YouTube URL here. SaveAPI signs the
      // stream to the requesting server/IP and the stream is one-pass. We create
      // it inside the actual download request and immediately stream it onward.
      return res.json({
        ok: true,
        directUrl: `/api/youtube-download?url=${encodeURIComponent(inputUrl)}&quality=${encodeURIComponent(yt.quality)}&name=${encodeURIComponent(yt.title)}`,
        title: yt.title,
        method: "saveapi-youtube",
        quality: yt.quality,
        size: yt.size
      });
    }

    // 3) Other supported platforms use the normal /v1/download endpoint.
    let data;
    try {
      data = await callSaveApi("/download", { url: inputUrl }, 30000);
    } catch (error) {
      const status = error.httpStatus === 429 ? 429 : 502;
      return res.status(status).json({ error: error.message });
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
        /mp4|video/i.test(String(item.ext || item.mime || item.content_type || ""))
      )
    );

    candidates.sort((a, b) => {
      const aq = Number(a?.height || a?.quality_height || 0);
      const bq = Number(b?.height || b?.quality_height || 0);
      if (aq !== bq) return bq - aq;
      const as = Number(a?.size_mb || a?.size || a?.filesize || a?.file_size || 0);
      const bs = Number(b?.size_mb || b?.size || b?.filesize || b?.file_size || 0);
      return bs - as;
    });

    const media = candidates[0] || null;
    if (!media) {
      return res.status(422).json({ error: "SaveAPI did not return a downloadable video for this link." });
    }

    await assertPublicHttpUrl(media.url);

    let size = Number(media.file_size ?? media.filesize ?? media.size ?? media.content_length);
    if (!Number.isFinite(size) && Number.isFinite(Number(media.size_mb))) size = Number(media.size_mb) * 1024 * 1024;
    if (!Number.isFinite(size)) size = null;

    if (tooLarge(size)) return res.status(413).json({ error: "Maximum file size is 5 GB." });

    // Normal social-media CDN links usually support a tiny Range request.
    // If a provider does not expose Range/Content-Length, do not reject a valid video URL solely for that reason.
    try {
      const check = await fetchWithSafeRedirects(media.url, {
        method: "GET",
        headers: {
          Range: "bytes=0-0",
          Accept: "video/*,application/octet-stream;q=0.9,*/*;q=0.5",
          "accept-encoding": "identity"
        },
        signal: AbortSignal.timeout(15000)
      });

      const checkType = (check.response.headers.get("content-type") || "").toLowerCase();
      const checkSize = parseTotalSize(check.response);
      const hasVideoType =
        checkType.startsWith("video/") ||
        checkType === "application/octet-stream" ||
        VIDEO_EXT.test(check.finalUrl);

      await check.response.body?.cancel().catch(() => {});

      if (!check.response.ok && check.response.status !== 206) {
        return res.status(502).json({ error: "The video download server did not return the file. Please try again." });
      }

      if (!hasVideoType && !media.type?.toLowerCase?.().includes("video")) {
        return res.status(502).json({ error: "The returned file is not a video. Please try again." });
      }

      if (size == null && Number.isFinite(checkSize)) size = checkSize;
      if (tooLarge(size)) return res.status(413).json({ error: "Maximum file size is 5 GB." });
    } catch {
      // Do not fail here just because the CDN blocks a HEAD/Range probe.
      // /api/download will make the real streaming request.
    }

    const title = cleanFileName(data?.meta?.title || data?.title || media?.title || titleFromUrl(inputUrl));

    return res.json({
      ok: true,
      directUrl: `/api/download?url=${encodeURIComponent(media.url)}&name=${encodeURIComponent(title)}`,
      title,
      method: "saveapi",
      size
    });
  } catch (error) {
    const message = error?.name === "TimeoutError"
      ? "The site took too long to respond. Please try again."
      : (error.message || "The link could not be processed.");

    return res.status(error.httpStatus === 429 ? 429 : 400).json({ error: message });
  }
});

// ----------------------------------------------------
// SECURE VIDEO STREAM / DOWNLOAD
// ----------------------------------------------------

function isLikelyVideoChunk(chunk) {
  if (!chunk || chunk.length === 0) return false;

  const sample = Buffer.from(chunk.slice(0, Math.min(chunk.length, 64)));
  const ascii = sample.toString("latin1").trimStart().toLowerCase();

  // Never let an API error page/JSON response become an .mp4 file.
  if (
    ascii.startsWith("<!doctype") ||
    ascii.startsWith("<html") ||
    ascii.startsWith("<?xml") ||
    ascii.startsWith("{") ||
    ascii.startsWith("[") ||
    ascii.startsWith("error")
  ) {
    return false;
  }

  // Common video/container signatures.
  if (sample.length >= 12 && sample.toString("ascii", 4, 8) === "ftyp") return true; // MP4/MOV
  if (sample.length >= 4 && sample[0] === 0x1a && sample[1] === 0x45 && sample[2] === 0xdf && sample[3] === 0xa3) return true; // WebM/Matroska
  if (sample.length >= 4 && sample.toString("ascii", 0, 4) === "RIFF") return true; // AVI/WebP family
  if (sample.length >= 4 && sample.toString("ascii", 0, 4) === "OggS") return true; // OGG/OGV
  if (sample.length >= 3 && sample[0] === 0x49 && sample[1] === 0x44 && sample[2] === 0x33) return true; // ID3 audio/video containers
  if (sample.length >= 1 && sample[0] === 0x47) return true; // MPEG-TS packet

  return false;
}

function extensionForContentType(contentType) {
  const type = String(contentType || "").split(";")[0].trim().toLowerCase();
  if (type === "video/webm") return ".webm";
  if (type === "video/quicktime") return ".mov";
  if (type === "video/x-matroska") return ".mkv";
  if (type === "video/ogg") return ".ogv";
  if (type === "video/mp4") return ".mp4";
  return ".mp4";
}

async function streamUpstreamToResponse(response, res, fileName, fallbackName, knownSize = null) {
  if (!response.ok || !response.body) {
    await response.body?.cancel().catch(() => {});
    return { ok: false, status: 502, error: `The video server could not provide the download (HTTP ${response.status}).` };
  }

  const upstreamSize = parseTotalSize(response);
  const effectiveSize = Number.isFinite(knownSize) ? knownSize : upstreamSize;

  if (tooLarge(effectiveSize)) {
    await response.body.cancel().catch(() => {});
    return { ok: false, status: 413, error: "Maximum file size is 5 GB." };
  }

  const rawType = response.headers.get("content-type") || "";
  const contentType = rawType.toLowerCase();

  // Read the first real bytes BEFORE sending any download headers.
  // This prevents HTML/JSON error pages from being saved as .mp4 files.
  const reader = response.body.getReader();
  let first;
  try {
    first = await reader.read();
  } catch {
    try { await reader.cancel(); } catch {}
    return { ok: false, status: 502, error: "The video stream could not be started. Please try again." };
  }

  if (first.done || !first.value || first.value.byteLength === 0) {
    try { await reader.cancel(); } catch {}
    return { ok: false, status: 502, error: "The video server returned an empty file. Please try again." };
  }

  const looksTextLike =
    contentType.startsWith("text/html") ||
    contentType.startsWith("application/json") ||
    contentType.startsWith("text/plain");

  if (looksTextLike) {
    try { await reader.cancel(); } catch {}
    return { ok: false, status: 502, error: "The video server returned an invalid media response. Please try again." };
  }

  const isVideoType =
    contentType.startsWith("video/") ||
    contentType === "application/octet-stream" ||
    contentType === "" ||
    contentType.includes("mp4") ||
    contentType.includes("quicktime") ||
    contentType.includes("matroska");

  if (!isVideoType || (contentType === "application/octet-stream" && !isLikelyVideoChunk(first.value))) {
    try { await reader.cancel(); } catch {}
    return { ok: false, status: 502, error: "The returned file is not a valid video. Please try again." };
  }

  const safeName = cleanFileName(fileName || fallbackName) || "EM-Fast-4K-Video";
  const extension = extensionForContentType(contentType);

  let finalName = safeName;
  if (!/\.(mp4|m4v|mov|webm|mkv|avi|mpeg|mpg|3gp|ogv)$/i.test(finalName)) {
    finalName += extension;
  }

  res.status(200);
  res.setHeader("Content-Type", contentType || "video/mp4");
  res.setHeader("Content-Disposition", `attachment; filename="${finalName.replace(/"/g, "")}"`);
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("X-Content-Type-Options", "nosniff");

  // YouTube's create endpoint intentionally has no Content-Length.
  // Only send Content-Length when the upstream/API gave us a trustworthy value.
  if (Number.isFinite(effectiveSize) && effectiveSize > 0) {
    res.setHeader("Content-Length", String(effectiveSize));
  }

  let totalBytes = 0;

  try {
    totalBytes += first.value.byteLength;
    if (totalBytes > MAX_FILE_BYTES) {
      res.destroy();
      return { ok: false, status: 413, error: "Maximum file size is 5 GB." };
    }

    if (!res.write(first.value)) await new Promise(resolve => res.once("drain", resolve));

    while (true) {
      const next = await reader.read();
      if (next.done) break;
      if (!next.value || next.value.byteLength === 0) continue;

      totalBytes += next.value.byteLength;
      if (totalBytes > MAX_FILE_BYTES) {
        res.destroy();
        return { ok: false, status: 413, error: "Maximum file size is 5 GB." };
      }

      if (!res.write(next.value)) await new Promise(resolve => res.once("drain", resolve));
    }

    // If the API supplied a size, verify that we actually received the whole file.
    // Never silently turn a truncated stream into a playable-looking 0:00 file.
    if (Number.isFinite(effectiveSize) && effectiveSize > 0 && totalBytes !== effectiveSize) {
      if (!res.destroyed) res.destroy();
      return { ok: false, status: 502, error: "The video download was incomplete. Please try again." };
    }

    res.end();
    return { ok: true, bytes: totalBytes };
  } catch {
    if (!res.destroyed) res.destroy();
    return { ok: false, status: 502, error: "The video download stream was interrupted. Please try again." };
  }
}

// ----------------------------------------------------
// YOUTUBE STREAM / DOWNLOAD
// ----------------------------------------------------

app.get("/api/youtube-download", async (req, res) => {
  const inputUrl = String(req.query?.url || "").trim();
  const quality = String(req.query?.quality || "").trim();
  const requestedName = cleanFileName(String(req.query?.name || "").trim());

  if (!inputUrl || inputUrl.length > 3000 || !isYouTubeUrl(inputUrl)) {
    return res.status(400).json({ error: "The YouTube link is not valid." });
  }

  if (!/^(144|240|360|480|720|1080)p$/i.test(quality)) {
    return res.status(400).json({ error: "The selected YouTube quality is not valid." });
  }

  try {
    await assertPublicHttpUrl(inputUrl);

    // Create and consume the signed URL in the SAME request. This avoids the
    // IP-binding/expiry problem caused by creating the URL during /api/prepare.
    const made = await callSaveApi("/youtube/create", {
      url: inputUrl,
      quality
    }, 60000);

    if (!made?.url || typeof made.url !== "string") {
      return res.status(502).json({ error: "SaveAPI did not return a valid YouTube download stream." });
    }

    const size = Number(made.file_size);
    const knownSize = Number.isFinite(size) && size >= 0 ? size : null;
    if (tooLarge(knownSize)) {
      return res.status(413).json({ error: "Maximum file size is 5 GB." });
    }

    await assertPublicHttpUrl(made.url);

    const { response, finalUrl } = await fetchWithSafeRedirects(made.url, {
      method: "GET",
      headers: {
        Accept: "video/mp4,video/*,application/octet-stream;q=0.9,*/*;q=0.5",
        "accept-encoding": "identity"
      },
      // The stream can be large; this timeout is only for the upstream request/stream.
      signal: AbortSignal.timeout(15 * 60 * 1000)
    });

    const fallbackName = cleanFileName(made.filename || made.title || requestedName || titleFromUrl(finalUrl));
    const result = await streamUpstreamToResponse(response, res, requestedName || fallbackName, fallbackName, knownSize);

    if (!result.ok && !res.headersSent) {
      return res.status(result.status || 502).json({ error: result.error });
    }
  } catch (error) {
    if (res.headersSent) return res.destroy(error);

    const message = error?.name === "TimeoutError"
      ? "The YouTube download took too long to start. Please try again."
      : (error.message || "The YouTube video could not be downloaded.");

    return res.status(error.httpStatus === 429 ? 429 : 502).json({ error: message });
  }
});

// ----------------------------------------------------
// SECURE VIDEO STREAM / DOWNLOAD
// ----------------------------------------------------

app.get("/api/download", async (req, res) => {
  const inputUrl = String(req.query?.url || "").trim();

  if (!inputUrl || inputUrl.length > 16000) {
    return res.status(400).json({ error: "The download link is not valid." });
  }

  try {
    await assertPublicHttpUrl(inputUrl);

    const { response, finalUrl } = await fetchWithSafeRedirects(inputUrl, {
      method: "GET",
      headers: {
        accept: "video/*,application/octet-stream;q=0.9,*/*;q=0.5",
        "accept-encoding": "identity"
      },
      signal: AbortSignal.timeout(15 * 60 * 1000)
    });

    const requestedName = cleanFileName(String(req.query?.name || "").trim());
    const fallbackName = titleFromUrl(finalUrl);
    const result = await streamUpstreamToResponse(response, res, requestedName, fallbackName, null);

    if (!result.ok && !res.headersSent) {
      return res.status(result.status || 502).json({ error: result.error });
    }
  } catch (error) {
    if (res.headersSent) return res.destroy(error);

    const message = error?.name === "TimeoutError"
      ? "The video server took too long to respond. Please try again."
      : (error.message || "The video could not be downloaded.");

    return res.status(502).json({ error: message });
  }
});
// ----------------------------------------------------
// EXPRESS 5 SPA FALLBACK
// ----------------------------------------------------

app.get("/{*splat}", (req, res, next) => {
  if (req.path.startsWith("/api/")) return next();
  res.sendFile(INDEX_FILE, err => {
    if (err && !res.headersSent) {
      res.status(404).send("index.html could not be found. Put index.html in the project root or public/index.html.");
    }
  });
});

// ----------------------------------------------------
// ERROR HANDLER
// ----------------------------------------------------

app.use((err, _req, res, _next) => {
  console.error("Unhandled error:", err.message);
  if (!res.headersSent) res.status(500).json({ error: "A server error occurred. Please try again later." });
});

// ----------------------------------------------------
// START SERVER
// ----------------------------------------------------

app.listen(PORT, () => {
  console.log(`EM Fast 4K running on port ${PORT}`);
  console.log(`Maximum file size: ${MAX_FILE_BYTES} bytes (5 GB)`);
  if (!SAVEAPI_KEY) console.warn("SAVEAPI_KEY is not set. Direct video URLs can still work; social links need SaveAPI.");
});
