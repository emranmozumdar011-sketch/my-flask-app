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

  // Highest available quality first, but never above 5 GB.
  const usable = formats
    .map(f => ({ format: f, height: numberFromQuality(f.quality), size: getFormatSize(f) }))
    .filter(x => !tooLarge(x.size))
    .sort((a, b) => b.height - a.height || ((b.size || 0) - (a.size || 0)));

  if (!usable.length) {
    throw new Error("All available YouTube video qualities are larger than the 5 GB limit.");
  }

  // The current SaveAPI YouTube API supports up to 1080p.
  const chosen = usable[0];
  const quality = chosen.format.quality;

  const made = await callSaveApi("/youtube/create", {
    url: inputUrl,
    quality
  }, 60000);

  if (!made?.url || typeof made.url !== "string") {
    throw new Error("SaveAPI did not return a valid YouTube download stream.");
  }

  const size = Number(made.file_size);
  const finalSize = Number.isFinite(size) && size >= 0 ? size : chosen.size;

  if (tooLarge(finalSize)) {
    return { tooLarge: true };
  }

  return {
    url: made.url,
    title: cleanFileName(made.filename || made.title || info.title || titleFromUrl(inputUrl)),
    size: Number.isFinite(finalSize) ? finalSize : null,
    quality
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

      // IMPORTANT: YouTube's SaveAPI URL is a signed stream with no Range/Content-Length.
      // Do not probe it with Range here. Render streams it to the browser in /api/download.
      return res.json({
        ok: true,
        directUrl: `/api/download?url=${encodeURIComponent(yt.url)}&name=${encodeURIComponent(yt.title)}`,
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
// DOWNLOAD DIAGNOSTICS
// ----------------------------------------------------

function bytesToHex(bytes, max = 24) {
  return Buffer.from(bytes.subarray(0, max)).toString("hex");
}

function bytesToAscii(bytes, max = 80) {
  return Buffer.from(bytes.subarray(0, max))
    .toString("utf8")
    .replace(/[^\x20-\x7E]/g, ".");
}

function diagnoseFirstChunk(bytes, contentType) {
  const lowerType = String(contentType || "").toLowerCase();
  const text = bytesToAscii(bytes).toLowerCase();
  const looksText =
    lowerType.includes("text/html") ||
    lowerType.includes("application/json") ||
    text.startsWith("<!doctype") ||
    text.startsWith("<html") ||
    text.startsWith("{") ||
    text.startsWith("[");
  const looksImage =
    lowerType.startsWith("image/") ||
    (bytes.length >= 4 && (
      (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) ||
      (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) ||
      (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46)
    ));
  const hasMp4 =
    bytes.length >= 8 &&
    Buffer.from(bytes).subarray(4, Math.min(bytes.length, 64)).includes(Buffer.from("ftyp"));
  const hasWebm =
    bytes.length >= 4 &&
    bytes[0] === 0x1a && bytes[1] === 0x45 && bytes[2] === 0xdf && bytes[3] === 0xa3;
  return { looksText, looksImage, hasMp4, hasWebm };
}

// ----------------------------------------------------
// SECURE VIDEO STREAM / DOWNLOAD
// ----------------------------------------------------

app.get("/api/download", async (req, res) => {
  const inputUrl = String(req.query?.url || "").trim();
  const requestId = Math.random().toString(36).slice(2, 9);

  const host = (() => {
    try { return new URL(inputUrl).hostname; } catch { return "invalid"; }
  })();

  console.log(`[DOWNLOAD ${requestId}] START url-host=${host}`);

  res.on("finish", () => {
    console.log(`[DOWNLOAD ${requestId}] RESPONSE FINISH status=${res.statusCode}`);
  });
  res.on("close", () => {
    console.log(`[DOWNLOAD ${requestId}] RESPONSE CLOSE headersSent=${res.headersSent} writableEnded=${res.writableEnded}`);
  });

  if (!inputUrl || inputUrl.length > 16000) {
    console.error(`[DOWNLOAD ${requestId}] ERROR invalid download URL`);
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
      signal: AbortSignal.timeout(120000)
    });

    const contentType = response.headers.get("content-type") || "";
    const contentLength = parseTotalSize(response);

    console.log(
      `[DOWNLOAD ${requestId}] UPSTREAM status=${response.status} ` +
      `type=${contentType || "none"} length=${Number.isFinite(contentLength) ? contentLength : "unknown"}`
    );

    if (!response.ok || !response.body) {
      await response.body?.cancel().catch(() => {});
      console.error(`[DOWNLOAD ${requestId}] ERROR upstream HTTP=${response.status}`);
      return res.status(502).json({
        error: `The video server could not provide the download (HTTP ${response.status}).`
      });
    }

    if (tooLarge(contentLength)) {
      await response.body.cancel().catch(() => {});
      return res.status(413).json({ error: "Maximum file size is 5 GB." });
    }

    // Read one real chunk first. Nothing is sent to the phone until
    // this check passes, so images/error pages cannot become fake MP4s.
    const reader = response.body.getReader();
    const first = await reader.read();

    if (first.done || !first.value || first.value.byteLength === 0) {
      await reader.cancel().catch(() => {});
      console.error(`[DOWNLOAD ${requestId}] ZERO_BYTES_STREAM`);
      return res.status(502).json({
        error: "Download failed: the source returned 0 bytes. No video data was received."
      });
    }

    const firstBytes = first.value;
    const diagnosis = diagnoseFirstChunk(firstBytes, contentType);

    console.log(
      `[DOWNLOAD ${requestId}] FIRST_CHUNK bytes=${firstBytes.byteLength} ` +
      `hex=${bytesToHex(firstBytes)} mp4=${diagnosis.hasMp4} webm=${diagnosis.hasWebm} ` +
      `image=${diagnosis.looksImage} text=${diagnosis.looksText}`
    );

    if (contentLength === 0 && firstBytes.byteLength > 0) {
      console.log(
        `[DOWNLOAD ${requestId}] NOTE upstream reported Content-Length=0 ` +
        `but sent real bytes; ignoring the incorrect zero length.`
      );
    }

    if (diagnosis.looksImage) {
      await reader.cancel().catch(() => {});
      console.error(`[DOWNLOAD ${requestId}] WRONG_FILE image-response`);
      return res.status(502).json({
        error: "Download failed: the source returned an image instead of a video."
      });
    }

    if (diagnosis.looksText) {
      await reader.cancel().catch(() => {});
      console.error(`[DOWNLOAD ${requestId}] WRONG_FILE text-error-response`);
      return res.status(502).json({
        error: "Download failed: the source returned an error page instead of video data."
      });
    }

    const requestedName = cleanFileName(String(req.query?.name || "").trim());
    const fallbackName = titleFromUrl(finalUrl);
    const fileName = cleanFileName(requestedName || fallbackName) || "EM-Fast-4K-Video";

    // IMPORTANT: Node rejects some Unicode characters in HTTP header values.
    // Use ASCII only in Content-Disposition so a valid video cannot become 0 B.
    const headerFileName = fileName
      .normalize("NFKD")
      .replace(/[^A-Za-z0-9._ -]/g, "_")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 100) || "EM-Fast-4K-Video";

    res.status(200);
    res.setHeader("Content-Type", contentType || "video/mp4");
    res.setHeader("Content-Disposition", `attachment; filename="${headerFileName}.mp4"`);
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");
    if (Number.isFinite(contentLength) && contentLength > 0) {
      res.setHeader("Content-Length", String(contentLength));
    }

    let totalBytes = 0;

    try {
      totalBytes = firstBytes.byteLength;
      if (!res.write(firstBytes)) {
        await new Promise(resolve => res.once("drain", resolve));
      }

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!value || value.byteLength === 0) continue;

        totalBytes += value.byteLength;

        if (totalBytes > MAX_FILE_BYTES) {
          await reader.cancel().catch(() => {});
          console.error(`[DOWNLOAD ${requestId}] ERROR exceeded 5GB bytes=${totalBytes}`);
          res.destroy();
          return;
        }

        if (!res.write(value)) {
          await new Promise(resolve => res.once("drain", resolve));
        }
      }

      if (totalBytes <= 0) {
        console.error(`[DOWNLOAD ${requestId}] ZERO_BYTES_AFTER_STREAM`);
        res.destroy();
        return;
      }

      console.log(`[DOWNLOAD ${requestId}] SUCCESS total-bytes=${totalBytes}`);
      res.end();
    } catch (streamError) {
      console.error(
        `[DOWNLOAD ${requestId}] STREAM_ERROR name=${streamError?.name || "Error"} ` +
        `message=${streamError?.message || streamError} bytes=${totalBytes}`
      );
      if (!res.destroyed) res.destroy(streamError);
    }
  } catch (error) {
    console.error(
      `[DOWNLOAD ${requestId}] REQUEST_ERROR name=${error?.name || "Error"} ` +
      `message=${error?.message || error}`
    );
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
