// EM Fast 4K — Render Web Service
// API keys belong in Render Environment Variables, never in public HTML.
// Architecture: detect direct video first; use SaveAPI only when needed.
// The browser downloads the final direct URL, so Render does NOT proxy the video bytes.

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

app.disable("x-powered-by");
app.set("trust proxy", 1);

app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://fonts.googleapis.com"
        ],
        fontSrc: [
          "'self'",
          "https://fonts.gstatic.com",
          "data:"
        ],
        imgSrc: [
          "'self'",
          "data:"
        ],
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

const INDEX_FILE = fs.existsSync(PUBLIC_INDEX)
  ? PUBLIC_INDEX
  : ROOT_INDEX;

app.use(
  express.static(
    fs.existsSync(PUBLIC_DIR) ? PUBLIC_DIR : __dirname,
    { extensions: ["html"] }
  )
);

// ----------------------------------------------------
// RATE LIMIT
// ----------------------------------------------------

const prepareLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 120,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: {
    error: "অনেক বেশি অনুরোধ হয়েছে। কিছুক্ষণ পরে আবার চেষ্টা করুন।"
  }
});

app.use("/api/prepare", prepareLimiter);

// ----------------------------------------------------
// SECURITY HELPERS
// ----------------------------------------------------

function isPrivateIPv4(ip) {
  const parts = ip.split(".").map(Number);

  if (
    parts.length !== 4 ||
    parts.some(
      n => !Number.isInteger(n) || n < 0 || n > 255
    )
  ) {
    return true;
  }

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
    throw new Error("সঠিক ভিডিও লিংক দিন।");
  }

  if (
    !["http:", "https:"].includes(u.protocol) ||
    u.username ||
    u.password
  ) {
    throw new Error(
      "শুধু সাধারণ HTTP/HTTPS লিংক ব্যবহার করুন।"
    );
  }

  const host = u.hostname
    .toLowerCase()
    .replace(/^\[|\]$/g, "");

  if (
    !host ||
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local")
  ) {
    throw new Error("এই ঠিকানাটি গ্রহণ করা যাচ্ছে না।");
  }

  const ipType = net.isIP(host);

  if (ipType === 4 && isPrivateIPv4(host)) {
    throw new Error("এই ঠিকানাটি গ্রহণ করা যাচ্ছে না।");
  }

  if (ipType === 6 && isPrivateIPv6(host)) {
    throw new Error("এই ঠিকানাটি গ্রহণ করা যাচ্ছে না।");
  }

  if (!ipType) {
    let records;

    try {
      records = await dns.lookup(host, {
        all: true,
        verbatim: true
      });
    } catch {
      throw new Error(
        "এই সাইটের ঠিকানা খুঁজে পাওয়া যায়নি।"
      );
    }

    if (
      !records.length ||
      records.some(r =>
        r.family === 4
          ? isPrivateIPv4(r.address)
          : isPrivateIPv6(r.address)
      )
    ) {
      throw new Error(
        "এই সাইটের ঠিকানা নিরাপদ নয়।"
      );
    }
  }

  return u;
}

// ----------------------------------------------------
// SAFE REDIRECT FETCH
// ----------------------------------------------------

async function fetchWithSafeRedirects(
  inputUrl,
  options = {},
  maxRedirects = MAX_REDIRECTS
) {
  let current = inputUrl;

  for (let i = 0; i <= maxRedirects; i++) {
    await assertPublicHttpUrl(current);

    const response = await fetch(current, {
      ...options,
      redirect: "manual",
      signal:
        options.signal ||
        AbortSignal.timeout(20000),
      headers: {
        "user-agent": "EMFast4K/1.1",
        ...(options.headers || {})
      }
    });

    if (
      [301, 302, 303, 307, 308].includes(
        response.status
      )
    ) {
      const location =
        response.headers.get("location");

      await response.body?.cancel().catch(() => {});

      if (
        !location ||
        i === maxRedirects
      ) {
        throw new Error(
          "সাইটের রিডাইরেক্ট সম্পন্ন করা যায়নি।"
        );
      }

      current = new URL(
        location,
        current
      ).toString();

      continue;
    }

    return {
      response,
      finalUrl: current
    };
  }

  throw new Error(
    "অনেকগুলো রিডাইরেক্ট হয়েছে।"
  );
}

// ----------------------------------------------------
// VIDEO DETECTION
// ----------------------------------------------------

const VIDEO_EXT =
  /\.(mp4|m4v|mov|webm|mkv|avi|mpeg|mpg|3gp|ogv)(?:$|[?#])/i;

function looksLikeVideo(response, url) {
  const type = (
    response.headers.get("content-type") || ""
  ).toLowerCase();

  let pathname = "";

  try {
    pathname = new URL(url).pathname;
  } catch {}

  return (
    type.startsWith("video/") ||
    (
      type === "application/octet-stream" &&
      VIDEO_EXT.test(pathname)
    ) ||
    VIDEO_EXT.test(pathname)
  );
}

function parseTotalSize(response) {
  const length = Number(
    response.headers.get("content-length")
  );

  if (
    Number.isFinite(length) &&
    length >= 0
  ) {
    return length;
  }

  const range =
    response.headers.get("content-range") || "";

  const match =
    range.match(/\/([0-9]+)$/);

  return match
    ? Number(match[1])
    : null;
}

async function probeDirectVideo(url) {
  // First try HEAD
  try {
    const {
      response,
      finalUrl
    } = await fetchWithSafeRedirects(
      url,
      { method: "HEAD" }
    );

    const direct =
      response.ok &&
      looksLikeVideo(
        response,
        finalUrl
      );

    const size =
      parseTotalSize(response);

    await response.body
      ?.cancel()
      .catch(() => {});

    if (direct) {
      return {
        direct: true,
        url: finalUrl,
        type:
          response.headers.get(
            "content-type"
          ) || "video/mp4",
        size
      };
    }
  } catch {}

  // Then try a tiny ranged GET
  try {
    const {
      response,
      finalUrl
    } = await fetchWithSafeRedirects(
      url,
      {
        method: "GET",
        headers: {
          Range: "bytes=0-0"
        }
      }
    );

    const direct =
      (
        response.ok ||
        response.status === 206
      ) &&
      looksLikeVideo(
        response,
        finalUrl
      );

    const size =
      parseTotalSize(response);

    const type =
      response.headers.get(
        "content-type"
      ) || "video/mp4";

    await response.body
      ?.cancel()
      .catch(() => {});

    if (direct) {
      return {
        direct: true,
        url: finalUrl,
        type,
        size
      };
    }
  } catch {}

  return {
    direct: false
  };
}

// ----------------------------------------------------
// FILE NAME
// ----------------------------------------------------

function cleanFileName(value) {
  const cleaned = String(
    value || "EM-Fast-4K-Video"
  )
    .replace(
      /[<>:"/\\|?*\u0000-\u001F]/g,
      "_"
    )
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 120);

  return (
    cleaned ||
    "EM-Fast-4K-Video"
  );
}

function titleFromUrl(value) {
  try {
    const u = new URL(value);

    const last = decodeURIComponent(
      u.pathname
        .split("/")
        .filter(Boolean)
        .pop() || ""
    );

    return cleanFileName(
      last.replace(
        /\.[a-z0-9]{2,5}$/i,
        ""
      ) || u.hostname
    );
  } catch {
    return "EM-Fast-4K-Video";
  }
}

function tooLarge(size) {
  return (
    Number.isFinite(size) &&
    size > MAX_FILE_BYTES
  );
}

// ----------------------------------------------------
// HEALTH CHECK
// ----------------------------------------------------

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    service: "EM Fast 4K",
    saveApiConfigured:
      Boolean(SAVEAPI_KEY),
    maxFileBytes:
      MAX_FILE_BYTES,
    downloadMode:
      "browser-direct"
  });
});

// ----------------------------------------------------
// PREPARE DOWNLOAD
// ----------------------------------------------------

app.post("/api/prepare", async (req, res) => {
  const inputUrl =
    String(
      req.body?.url || ""
    ).trim();

  if (
    !inputUrl ||
    inputUrl.length > 3000
  ) {
    return res.status(400).json({
      error:
        "একটি সঠিক ভিডিও লিংক পেস্ট করুন।"
    });
  }

  try {
    await assertPublicHttpUrl(
      inputUrl
    );

    // 1) Try direct video first.
    // No SaveAPI call if the link is already a video.
    const direct =
      await probeDirectVideo(
        inputUrl
      );

    if (direct.direct) {
      if (tooLarge(direct.size)) {
        return res.status(413).json({
          error:
            "Maximum file size is 5 GB."
        });
      }

      return res.json({
        ok: true,
        directUrl: `/api/download?url=${encodeURIComponent(direct.url)}&name=${encodeURIComponent(titleFromUrl(direct.url))}`,
        title:
          titleFromUrl(
            direct.url
          ),
        method: "direct",
        size: direct.size
      });
    }

    // 2) Only use SaveAPI if direct detection failed.
    if (!SAVEAPI_KEY) {
      return res.status(503).json({
        error:
          "This link is not a direct video file. Add SAVEAPI_KEY in Render → Environment Variables."
      });
    }

    const apiUrl =
      `https://api.saveapi.org/v1/download?url=${encodeURIComponent(inputUrl)}`;

    const apiResponse =
      await fetch(apiUrl, {
        method: "GET",
        headers: {
          "Authorization":
            `Bearer ${SAVEAPI_KEY}`,
          "Accept":
            "application/json"
        },
        signal:
          AbortSignal.timeout(30000)
      });

    let data;

    try {
      data =
        await apiResponse.json();
    } catch {
      data = null;
    }

    if (
      !apiResponse.ok ||
      data?.success === false
    ) {
      const code =
        data?.error?.code || "";

      const statusMessage =
        apiResponse.status === 429
          ? "SaveAPI rate limit reached. Please try again later."
          : apiResponse.status === 401
            ? "SaveAPI key is invalid. Check Render → Environment Variables."
            : code ===
              "UNSUPPORTED_PLATFORM"
              ? "This video site is not supported by SaveAPI."
              : (
                data?.error?.message ||
                `SaveAPI request failed (HTTP ${apiResponse.status}).`
              );

      return res.status(
        apiResponse.status === 429
          ? 429
          : 502
      ).json({
        error: statusMessage
      });
    }

    const media =
      Array.isArray(data?.medias)
        ? data.medias.find(
            item =>
              item &&
              item.type !== "audio" &&
              typeof item.url ===
                "string" &&
              /^https?:\/\//i.test(
                item.url
              )
          )
        : null;

    if (!media) {
      return res.status(422).json({
        error:
          "SaveAPI could not find a direct video file for this link."
      });
    }

    await assertPublicHttpUrl(
      media.url
    );

    // Prefer API-provided size.
    let size = Number(
      media.size ||
      media.filesize ||
      media.file_size ||
      media.content_length
    );

    if (!Number.isFinite(size)) {
      size = null;
    }

    if (tooLarge(size)) {
      return res.status(413).json({
        error:
          "Maximum file size is 5 GB."
      });
    }

    const title =
      cleanFileName(
        data?.meta?.title ||
        data?.title ||
        titleFromUrl(
          inputUrl
        )
      );

    return res.json({
      ok: true,
      directUrl: `/api/download?url=${encodeURIComponent(media.url)}&name=${encodeURIComponent(title)}`,
      title,
      method: "saveapi",
      size
    });

  } catch (error) {
    const message =
      error?.name ===
      "TimeoutError"
        ? "The site took too long to respond. Please try again."
        : (
          error.message ||
          "The link could not be processed."
        );

    return res.status(400).json({
      error: message
    });
  }
});

// ----------------------------------------------------
// DOWNLOAD PROXY
// ----------------------------------------------------
// The browser must receive the video from the same origin with
// Content-Disposition: attachment. This prevents mobile browsers
// from opening a 0:00 video player instead of downloading the file.

app.get("/api/download", async (req, res) => {
  const inputUrl = String(req.query?.url || "").trim();
  const requestedName = cleanFileName(String(req.query?.name || "").trim());

  if (!inputUrl || inputUrl.length > 12000) {
    return res.status(400).json({
      error: "ডাউনলোড লিংকটি সঠিক নয়।"
    });
  }

  try {
    await assertPublicHttpUrl(inputUrl);

    const { response, finalUrl } = await fetchWithSafeRedirects(
      inputUrl,
      {
        method: "GET",
        headers: {
          "accept": "video/*,application/octet-stream;q=0.9,*/*;q=0.5",
          "accept-encoding": "identity"
        },
        signal: AbortSignal.timeout(30000)
      }
    );

    if (!response.ok || !response.body) {
      await response.body?.cancel().catch(() => {});
      return res.status(502).json({
        error: `ভিডিও সার্ভার ডাউনলোড দিতে পারেনি (HTTP ${response.status}).`
      });
    }

    const contentType = (
      response.headers.get("content-type") || ""
    ).toLowerCase();
    const contentLength = parseTotalSize(response);

    // Never turn an HTML/error response into a fake .mp4 file.
    if (
      contentType.includes("text/html") ||
      contentType.includes("application/json")
    ) {
      await response.body.cancel().catch(() => {});
      return res.status(502).json({
        error: "আসল ভিডিও ফাইলটি পাওয়া যায়নি।"
      });
    }

    if (tooLarge(contentLength)) {
      await response.body.cancel().catch(() => {});
      return res.status(413).json({
        error: "Maximum file size is 5 GB."
      });
    }

    const fileName =
      requestedName || titleFromUrl(finalUrl) || "EM-Fast-4K-Video";

    res.status(200);
    res.setHeader(
      "Content-Type",
      contentType.startsWith("video/")
        ? contentType
        : "application/octet-stream"
    );
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${fileName.replace(/"/g, "")}.mp4"`
    );
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");

    if (Number.isFinite(contentLength)) {
      res.setHeader("Content-Length", String(contentLength));
    }

    let totalBytes = 0;

    try {
      for await (const chunk of response.body) {
        totalBytes += chunk.byteLength;

        if (totalBytes > MAX_FILE_BYTES) {
          res.destroy();
          return;
        }

        if (!res.write(chunk)) {
          await new Promise(resolve => res.once("drain", resolve));
        }
      }

      if (totalBytes === 0) {
        if (!res.headersSent) {
          return res.status(502).json({
            error: "ভিডিও ফাইলটি খালি বা 0 byte।"
          });
        }
        res.destroy();
        return;
      }

      res.end();
    } catch (streamError) {
      if (!res.destroyed) {
        res.destroy(streamError);
      }
    }
  } catch (error) {
    if (res.headersSent) {
      return res.destroy(error);
    }

    const message =
      error?.name === "TimeoutError"
        ? "ভিডিও সার্ভার উত্তর দিতে বেশি সময় নিয়েছে। আবার চেষ্টা করুন।"
        : (error.message || "ভিডিও ডাউনলোড করা যায়নি।");

    return res.status(502).json({ error: message });
  }
});

// ----------------------------------------------------
// EXPRESS 5 SPA FALLBACK
// ----------------------------------------------------

app.get(
  "/{*splat}",
  (req, res, next) => {
    if (
      req.path.startsWith("/api/")
    ) {
      return next();
    }

    res.sendFile(
      INDEX_FILE,
      err => {
        if (
          err &&
          !res.headersSent
        ) {
          res
            .status(404)
            .send(
              "index.html পাওয়া যায়নি। GitHub-এ index.html মূল ফোল্ডারে অথবা public/index.html-এ রাখুন।"
            );
        }
      }
    );
  }
);

// ----------------------------------------------------
// ERROR HANDLER
// ----------------------------------------------------

app.use(
  (err, _req, res, _next) => {
    console.error(
      "Unhandled error:",
      err.message
    );

    if (!res.headersSent) {
      res.status(500).json({
        error:
          "সার্ভারে সমস্যা হয়েছে। কিছুক্ষণ পরে আবার চেষ্টা করুন।"
      });
    }
  }
);

// ----------------------------------------------------
// START SERVER
// ----------------------------------------------------

app.listen(PORT, () => {
  console.log(
    `EM Fast 4K running on port ${PORT}`
  );

  console.log(
    `Maximum file size: ${MAX_FILE_BYTES} bytes (5 GB)`
  );

  if (!SAVEAPI_KEY) {
    console.warn(
      "SAVEAPI_KEY is not set. Direct video URLs can still work; social links need SaveAPI."
    );
  }
});