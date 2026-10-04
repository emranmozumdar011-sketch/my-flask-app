// EM Fast 4K — Render Web Service
// Server file: Giveite.js

const express = require("express");
const helmet = require("helmet");
const { rateLimit } = require("express-rate-limit");
const dns = require("node:dns").promises;
const net = require("node:net");
const path = require("node:path");
const fs = require("node:fs");
const crypto = require("node:crypto");
const { Readable } = require("node:stream");

const app = express();

const PORT = process.env.PORT || 3000;
const SAVEAPI_KEY =
  process.env.SAVEAPI_KEY ||
  process.env.SAVEAPI_API_KEY ||
  "";

const TOKEN_TTL_MS = 10 * 60 * 1000;
const MAX_REDIRECTS = 5;

const prepared = new Map();

app.disable("x-powered-by");
app.set("trust proxy", 1);

app.use(
  helmet({
    crossOriginResourcePolicy: {
      policy: "cross-origin"
    },
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

/* =========================
   INDEX / STATIC FILE SETUP
========================= */

const PUBLIC_DIR = path.join(__dirname, "public");
const ROOT_INDEX = path.join(__dirname, "index.html");
const PUBLIC_INDEX = path.join(PUBLIC_DIR, "index.html");

const INDEX_FILE = fs.existsSync(PUBLIC_INDEX)
  ? PUBLIC_INDEX
  : ROOT_INDEX;

const STATIC_DIR = fs.existsSync(PUBLIC_DIR)
  ? PUBLIC_DIR
  : __dirname;

app.use(
  express.static(STATIC_DIR, {
    extensions: ["html"]
  })
);

/* =========================
   RATE LIMIT
========================= */

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

/* =========================
   IP SECURITY
========================= */

function isPrivateIPv4(ip) {
  const parts = ip.split(".").map(Number);

  if (
    parts.length !== 4 ||
    parts.some(
      (n) =>
        !Number.isInteger(n) ||
        n < 0 ||
        n > 255
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

/* =========================
   URL SECURITY
========================= */

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
      records.some((r) =>
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

/* =========================
   SAFE FETCH / REDIRECT
========================= */

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
        "user-agent": "EMFast4K/1.0",
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

/* =========================
   VIDEO DETECTION
========================= */

const VIDEO_EXT =
  /\.(mp4|m4v|mov|webm|mkv|avi|mpeg|mpg|3gp|ogv)$/i;

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

async function probeDirectVideo(url) {
  /* প্রথমে HEAD চেষ্টা */
  try {
    const {
      response,
      finalUrl
    } = await fetchWithSafeRedirects(
      url,
      {
        method: "HEAD"
      }
    );

    const direct =
      response.ok &&
      looksLikeVideo(
        response,
        finalUrl
      );

    await response.body?.cancel().catch(() => {});

    if (direct) {
      return {
        direct: true,
        url: finalUrl,
        type:
          response.headers.get(
            "content-type"
          ) || "video/mp4"
      };
    }
  } catch {}

  /* HEAD কাজ না করলে ছোট Range GET */
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
      (response.ok ||
        response.status === 206) &&
      looksLikeVideo(
        response,
        finalUrl
      );

    const type =
      response.headers.get(
        "content-type"
      ) || "video/mp4";

    await response.body?.cancel().catch(() => {});

    if (direct) {
      return {
        direct: true,
        url: finalUrl,
        type
      };
    }
  } catch {}

  return {
    direct: false
  };
}

/* =========================
   FILE NAME
========================= */

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
    cleaned || "EM-Fast-4K-Video"
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

/* =========================
   DOWNLOAD TOKEN
========================= */

function makeToken(entry) {
  const token =
    crypto.randomBytes(24).toString("hex");

  prepared.set(token, {
    ...entry,
    expiresAt:
      Date.now() + TOKEN_TTL_MS
  });

  return token;
}

setInterval(() => {
  const now = Date.now();

  for (
    const [token, entry] of prepared
  ) {
    if (entry.expiresAt <= now) {
      prepared.delete(token);
    }
  }
}, 60000).unref();

/* =========================
   HEALTH CHECK
========================= */

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    service: "EM Fast 4K",
    saveApiConfigured:
      Boolean(SAVEAPI_KEY)
  });
});

/* =========================
   PREPARE DOWNLOAD
========================= */

app.post(
  "/api/prepare",
  async (req, res) => {
    const inputUrl = String(
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

      /* =========================
         DIRECT VIDEO FIRST
      ========================= */

      const direct =
        await probeDirectVideo(
          inputUrl
        );

      if (direct.direct) {
        const title =
          titleFromUrl(
            direct.url
          );

        const token = makeToken({
          url: direct.url,
          title,
          source: "direct",
          contentType:
            direct.type
        });

        return res.json({
          ok: true,
          token,
          title,
          method: "direct"
        });
      }

      /* =========================
         SAVEAPI FALLBACK
      ========================= */

      if (!SAVEAPI_KEY) {
        return res.status(503).json({
          error:
            "এই লিংকটি সরাসরি ভিডিও ফাইল নয়। Render → Environment Variables-এ SAVEAPI_KEY যোগ করে SaveAPI key দিন।"
        });
      }

      const apiUrl =
        `https://api.saveapi.org/v1/download?url=${encodeURIComponent(inputUrl)}`;

      const apiResponse =
        await fetch(apiUrl, {
          method: "GET",
          headers: {
            Authorization:
              `Bearer ${SAVEAPI_KEY}`,
            Accept:
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
            ? "SaveAPI-এর ফ্রি রেট লিমিট আপাতত শেষ। কিছুক্ষণ পরে আবার চেষ্টা করুন।"
            : apiResponse.status === 401
            ? "SaveAPI key সঠিক নয়। Render-এর SAVEAPI_KEY মানটি পরীক্ষা করুন।"
            : code ===
              "UNSUPPORTED_PLATFORM"
            ? "এই ভিডিও সাইট SaveAPI সমর্থন করে না।"
            : (
                data?.error?.message ||
                `SaveAPI অনুরোধ সফল হয়নি (HTTP ${apiResponse.status})।`
              );

        return res
          .status(
            apiResponse.status === 429
              ? 429
              : 502
          )
          .json({
            error: statusMessage
          });
      }

      const media =
        Array.isArray(data?.medias)
          ? data.medias.find(
              (item) =>
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
            "SaveAPI এই লিংকের জন্য ভিডিও ফাইল খুঁজে পায়নি। অন্য পাবলিক লিংক চেষ্টা করুন।"
        });
      }

      await assertPublicHttpUrl(
        media.url
      );

      const title =
        cleanFileName(
          data?.meta?.title ||
            data?.title ||
            titleFromUrl(inputUrl)
        );

      const token = makeToken({
        url: media.url,
        title,
        source: "saveapi",
        contentType:
          media.mime_type ||
          media.mimeType ||
          (
            media.ext
              ? `video/${media.ext}`
              : "application/octet-stream"
          )
      });

      return res.json({
        ok: true,
        token,
        title,
        method: "saveapi"
      });

    } catch (error) {
      const message =
        error?.name ===
        "TimeoutError"
          ? "সাইটের উত্তর পেতে বেশি সময় লাগছে। আবার চেষ্টা করুন।"
          : (
              error.message ||
              "লিংক প্রসেস করা যায়নি।"
            );

      return res.status(400).json({
        error: message
      });
    }
  }
);

/* =========================
   FILE DOWNLOAD
========================= */

app.get(
  "/api/file/:token",
  async (req, res) => {
    const entry =
      prepared.get(
        req.params.token
      );

    if (
      !entry ||
      entry.expiresAt <= Date.now()
    ) {
      prepared.delete(
        req.params.token
      );

      return res
        .status(410)
        .send(
          "ডাউনলোড লিংকের মেয়াদ শেষ হয়েছে। আবার লিংক পেস্ট করুন।"
        );
    }

    try {
      const headers = {};

      if (req.headers.range) {
        headers.Range =
          req.headers.range;
      }

      const {
        response: upstream
      } =
        await fetchWithSafeRedirects(
          entry.url,
          {
            method: "GET",
            headers
          }
        );

      const type =
        upstream.headers.get(
          "content-type"
        ) ||
        entry.contentType ||
        "application/octet-stream";

      if (
        !upstream.ok &&
        upstream.status !== 206
      ) {
        await upstream.body
          ?.cancel()
          .catch(() => {});

        return res
          .status(502)
          .send(
            "ভিডিও ফাইলটি সাইট থেকে পাওয়া যায়নি।"
          );
      }

      if (
        type
          .toLowerCase()
          .includes("text/html")
      ) {
        await upstream.body
          ?.cancel()
          .catch(() => {});

        return res
          .status(502)
          .send(
            "সাইট ভিডিও ফাইলের বদলে একটি ওয়েব পেজ দিয়েছে।"
          );
      }

      const extMatch =
        type.match(
          /video\/(mp4|webm|quicktime|x-matroska)/i
        );

      let ext = extMatch
        ? (
            {
              quicktime: "mov",
              "x-matroska": "mkv"
            }[
              extMatch[1]
                .toLowerCase()
            ] ||
            extMatch[1]
              .toLowerCase()
          )
        : "";

      if (!ext) {
        try {
          const m =
            new URL(
              entry.url
            ).pathname.match(
              VIDEO_EXT
            );

          if (m) {
            ext =
              m[1].toLowerCase();
          }
        } catch {}
      }

      if (!ext) {
        ext = "mp4";
      }

      const fileName =
        cleanFileName(
          entry.title
        ) +
        "." +
        ext;

      res.status(
        upstream.status === 206
          ? 206
          : 200
      );

      res.setHeader(
        "Content-Type",
        type
      );

      const asciiFallback =
        fileName
          .replace(
            /[^\x20-\x7E]/g,
            "_"
          )
          .replace(
            /["\\]/g,
            "_"
          );

      const encodedName =
        encodeURIComponent(
          fileName
        ).replace(
          /['()*]/g,
          (ch) =>
            `%${ch.charCodeAt(0)
              .toString(16)
              .toUpperCase()}`
        );

      res.setHeader(
        "Content-Disposition",
        `attachment; filename="${asciiFallback}"; filename*=UTF-8''${encodedName}`
      );

      res.setHeader(
        "Cache-Control",
        "no-store"
      );

      res.setHeader(
        "X-Content-Type-Options",
        "nosniff"
      );

      for (
        const h of [
          "content-length",
          "content-range",
          "accept-ranges"
        ]
      ) {
        const value =
          upstream.headers.get(h);

        if (value) {
          res.setHeader(
            h,
            value
          );
        }
      }

      if (!upstream.body) {
        return res.end();
      }

      const nodeStream =
        Readable.fromWeb(
          upstream.body
        );

      res.on("close", () => {
        if (!res.writableEnded) {
          nodeStream.destroy();
        }
      });

      nodeStream.on(
        "error",
        () => {
          if (!res.headersSent) {
            res.status(502);
          }

          res.end();
        }
      );

      nodeStream.pipe(res);

    } catch (error) {
      if (!res.headersSent) {
        res.status(502);
      }

      res.end(
        error.message ||
          "ভিডিও ডাউনলোড করা যায়নি।"
      );
    }
  }
);

/* =========================
   FIXED EXPRESS 5 ROUTE
   আগের app.get("*") এর বদলে
   এই Express 5-compatible route
========================= */

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
      (err) => {
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

/* =========================
   ERROR HANDLER
========================= */

app.use(
  (
    err,
    _req,
    res,
    _next
  ) => {
    console.error(
      "Unhandled error:",
      err.message
    );

    res.status(500).json({
      error:
        "সার্ভারে সমস্যা হয়েছে। কিছুক্ষণ পরে আবার চেষ্টা করুন।"
    });
  }
);

/* =========================
   START SERVER
========================= */

app.listen(
  PORT,
  () => {
    console.log(
      `EM Fast 4K running on port ${PORT}`
    );

    if (!SAVEAPI_KEY) {
      console.warn(
        "SAVEAPI_KEY is not set. Direct video URLs can still work; social links need SaveAPI."
      );
    }
  }
);
