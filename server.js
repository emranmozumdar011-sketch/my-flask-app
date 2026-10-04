const express = require("express");
const helmet = require("helmet");
const { rateLimit } = require("express-rate-limit");
const dns = require("node:dns").promises;
const net = require("node:net");
const path = require("node:path");
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

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "blob:", "https:"],
        mediaSrc: ["'self'", "blob:", "https:"],
        connectSrc: ["'self'", "https:"],
        fontSrc: ["'self'", "data:", "https:"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'self'"]
      }
    }
  })
);

app.use(express.json({ limit: "8kb" }));

const prepareLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    error: "Too many requests. Please wait a moment and try again."
  }
});

app.use("/api/prepare", prepareLimiter);

const fs = require("node:fs");

const PUBLIC_DIR = path.join(__dirname, "public");
const ROOT_INDEX = path.join(__dirname, "index.html");
const PUBLIC_INDEX = path.join(PUBLIC_DIR, "index.html");

const INDEX_FILE = fs.existsSync(PUBLIC_INDEX)
  ? PUBLIC_INDEX
  : ROOT_INDEX;

app.use(
  express.static(
    fs.existsSync(PUBLIC_DIR)
      ? PUBLIC_DIR
      : __dirname,
    {
      extensions: ["html"]
    }
  )
);

function isPrivateIPv4(ip) {
  const parts = ip.split(".").map(Number);

  if (parts.length !== 4 || parts.some(Number.isNaN)) {
    return true;
  }

  const [a, b] = parts;

  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;

  return false;
}

function isPrivateIPv6(ip) {
  const value = ip.toLowerCase();

  if (value === "::1") return true;
  if (value.startsWith("fc")) return true;
  if (value.startsWith("fd")) return true;
  if (value.startsWith("fe80:")) return true;

  if (value.startsWith("::ffff:")) {
    const mapped = value.substring(7);

    if (net.isIP(mapped) === 4) {
      return isPrivateIPv4(mapped);
    }
  }

  return false;
}

async function assertPublicHttpUrl(value) {
  let url;

  try {
    url = new URL(value);
  } catch {
    throw new Error("Invalid URL.");
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Only HTTP and HTTPS URLs are supported.");
  }

  if (url.username || url.password) {
    throw new Error("URLs containing username or password are not allowed.");
  }

  const hostname = url.hostname.toLowerCase();

  if (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local")
  ) {
    throw new Error("Private/local URLs are not allowed.");
  }

  const addresses = await dns.lookup(hostname, {
    all: true,
    verbatim: true
  });

  if (!addresses.length) {
    throw new Error("The video host could not be resolved.");
  }

  for (const item of addresses) {
    if (net.isIP(item.address) === 4 && isPrivateIPv4(item.address)) {
      throw new Error("Private network addresses are not allowed.");
    }

    if (net.isIP(item.address) === 6 && isPrivateIPv6(item.address)) {
      throw new Error("Private network addresses are not allowed.");
    }
  }

  return url;
}

async function fetchWithSafeRedirects(
  initialUrl,
  options = {}
) {
  let currentUrl = initialUrl;

  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    await assertPublicHttpUrl(currentUrl);

    const response = await fetch(currentUrl, {
      ...options,
      redirect: "manual",
      signal:
        options.signal ||
        AbortSignal.timeout(20_000)
    });

    if (
      [301, 302, 303, 307, 308].includes(
        response.status
      )
    ) {
      const location = response.headers.get("location");

      await response.body?.cancel().catch(() => {});

      if (!location) {
        throw new Error("Redirect location missing.");
      }

      currentUrl = new URL(
        location,
        currentUrl
      ).toString();

      continue;
    }

    return {
      response,
      finalUrl: currentUrl
    };
  }

  throw new Error("Too many redirects.");
}

const VIDEO_EXT =
  /\.(mp4|m4v|webm|mov|mkv|avi|flv|wmv|mpeg?|3gp)(?:$|[?#])/i;

function looksLikeVideo(response, url) {
  const type =
    response.headers.get("content-type") || "";

  if (type.toLowerCase().startsWith("video/")) {
    return true;
  }

  return VIDEO_EXT.test(url);
}

async function probeDirectVideo(inputUrl) {
  try {
    let result = await fetchWithSafeRedirects(
      inputUrl,
      {
        method: "HEAD",
        signal: AbortSignal.timeout(15_000)
      }
    );

    let response = result.response;
    let finalUrl = result.finalUrl;

    let direct =
      (response.ok || response.status === 206) &&
      looksLikeVideo(response, finalUrl);

    await response.body?.cancel().catch(() => {});

    if (direct) {
      const type =
        response.headers.get("content-type") ||
        "video/mp4";

      return {
        direct: true,
        url: finalUrl,
        type
      };
    }

    result = await fetchWithSafeRedirects(
      inputUrl,
      {
        method: "GET",
        headers: {
          Range: "bytes=0-0"
        },
        signal: AbortSignal.timeout(15_000)
      }
    );

    response = result.response;
    finalUrl = result.finalUrl;

    direct =
      (response.ok || response.status === 206) &&
      looksLikeVideo(response, finalUrl);

    const type =
      response.headers.get("content-type") ||
      "video/mp4";

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

  return cleaned || "EM-Fast-4K-Video";
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

  for (const [token, entry] of prepared) {
    if (entry.expiresAt <= now) {
      prepared.delete(token);
    }
  }
}, 60_000).unref();

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    service: "EM Fast 4K",
    saveApiConfigured: Boolean(SAVEAPI_KEY)
  });
});

app.post("/api/prepare", async (req, res) => {
  const inputUrl =
    String(req.body?.url || "").trim();

  if (!inputUrl || inputUrl.length > 3000) {
    return res.status(400).json({
      error: "একটি সঠিক ভিডিও লিংক পেস্ট করুন।"
    });
  }

  try {
    await assertPublicHttpUrl(inputUrl);

    /*
      প্রথমে সরাসরি ভিডিও URL খোঁজা হবে।
      Direct video পাওয়া গেলে SaveAPI ব্যবহার হবে না।
    */
    const direct =
      await probeDirectVideo(inputUrl);

    if (direct.direct) {
      const title =
        titleFromUrl(direct.url);

      const token = makeToken({
        url: direct.url,
        title,
        source: "direct",
        contentType: direct.type
      });

      return res.json({
        ok: true,
        token,
        title,
        method: "direct"
      });
    }

    /*
      Direct video না পেলে তবেই SaveAPI ব্যবহার হবে।
    */
    if (!SAVEAPI_KEY) {
      return res.status(503).json({
        error:
          "এই লিংকটি সরাসরি ভিডিও ফাইল নয়। Render → Environment Variables-এ SAVEAPI_KEY যোগ করে SaveAPI key দিন।"
      });
    }

    const apiUrl =
      `https://api.saveapi.org/v1/download?url=${encodeURIComponent(
        inputUrl
      )}`;

    const apiResponse = await fetch(
      apiUrl,
      {
        method: "GET",
        headers: {
          Authorization:
            `Bearer ${SAVEAPI_KEY}`,
          Accept:
            "application/json"
        },
        signal:
          AbortSignal.timeout(30_000)
      }
    );

    let data;

    try {
      data = await apiResponse.json();
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
            item =>
              item &&
              item.type !== "audio" &&
              typeof item.url === "string" &&
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

    const title = cleanFileName(
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
});

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

      return res.status(410).json({
        error:
          "এই download link-এর মেয়াদ শেষ হয়েছে। আবার চেষ্টা করুন।"
      });
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
            headers,
            signal:
              AbortSignal.timeout(
                30_000
              )
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

        return res.status(502).send(
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

        return res.status(502).send(
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
              extMatch[1].toLowerCase()
            ] ||
            extMatch[1].toLowerCase()
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
          ch =>
            `%${ch
              .charCodeAt(0)
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

      /*
        Content-Length থাকলে frontend
        প্রকৃত download progress হিসাব
        করতে পারবে।
      */
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

/*
  Express 5 compatible catch-all.
  app.get("*") ব্যবহার করা যাবে না।
*/
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
