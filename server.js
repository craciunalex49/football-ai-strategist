
const express = require("express");
const crypto = require("crypto");

const app = express();
app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;
const CLIENT_KEY = process.env.TIKTOK_CLIENT_KEY;
const CLIENT_SECRET = process.env.TIKTOK_CLIENT_SECRET;
const REDIRECT_URI = process.env.TIKTOK_REDIRECT_URI;
const SESSION_SECRET = process.env.SESSION_SECRET;

const pendingStates = new Map();

// Temporary single-user testing only.
// Tokens are lost when the service restarts.
let currentToken = null;

app.get("/", (req, res) => {
  res.send(`
    <h1>Football AI Strategist</h1>
    <p>Backend is running.</p>
    <a href="/oauth">Connect with TikTok</a>
    <br><br>
    <a href="/videos">View authorized TikTok videos</a>
  `);
});

app.get("/health", (req, res) => {
  res.json({ service: "Football AI Strategist", status: "running" });
});

app.get("/oauth", (req, res) => {
  if (!CLIENT_KEY || !REDIRECT_URI || !SESSION_SECRET) {
    return res.status(500).send("Server configuration is incomplete.");
  }

  const state = crypto.randomBytes(32).toString("hex");
  const signature = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(state)
    .digest("hex");

  pendingStates.set(state, Date.now());

  for (const [key, createdAt] of pendingStates) {
    if (Date.now() - createdAt > 10 * 60 * 1000) {
      pendingStates.delete(key);
    }
  }

  const url = new URL("https://www.tiktok.com/v2/auth/authorize/");
  url.searchParams.set("client_key", CLIENT_KEY);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "user.info.basic,video.list");
  url.searchParams.set("redirect_uri", REDIRECT_URI);
  url.searchParams.set("state", `${state}.${signature}`);

  res.redirect(url.toString());
});

app.get("/auth/callback", async (req, res) => {
  const { code, state, error, error_description } = req.query;

  if (error) {
    return res.status(400).send(
      `TikTok authorization failed: ${String(error_description || error)}`
    );
  }

  if (typeof code !== "string" || typeof state !== "string") {
    return res.status(400).send("Missing authorization response.");
  }

  if (!SESSION_SECRET || !CLIENT_SECRET || !CLIENT_KEY || !REDIRECT_URI) {
    return res.status(500).send("Server configuration is incomplete.");
  }

  const separator = state.lastIndexOf(".");
  if (separator < 1) {
    return res.status(400).send("Invalid state.");
  }

  const stateValue = state.slice(0, separator);
  const suppliedSignature = state.slice(separator + 1);
  const createdAt = pendingStates.get(stateValue);

  if (!createdAt || Date.now() - createdAt > 10 * 60 * 1000) {
    pendingStates.delete(stateValue);
    return res.status(400).send("State expired. Please try again.");
  }

  const expectedSignature = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(stateValue)
    .digest("hex");

  const supplied = Buffer.from(suppliedSignature);
  const expected = Buffer.from(expectedSignature);

  if (
    supplied.length !== expected.length ||
    !crypto.timingSafeEqual(supplied, expected)
  ) {
    pendingStates.delete(stateValue);
    return res.status(400).send("State validation failed.");
  }

  pendingStates.delete(stateValue);

  try {
    const body = new URLSearchParams({
      client_key: CLIENT_KEY,
      client_secret: CLIENT_SECRET,
      code,
      grant_type: "authorization_code",
      redirect_uri: REDIRECT_URI
    });

    const response = await fetch(
      "https://open.tiktokapis.com/v2/oauth/token/",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body
      }
    );

    const result = await response.json();

    if (!response.ok || result.error || !result.access_token) {
      console.error("TikTok token exchange failed:", result.error);
      return res.status(400).send(
        "TikTok token exchange failed. Check Render logs."
      );
    }

    currentToken = {
      access_token: result.access_token,
      refresh_token: result.refresh_token,
      expires_at: Date.now() + result.expires_in * 1000,
      open_id: result.open_id,
      scope: result.scope
    };

    res.send(`
      <h1>TikTok connected successfully!</h1>
      <p>Temporary test session created.</p>
      <p><a href="/videos">Load your TikTok videos</a></p>
    `);
  } catch (err) {
    console.error("OAuth callback failed:", err.message);
    res.status(500).send("Authorization failed. Check Render logs.");
  }
});

app.get("/videos", async (req, res) => {
  if (!currentToken) {
    return res.status(401).send(
      'TikTok is not connected. <a href="/oauth">Connect with TikTok</a>'
    );
  }

  if (Date.now() >= currentToken.expires_at) {
    return res.status(401).send(
      'Access token expired. <a href="/oauth">Reconnect with TikTok</a>'
    );
  }

  try {
    const fields = [
      "id",
      "create_time",
      "cover_image_url",
      "share_url",
      "video_description",
      "duration",
      "title",
      "like_count",
      "comment_count",
      "share_count",
      "view_count"
    ].join(",");

    const response = await fetch(
      `https://open.tiktokapis.com/v2/video/list/?fields=${encodeURIComponent(fields)}`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${currentToken.access_token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ max_count: 20 })
      }
    );

    const result = await response.json();

    if (!response.ok || result.error?.code !== "ok") {
      console.error("TikTok video list failed:", result.error);
      return res.status(502).json({
        error: "TikTok could not return the video list.",
        details: result.error || null
      });
    }

    res.json({
      count: result.data?.videos?.length || 0,
      videos: result.data?.videos || [],
      has_more: result.data?.has_more || false,
      cursor: result.data?.cursor || null
    });
  } catch (err) {
    console.error("Video request failed:", err.message);
    res.status(500).json({ error: "Could not load TikTok videos." });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Football AI Strategist listening on port ${PORT}`);
});

