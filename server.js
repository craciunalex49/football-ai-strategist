
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

// Temporary storage for testing only.
// Tokens are lost when the service restarts.
const temporaryTokens = new Map();

app.get("/", (req, res) => {
  res.send("Football AI Strategist backend is running.");
});

app.get("/health", (req, res) => {
  res.json({
    service: "Football AI Strategist",
    status: "running"
  });
});

app.get("/oauth", (req, res) => {
  if (!CLIENT_KEY || !REDIRECT_URI || !SESSION_SECRET) {
    return res.status(500).send(
      "Server configuration is incomplete."
    );
  }

  const state = crypto.randomBytes(32).toString("hex");
  const signature = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(state)
    .digest("hex");

  pendingStates.set(state, Date.now());

  // Remove expired states.
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

  const separator = state.lastIndexOf(".");
  if (separator < 1) {
    return res.status(400).send("Invalid state.");
  }

  const stateValue = state.slice(0, separator);
  const suppliedSignature = state.slice(separator + 1);
  const createdAt = pendingStates.get(stateValue);

  if (!createdAt || Date.now() - createdAt > 10 * 60 * 1000) {
    pendingStates.delete(stateValue);
    return res.status(400).send("State expired or not found. Try again.");
  }

  const expectedSignature = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(stateValue)
    .digest("hex");

  if (
    suppliedSignature.length !== expectedSignature.length ||
    !crypto.timingSafeEqual(
      Buffer.from(suppliedSignature),
      Buffer.from(expectedSignature)
    )
  ) {
    pendingStates.delete(stateValue);
    return res.status(400).send("State validation failed.");
  }

  pendingStates.delete(stateValue);

  if (!CLIENT_SECRET || !REDIRECT_URI) {
    return res.status(500).send("Server configuration is incomplete.");
  }

  try {
    const body = new URLSearchParams({
      client_key: CLIENT_KEY,
      client_secret: CLIENT_SECRET,
      code,
      grant_type: "authorization_code",
      redirect_uri: REDIRECT_URI
    });

    const tokenResponse = await fetch(
      "https://open.tiktokapis.com/v2/oauth/token/",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body
      }
    );

    const result = await tokenResponse.json();

    if (!tokenResponse.ok || result.error) {
      console.error("TikTok token exchange failed:", result.error);
      return res.status(400).send(
        "TikTok token exchange failed. Check server logs."
      );
    }

    // Temporary testing storage; not persistent.
    temporaryTokens.set(result.open_id, {
      access_token: result.access_token,
      refresh_token: result.refresh_token,
      expires_at: Date.now() + result.expires_in * 1000,
      scope: result.scope
    });

    res.send(
      "TikTok authorization succeeded. " +
      "Tokens are held temporarily for testing only."
    );
  } catch (err) {
    console.error("OAuth callback failed:", err.message);
    res.status(500).send("Authorization could not be completed.");
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Football AI Strategist listening on port ${PORT}`);
});
