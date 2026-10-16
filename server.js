
const express = require("express");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");
const app = express();
app.set("trust proxy", 1);
const allowedOrigin = "https://craciunalex49.github.io";

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", allowedOrigin);
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});
const PORT = process.env.PORT || 3000;
const CLIENT_KEY = process.env.TIKTOK_CLIENT_KEY;
const CLIENT_SECRET = process.env.TIKTOK_CLIENT_SECRET;
const REDIRECT_URI = process.env.TIKTOK_REDIRECT_URI;
const SESSION_SECRET = process.env.SESSION_SECRET;

const TOKEN_ENCRYPTION_KEY = process.env.TOKEN_ENCRYPTION_KEY;

function encryptToken(value) {
  if (!TOKEN_ENCRYPTION_KEY || !/^[0-9a-f]{64}$/i.test(TOKEN_ENCRYPTION_KEY)) {
    throw new Error("TOKEN_ENCRYPTION_KEY must be 64 hexadecimal characters.");
  }

  const key = Buffer.from(TOKEN_ENCRYPTION_KEY, "hex");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  const encrypted = Buffer.concat([
    cipher.update(value, "utf8"),
    cipher.final()
  ]);

  const tag = cipher.getAuthTag();

  return [
    iv.toString("hex"),
    tag.toString("hex"),
    encrypted.toString("hex")
  ].join(":");
}

function decryptToken(value) {
  if (!TOKEN_ENCRYPTION_KEY || !/^[0-9a-f]{64}$/i.test(TOKEN_ENCRYPTION_KEY)) {
    throw new Error("TOKEN_ENCRYPTION_KEY must be 64 hexadecimal characters.");
  }

  const parts = value.split(":");
  if (parts.length !== 3) {
    throw new Error("Invalid encrypted token format.");
  }

  const [ivHex, tagHex, encryptedHex] = parts;
  const key = Buffer.from(TOKEN_ENCRYPTION_KEY, "hex");
  const iv = Buffer.from(ivHex, "hex");
  const tag = Buffer.from(tagHex, "hex");
  const encrypted = Buffer.from(encryptedHex, "hex");

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);

  return Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ]).toString("utf8");
}

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;

const supabase =
  SUPABASE_URL && SUPABASE_SECRET_KEY
    ? createClient(SUPABASE_URL, SUPABASE_SECRET_KEY, {
        auth: {
          persistSession: false,
          autoRefreshToken: false,
          detectSessionInUrl: false
        }
      })
    : null;

const pendingStates = new Map();


let currentToken = null;
// Recover the saved TikTok connection after a server restart.
async function loadStoredToken() {
  if (!supabase) {
    throw new Error("Supabase is not configured.");
  }

  const { data, error } = await supabase
    .from("tiktok_tokens")
    .select(
      "open_id, access_token_encrypted, refresh_token_encrypted, expires_at, scopes"
    )
    .order("updated_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  if (error) {
    console.error("Could not load saved TikTok connection:", error.code);
    throw new Error("Could not load the saved TikTok connection.");
  }

  if (!data) {
    return null;
  }

  currentToken = {
    access_token: decryptToken(data.access_token_encrypted),
    refresh_token: data.refresh_token_encrypted
      ? decryptToken(data.refresh_token_encrypted)
      : null,
    expires_at: data.expires_at
      ? new Date(data.expires_at).getTime()
      : 0,
    open_id: data.open_id,
    scope: data.scopes
  };

   return currentToken;
}

// Refresh the TikTok access token before it expires.
async function refreshTikTokToken() {
  if (!currentToken) {
    await loadStoredToken();
  }

  if (!currentToken) {
    throw new Error("No saved TikTok connection.");
  }

  if (Date.now() < currentToken.expires_at - 5 * 60 * 1000) {
    return currentToken;
  }

  if (!currentToken.refresh_token) {
    throw new Error("No TikTok refresh token. Reconnect TikTok.");
  }

  const body = new URLSearchParams({
    client_key: process.env.TIKTOK_CLIENT_KEY,
    client_secret: process.env.TIKTOK_CLIENT_SECRET,
    grant_type: "refresh_token",
    refresh_token: currentToken.refresh_token
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
    console.error("TikTok token refresh failed:", {
      status: response.status,
      error: result.error || "Missing access token",
      description: result.error_description || null
    });

    throw new Error("TikTok token refresh failed. Reconnect if necessary.");
  }

  const newRefreshToken =
    result.refresh_token || currentToken.refresh_token;

  const updatedToken = {
    access_token: result.access_token,
    refresh_token: newRefreshToken,
    expires_at: Date.now() + result.expires_in * 1000,
    open_id: result.open_id || currentToken.open_id,
    scope: result.scope || currentToken.scope
  };

  const { error } = await supabase
    .from("tiktok_tokens")
    .upsert(
      {
        open_id: updatedToken.open_id,
        access_token_encrypted: encryptToken(updatedToken.access_token),
        refresh_token_encrypted: encryptToken(updatedToken.refresh_token),
        expires_at: new Date(updatedToken.expires_at).toISOString(),
        scopes: updatedToken.scope,
        updated_at: new Date().toISOString()
      },
      { onConflict: "open_id" }
    );

  if (error) {
    console.error("Could not save refreshed TikTok token:", error.code);
    throw new Error("Could not save refreshed TikTok token.");
  }

  currentToken = updatedToken;
  console.log("TikTok access token refreshed and saved.");

  return currentToken;
}

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
app.get("/supabase-health", async (req, res) => {
  if (!supabase) {
    return res.status(500).json({
      status: "error",
      message: "Supabase environment variables are missing."
    });
  }

  try {
    const { error } = await supabase
      .from("connection_test")
      .select("id")
      .limit(1);

    // A missing table is acceptable for this initial connectivity test.
    if (error && error.code !== "42P01" && error.code !== "PGRST205") {
      console.error("Supabase health check failed:", error.code);
      return res.status(502).json({
        status: "error",
        message: "Supabase connection check failed."
      });
    }

    return res.json({
      status: "connected",
      service: "Football AI Strategist"
    });
  } catch (err) {
    console.error("Supabase health check error:", err.message);
    return res.status(502).json({
      status: "error",
      message: "Supabase connection check failed."
    });
  }
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
  console.error("TikTok token exchange failed:", {
    status: response.status,
    error: result.error || "Missing access token"
  });

  return res.status(400).send(
    "TikTok token exchange failed. Check Render logs."
  );
}

   
    if (!supabase) {
      return res.status(500).send("Supabase is not configured.");
    }

    if (!result.open_id || !result.expires_in) {
      return res.status(502).send("TikTok returned incomplete token data.");
    }

    const expiresAt = Date.now() + Number(result.expires_in) * 1000;

    const { error: saveError } = await supabase
      .from("tiktok_tokens")
      .upsert(
        {
          open_id: result.open_id,
          access_token_encrypted: encryptToken(result.access_token),
          refresh_token_encrypted: result.refresh_token
            ? encryptToken(result.refresh_token)
            : null,
          expires_at: new Date(expiresAt).toISOString(),
          scopes: result.scope || null,
          updated_at: new Date().toISOString()
        },
        { onConflict: "open_id" }
      );

    if (saveError) {
      console.error("Failed to save TikTok tokens:", saveError.code);
      return res.status(500).send(
        "Could not save TikTok connection. Check server logs."
      );
    }

    currentToken = {
      access_token: result.access_token,
      refresh_token: result.refresh_token,
      expires_at: expiresAt,
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
  try {
    if (!currentToken) {
      await loadStoredToken();
    }

    if (!currentToken) {
      return res.status(401).send(
        'TikTok is not connected. <a href="/oauth">Connect with TikTok</a>'
      );
    }

    try {
  await refreshTikTokToken();
} catch (err) {
  console.error("TikTok connection refresh failed:", err.message);

  return res.status(401).send(
    'TikTok connection needs attention. <a href="/oauth">Reconnect with TikTok</a>'
  );
}
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
    res.status(500).json({
      error: "Could not load TikTok videos."
    });
  }
});
app.get("/sync-videos", async (req, res) => {
  try {
    if (!supabase) {
      return res.status(500).json({
        error: "Supabase is not configured."
      });
    }

    await refreshTikTokToken();

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
      console.error("TikTok sync failed:", result.error);

      return res.status(502).json({
        error: "Could not retrieve TikTok videos.",
        details: result.error || null
      });
    }

    const videos = result.data?.videos || [];

    const rows = videos.map((video) => ({
      video_id: video.id,
      create_time: video.create_time
        ? new Date(video.create_time * 1000).toISOString()
        : null,
      description: video.video_description || null,
      title: video.title || null,
      duration: video.duration ?? null,
      share_url: video.share_url || null,
      cover_image_url: video.cover_image_url || null,
      view_count: video.view_count ?? 0,
      like_count: video.like_count ?? 0,
      comment_count: video.comment_count ?? 0,
      share_count: video.share_count ?? 0,
      imported_at: new Date().toISOString()
    }));

    if (rows.length > 0) {
      const { error } = await supabase
        .from("tiktok_videos")
        .upsert(rows, { onConflict: "video_id" });

      if (error) {
        console.error("Supabase video sync failed:", error.code);

        return res.status(500).json({
          error: "Could not save videos to Supabase.",
          code: error.code
        });
      }
    }

    return res.json({
      success: true,
      synced: rows.length,
      has_more: result.data?.has_more || false,
      message: "TikTok videos saved to Supabase."
    });
  } catch (err) {
    console.error("Video sync failed:", err.message);

    return res.status(500).json({
      error: "Video synchronization failed."
    });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Football AI Strategist listening on port ${PORT}`);
});

