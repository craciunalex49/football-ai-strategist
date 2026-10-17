const express = require("express");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.set("trust proxy", 1);

const allowedOrigin = "https://craciunalex49.github.io";

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", allowedOrigin);
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

app.use(express.json({ limit: "100kb" }));

const PORT = process.env.PORT || 3000;
const CLIENT_KEY = process.env.TIKTOK_CLIENT_KEY;
const CLIENT_SECRET = process.env.TIKTOK_CLIENT_SECRET;
const REDIRECT_URI = process.env.TIKTOK_REDIRECT_URI;
const SESSION_SECRET = process.env.SESSION_SECRET;
const TOKEN_ENCRYPTION_KEY = process.env.TOKEN_ENCRYPTION_KEY;

function encryptToken(value) {
  if (
    !TOKEN_ENCRYPTION_KEY ||
    !/^[0-9a-f]{64}$/i.test(TOKEN_ENCRYPTION_KEY)
  ) {
    throw new Error(
      "TOKEN_ENCRYPTION_KEY must be 64 hexadecimal characters."
    );
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
  if (
    !TOKEN_ENCRYPTION_KEY ||
    !/^[0-9a-f]{64}$/i.test(TOKEN_ENCRYPTION_KEY)
  ) {
    throw new Error(
      "TOKEN_ENCRYPTION_KEY must be 64 hexadecimal characters."
    );
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
    client_key: CLIENT_KEY,
    client_secret: CLIENT_SECRET,
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

    throw new Error(
      "TikTok token refresh failed. Reconnect if necessary."
    );
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
        access_token_encrypted: encryptToken(
          updatedToken.access_token
        ),
        refresh_token_encrypted: encryptToken(
          updatedToken.refresh_token
        ),
        expires_at: new Date(
          updatedToken.expires_at
        ).toISOString(),
        scopes: updatedToken.scope,
        updated_at: new Date().toISOString()
      },
      { onConflict: "open_id" }
    );

  if (error) {
    console.error(
      "Could not save refreshed TikTok token:",
      error.code
    );
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

    let cursor;
    let hasMore = true;
    let synced = 0;
    let pages = 0;
    const maxPages = 100;
    const seenCursors = new Set();

    while (hasMore && pages < maxPages) {
      const body = { max_count: 20 };

      if (cursor !== undefined && cursor !== null) {
        body.cursor = cursor;
      }

      const response = await fetch(
        `https://open.tiktokapis.com/v2/video/list/?fields=${encodeURIComponent(fields)}`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${currentToken.access_token}`,
            "Content-Type": "application/json"
          },
          body: JSON.stringify(body)
        }
      );

      const result = await response.json();

      if (!response.ok || result.error?.code !== "ok") {
        console.error("TikTok sync failed:", result.error);
        return res.status(502).json({
          error: "Could not retrieve TikTok videos.",
          details: result.error || null,
          synced,
          pages
        });
      }

      const data = result.data || {};
      const videos = data.videos || [];

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
            code: error.code,
            synced,
            pages
          });
        }

        const historyRows = rows.map((row) => ({
          video_id: row.video_id,
          recorded_at: new Date().toISOString(),
          view_count: row.view_count,
          like_count: row.like_count,
          comment_count: row.comment_count,
          share_count: row.share_count
        }));

        const { error: historyError } = await supabase
          .from("video_stats_history")
          .insert(historyRows);

        if (historyError) {
          console.error(
            "Could not save video stats history:",
            historyError.code
          );

          return res.status(500).json({
            error: "Videos were synced, but their history could not be saved.",
            code: historyError.code,
            synced,
            pages
          });
        }

        synced += rows.length;
      }

      pages += 1;
      hasMore = Boolean(data.has_more);

      if (!hasMore) {
        break;
      }

      const nextCursor = data.cursor;

      if (
        nextCursor === undefined ||
        nextCursor === null ||
        seenCursors.has(String(nextCursor))
      ) {
        console.error(
          "TikTok pagination stopped: invalid or repeated cursor."
        );

        return res.status(502).json({
          error: "Pagination stopped because TikTok returned an invalid or repeated cursor.",
          synced,
          pages
        });
      }

      seenCursors.add(String(nextCursor));
      cursor = nextCursor;
    }

    return res.json({
      success: true,
      synced,
      pages,
      has_more: hasMore,
      message: hasMore
        ? "Sync reached the 100-page safety limit. Run sync again to continue."
        : "All available TikTok video pages were synchronized."
    });
  } catch (err) {
    console.error("Video sync failed:", err.message);
    return res.status(500).json({
      error: "Video synchronization failed."
    });
  }
});
app.get("/analyze-videos", async (req, res) => {
  try {
    if (!supabase) {
      return res.status(500).json({
        error: "Supabase is not configured."
      });
    }

    const { data: videos, error: videosError } = await supabase
      .from("tiktok_videos")
      .select(
        "video_id, title, description, view_count, like_count, comment_count, share_count"
      );

    if (videosError) {
      console.error("Could not load videos for analysis:", videosError.code);
      return res.status(500).json({
        error: "Could not load videos from Supabase."
      });
    }

    if (!videos || videos.length === 0) {
      return res.json({
        success: true,
        analyzed: 0,
        message: "No videos found. Sync videos first."
      });
    }

    const analyzedVideos = videos.map((video) => {
      const views = Number(video.view_count) || 0;
      const likes = Number(video.like_count) || 0;
      const comments = Number(video.comment_count) || 0;
      const shares = Number(video.share_count) || 0;
      const interactions = likes + comments + shares;

      const engagementRate =
        views > 0 ? (interactions / views) * 100 : null;

      return {
        video_id: video.video_id,
        title: video.title || null,
        description: video.description || null,
        views,
        likes,
        comments,
        shares,
        interactions,
        engagement_rate: engagementRate
      };
    });

    const validRates = analyzedVideos
      .map((video) => video.engagement_rate)
      .filter((rate) => rate !== null);

    const averageRate =
      validRates.length > 0
        ? validRates.reduce((sum, rate) => sum + rate, 0) /
          validRates.length
        : null;

    const rows = analyzedVideos.map((video) => {
      let performance = "insufficient_data";

      if (video.engagement_rate !== null && averageRate !== null) {
        if (video.engagement_rate > averageRate) {
          performance = "above_average";
        } else if (video.engagement_rate < averageRate) {
          performance = "below_average";
        } else {
          performance = "average";
        }
      }

      return {
        video_id: video.video_id,
        engagement_rate:
          video.engagement_rate === null
            ? null
            : Number(video.engagement_rate.toFixed(4)),
        analysis: {
          title: video.title,
          description: video.description,
          views: video.views,
          likes: video.likes,
          comments: video.comments,
          shares: video.shares,
          total_interactions: video.interactions,
          performance,
          dataset_average_engagement_rate:
            averageRate === null
              ? null
              : Number(averageRate.toFixed(4)),
          note:
            "Performance is compared with the average engagement rate of the currently imported videos. It is not a causal assessment."
        },
        analyzed_at: new Date().toISOString()
      };
    });

    const { error: saveError } = await supabase
      .from("video_analytics")
      .upsert(rows, { onConflict: "video_id" });

    if (saveError) {
      console.error("Could not save video analysis:", saveError.code);
      return res.status(500).json({
        error: "Could not save video analysis.",
        code: saveError.code
      });
    }

    return res.json({
      success: true,
      analyzed: rows.length,
      average_engagement_rate:
        averageRate === null ? null : Number(averageRate.toFixed(4)),
      videos: analyzedVideos
        .sort(
          (a, b) =>
            (b.engagement_rate ?? -1) - (a.engagement_rate ?? -1)
        )
        .map((video) => ({
          video_id: video.video_id,
          title: video.title,
          views: video.views,
          engagement_rate:
            video.engagement_rate === null
              ? null
              : Number(video.engagement_rate.toFixed(4))
        }))
    });
  } catch (err) {
    console.error("Video analysis failed:", err.message);
    return res.status(500).json({
      error: "Video analysis failed."
    });
  }
});

app.get("/video-growth", async (req, res) => {
  try {
    if (!supabase) {
      return res.status(500).json({
        error: "Supabase is not configured."
      });
    }

    let history = [];
    let start = 0;
    const pageSize = 1000;

    while (true) {
      const { data, error } = await supabase
        .from("video_stats_history")
        .select(
          "video_id, recorded_at, view_count, like_count, comment_count, share_count"
        )
        .order("video_id", { ascending: true })
        .order("recorded_at", { ascending: false })
        .range(start, start + pageSize - 1);

      if (error) {
        console.error("Could not load stats history:", error.code);
        return res.status(500).json({
          error: "Could not load video statistics history."
        });
      }

      history = history.concat(data || []);

      if (!data || data.length < pageSize) {
        break;
      }

      start += pageSize;
    }

    const latestTwo = new Map();

    for (const snapshot of history) {
      if (!latestTwo.has(snapshot.video_id)) {
        latestTwo.set(snapshot.video_id, []);
      }

      const snapshots = latestTwo.get(snapshot.video_id);

      if (snapshots.length < 2) {
        snapshots.push(snapshot);
      }
    }

    const growth = [];

    for (const [videoId, snapshots] of latestTwo.entries()) {
      if (snapshots.length < 2) continue;

      const latest = snapshots[0];
      const previous = snapshots[1];

      const viewsGained =
        Number(latest.view_count) - Number(previous.view_count);
      const likesGained =
        Number(latest.like_count) - Number(previous.like_count);
      const commentsGained =
        Number(latest.comment_count) - Number(previous.comment_count);
      const sharesGained =
        Number(latest.share_count) - Number(previous.share_count);

      const interactionsGained =
        likesGained + commentsGained + sharesGained;

      growth.push({
        video_id: videoId,
        latest_snapshot: latest.recorded_at,
        previous_snapshot: previous.recorded_at,
        views: Number(latest.view_count),
        views_gained: viewsGained,
        likes_gained: likesGained,
        comments_gained: commentsGained,
        shares_gained: sharesGained,
        interactions_gained: interactionsGained,
        engagement_rate_between_snapshots:
          viewsGained > 0
            ? Number(
                ((interactionsGained / viewsGained) * 100).toFixed(4)
              )
            : null
      });
    }

    growth.sort((a, b) => b.views_gained - a.views_gained);

    return res.json({
      success: true,
      videos_compared: growth.length,
      note:
        "Growth is measured between the two latest saved snapshots. Negative changes can occur if TikTok revises statistics.",
      top_by_view_growth: growth.slice(0, 50)
    });
  } catch (err) {
    console.error("Video growth analysis failed:", err.message);
    return res.status(500).json({
      error: "Video growth analysis failed."
    });
  }
});
app.get("/stored-videos", async (req, res) => {
  try {
    if (!supabase) {
      return res.status(500).json({
        error: "Supabase is not configured."
      });
    }

    const allVideos = [];
    const pageSize = 1000;
    let start = 0;

    while (true) {
      const { data, error } = await supabase
        .from("tiktok_videos")
        .select(
          "video_id, title, description, create_time, duration, share_url, cover_image_url, view_count, like_count, comment_count, share_count"
        )
        .order("create_time", { ascending: false })
        .range(start, start + pageSize - 1);

      if (error) {
        console.error("Could not load stored videos:", error.code);
        return res.status(500).json({
          error: "Could not load stored videos."
        });
      }

      allVideos.push(...(data || []));

      if (!data || data.length < pageSize) break;
      start += pageSize;
    }

    return res.json({
      success: true,
      count: allVideos.length,
      videos: allVideos
    });
  } catch (err) {
    console.error("Stored videos request failed:", err.message);
    return res.status(500).json({
      error: "Could not load stored videos."
    });
  }
});

async function fetchRecentFootballNews(focus = "") {
   const feeds = [
    {
      name: "GSP",
      url: "https://www.gsp.ro/rss.xml"
    },
    {
      name: "BBC Sport",
      url: "https://feeds.bbci.co.uk/sport/football/rss.xml"
    }
  ];

  if (focus && focus.trim()) {
    const searchParams = new URLSearchParams({
      q: `${focus.trim()} when:7d`,
      hl: "ro",
      gl: "RO",
      ceid: "RO:ro"
    });

    feeds.push({
      name: "Google News",
      url: `https://news.google.com/rss/search?${searchParams.toString()}`
    });
  }
  function cleanText(value = "") {
    return value
      .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
      .replace(/<[^>]*>/g, "")
      .replace(/&amp;/g, "&")
      .replace(/&quot;/g, '"')
      .replace(/&#39;|&apos;/g, "'")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .trim();
  }

  function getTag(item, tag) {
    const match = item.match(
      new RegExp(
        `<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}\\s*>`,
        "i"
      )
    );

    return match ? cleanText(match[1]) : "";
  }

  const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;

  const results = await Promise.allSettled(
    feeds.map(async (feed) => {
      const response = await fetch(feed.url, {
        signal: AbortSignal.timeout(10000),
        headers: {
          "User-Agent": "FootballAIStrategist/1.0"
        }
      });

      if (!response.ok) {
        throw new Error(
          `${feed.name} RSS returned ${response.status}`
        );
      }

      const xml = await response.text();
      const items = xml.match(/<item(?:\s[^>]*)?>[\s\S]*?<\/item>/gi) || [];

      return items.map((item) => {
        const title = getTag(item, "title");
        const link = getTag(item, "link");
        const publishedAt = getTag(item, "pubDate");
        const description = getTag(item, "description");
        const publishedTimestamp = Date.parse(publishedAt);

     
return {
  source: feed.name,
  title,
  url: link,
  published_at: publishedAt,
  published_at_source: "rss_feed",
  original_publication_date_verified: false,
  description: description.slice(0, 500),
  publishedTimestamp
};

      }).filter((article) =>
        article.title &&
        article.url.startsWith("https://") &&
        Number.isFinite(article.publishedTimestamp) &&
        article.publishedTimestamp >= cutoff &&
        article.publishedTimestamp <= Date.now()
      );
    })
  );


  const news = results
    .filter((result) => result.status === "fulfilled")
    .flatMap((result) => result.value);

  const uniqueNews = [
    ...new Map(news.map((item) => [item.url, item])).values()
  ];

  const sortedNews = uniqueNews.sort((a, b) => {
    if (focus && focus.trim()) {
      const aIsGoogleNews = a.source === "Google News";
      const bIsGoogleNews = b.source === "Google News";

      if (aIsGoogleNews && !bIsGoogleNews) return -1;
      if (!aIsGoogleNews && bIsGoogleNews) return 1;
    }

    return b.publishedTimestamp - a.publishedTimestamp;
  });

  return sortedNews
    .slice(0, 20)
    .map(({ publishedTimestamp, ...article }) => article);
}

// AI Content Strategist: generates ideas from real Supabase metrics.
app.post("/ai-content-strategist", async (req, res) => {
  try {
    if (!supabase) {
      return res.status(500).json({
        error: "Supabase is not configured."
      });
    }

    if (!process.env.GEMINI_API_KEY) {
  return res.status(503).json({
    error: "GEMINI_API_KEY is not configured on the backend. Add it to Render environment variables."
  });
}

    const requestedFocus =
      typeof req.body?.focus === "string"
        ? req.body.focus.trim().slice(0, 180)
        : "";

    const allVideos = [];
    const pageSize = 1000;
    let start = 0;

    while (true) {
      const { data, error } = await supabase
        .from("tiktok_videos")
        .select(
          "video_id, title, description, create_time, duration, share_url, view_count, like_count, comment_count, share_count"
        )
        .order("create_time", { ascending: false })
        .range(start, start + pageSize - 1);

      if (error) {
        console.error(
          "AI strategist could not load Supabase videos:",
          error.code
        );

        return res.status(500).json({
          error: "Could not load video statistics from Supabase."
        });
      }

      allVideos.push(...(data || []));

      if (!data || data.length < pageSize) break;
      start += pageSize;
    }

    if (!allVideos.length) {
      return res.status(400).json({
        error: "No saved videos found. Sync TikTok first."
      });
    }

    const metricVideos = allVideos.map((v) => {
      const views = Number(v.view_count) || 0;
      const likes = Number(v.like_count) || 0;
      const comments = Number(v.comment_count) || 0;
      const shares = Number(v.share_count) || 0;

      return {
        title: (
          v.title ||
          v.description ||
          "Videoclip fără titlu"
        ).slice(0, 220),
        description: (v.description || "").slice(0, 300),
        duration_seconds: v.duration ?? null,
        views,
        likes,
        comments,
        shares,
        engagement_rate_percent:
          views > 0
            ? Number(
                (
                  ((likes + comments + shares) / views) *
                  100
                ).toFixed(3)
              )
            : null,
        created_at: v.create_time || null,
        url: v.share_url || null
      };
    });

    const valid = metricVideos.filter((v) => v.views > 0);

    const totalViews = valid.reduce(
      (sum, v) => sum + v.views,
      0
    );

    const totalInteractions = valid.reduce(
      (sum, v) => sum + v.likes + v.comments + v.shares,
      0
    );

    const averageVideoEngagement = valid.length
      ? valid.reduce(
          (sum, v) => sum + (v.engagement_rate_percent || 0),
          0
        ) / valid.length
      : null;

    const topByViews = [...valid]
      .sort((a, b) => b.views - a.views)
      .slice(0, 15);

    const topByEngagement = [...valid]
      .filter((v) => v.engagement_rate_percent !== null)
      .sort(
        (a, b) =>
          b.engagement_rate_percent -
          a.engagement_rate_percent
      )
      .slice(0, 15);

    // Historical reference supplied by the creator.
    // These are NOT live Supabase statistics.
    const historicalExamples = [
      {
        title: "Efectul Cristiano Ronaldo",
        views: 239000,
        likes: 9142,
        comments: 279,
        shares: 413,
        saves: 570,
        followers_gained: 112,
        duration_seconds: 15,
        followers_per_1000_views: 0.469
      },
      {
        title: "Cariera de fotbalist — Episodul 1",
        views: 139000,
        likes: 2161,
        comments: 46,
        shares: 39,
        saves: 227,
        followers_gained: 125,
        duration_seconds: 177,
        followers_per_1000_views: 0.899
      },
      {
        title: "Jucătorii care au refuzat Real Madrid",
        views: 101000,
        likes: 2206,
        comments: 129,
        shares: 48,
        saves: 144,
        followers_gained: 80,
        duration_seconds: 73,
        followers_per_1000_views: 0.792
      },
      {
        title: "Top 10 tineri jucători care vor domina fotbalul în 5 ani",
        views: 26000,
        likes: 448,
        comments: 33,
        shares: 19,
        saves: 41,
        followers_gained: 17,
        duration_seconds: 112,
        followers_per_1000_views: 0.654
      },
      {
        title: "Top 10 momente World Cup — Partea 2",
        views: 29000,
        likes: 868,
        comments: 22,
        shares: 36,
        saves: 39,
        followers_gained: 11,
        duration_seconds: 66,
        followers_per_1000_views: 0.379
      }
    ];

const systemPrompt = `
Ești Football AI Strategist, un strateg editorial specializat în creșterea unui cont TikTok de fotbal din România.
OBIECTIV
Propune exact 5 idei concrete, filmabile și distincte, optimizate pentru atragerea de urmăritori noi la 1.000 de vizualizări (F1000).
REGULA PRINCIPALĂ: SPECIFICITATE
1. Fiecare idee trebuie să aibă un subiect clar și identificabil.
2. Pentru o poveste despre un fotbalist, numește jucătorul în titlu sau în primele două propoziții ale scenariului.
3. Nu folosi formulări vagi precum „noua speranță a României”, „un talent irosit”, „un club românesc” sau „un meci istoric” fără să identifici persoana, clubul ori partida.
4. Dacă propui o comparație cu Adrian Mutu, numește fotbalistul comparat cu Mutu și explică precis asemănarea. Dacă nu poți identifica un caz real și relevant, alege alt subiect.
5. Fiecare scenariu trebuie să conțină informație concretă, nu doar promisiuni, clișee sau apeluri la follow.
6. Nu inventa citate, transferuri, conflicte, statistici, meciuri, rezultate, trofee sau detalii biografice.
7. Nu transforma o ipoteză editorială într-un fapt.
**REGULI PENTRU SCENARII — DURATĂ ȘI CALITATE**

8. **Durata scenariului trebuie adaptată subiectului:**

   - Știri rapide, transferuri și declarații: 15–25 de secunde.
   - Comparații, opinii argumentate și controverse: 30–45 de secunde.
   - Povești despre fotbaliști, topuri și analize: 45–60 de secunde.
   - Nu lungi artificial scenariul pentru a atinge o durată fixă.

9. **Scrie textul integral pentru narare.** Scenariul trebuie să poată fi citit direct la înregistrare, fără ca utilizatorul să fie nevoit să inventeze propoziții suplimentare.

10. **Construiește scenariul într-o succesiune logică:**

- HOOK: o întrebare, o afirmație surprinzătoare sau un contrast concret care captează atenția.
- CONTEXT: prezintă rapid fotbalistul, echipa, meciul sau evenimentul despre care vorbești.
- DEZVOLTARE: explică informația principală folosind detalii concrete, exemple, comparații relevante sau date verificate.
- MOMENT FORTE: oferă concluzia, contrastul sau detaliul cel mai interesant al poveștii.
- FINAL: încheie natural, eventual cu o întrebare specifică ce încurajează comentariile.

11. **Nu limita scenariul la 4 propoziții scurte.** Dezvoltă ideea suficient pentru durata aleasă, folosind propoziții naturale și informații care adaugă valoare. Nu impune un număr fix de puncte sau paragrafe.

12. **Adaugă indicații de montaj pentru fiecare secvență:** intervalul aproximativ, imaginile recomandate, textul scurt afișat pe ecran și momentul schimbării cadrului. Indicațiile de montaj trebuie separate clar de textul pentru narare.

13. **Evită umplutura:** nu repeta aceeași informație în mai multe formulări, nu folosi introduceri lungi și nu adăuga apeluri generice la follow doar pentru a prelungi clipul.

14. **Păstrează acuratețea factuală:** nu inventa statistici, rezultate, citate sau detalii biografice. Dacă o afirmație relevantă nu poate fi verificată din sursele disponibile, marcheaz-o explicit pentru verificare și nu o prezenta drept fapt confirmat.

15. **Optimizează pentru F1000:** prioritizează un început care oprește scroll-ul, informații care mențin interesul, o concluzie memorabilă și un motiv concret pentru care spectatorul ar dori să urmărească în continuare contul. Nu garanta un anumit număr de urmăritori câștigați.

16. **Adaptează structura la subiect.** Nu transforma toate ideile în aceeași poveste cu aceleași cinci etape mecanice. Ordinea și ritmul pot varia dacă asta face scenariul mai captivant.

VERIFICAREA INFORMAȚIILOR
8. Datele live din Supabase pot susține numai afirmații despre metricile prezente în payload.
9. Exemplele istorice sunt date furnizate separat, nu statistici live.
10. Nu pretinde că ai verificat o informație dacă nu ai o sursă care o confirmă.
11. Pentru fiecare idee, enumeră afirmațiile factuale ce trebuie verificate înainte de publicare.
12. Pentru afirmații importante, indică sursa oficială sau sursa credibilă care ar trebui consultată. Nu inventa URL-uri, articole sau citate.
13. Folosește evidence_type = "date_live" numai pentru concluzii susținute direct de datele live furnizate.
14. Dacă un subiect necesită verificări, marchează-l ca neverificat și precizează ce informații lipsesc.
15. Dacă nu poți propune o idee concretă fără să inventezi fapte, înlocuiește-o.
STRATEGIE EDITORIALĂ
16. Obiectivul principal este F1000. Datele live nu conțin followers_gained, saves, retention, completion_rate sau profile_visits.
17. Nu susține că un format este câștigător pe baza unui singur clip.
18. Compară formate numai când există suficiente clipuri comparabile; cinci clipuri reprezintă un prag orientativ, nu o garanție statistică.
19. Recomandă teste care schimbă câte o singură variabilă.
20. Preferă subiecte relevante pentru România, cu potențial de curiozitate, dezbatere, distribuire și continuare în serie.
21. Evită să generezi cinci variante aproape identice ale aceleiași idei.
SCOR STRATEGIC
Acordă fiecărei componente o notă între 1 și 5:
- follower_attraction: 35%
- romanian_relevance: 20%
- novelty: 15%
- verifiability: 15%
- shareability: 15%
Calculează:
(35*F + 20*R + 15*N + 15*V + 15*D) / 5
Scorul trebuie să fie între 20 și 100. Nu îl prezenta drept probabilitate de viralizare sau garanție de succes.
ACTUALITATE ȘI CĂUTARE WEB

1. Înainte să generezi ideile, caută pe Google știri și evenimente
   relevante din fotbalul românesc și internațional.

2. Prioritizează evenimentele din ultimele 7 zile față de poveștile
   istorice. Folosește data curentă reală, nu date presupuse.

3. Cel puțin 3 dintre cele 5 idei trebuie să pornească de la evenimente
   recente, dacă există suficiente subiecte relevante și verificabile.
   Nu inventa noutăți pentru a îndeplini această cerință.

4. Pentru fiecare știre, identifică evenimentul, data, persoanele
   sau cluburile implicate și sursele web consultate.

5. Include în fiecare idee un câmp "sources", cu URL-urile reale
   ale surselor folosite, și un câmp "published_at" pentru data
   publicării știrii sau articolului, dacă este disponibilă.

6. Nu confunda data publicării unui articol cu data evenimentului.

7. Nu prezenta o informație drept verificată dacă sursele găsite
   nu o susțin. Dacă nu găsești suficiente dovezi, exclude subiectul.

8. Nu folosi automat datele istorice din Supabase ca știri actuale.
   Utilizează-le separat, doar pentru analiza performanței conținutului.

9. Dacă nu există suficiente știri recente verificabile, explică
   acest lucru și completează cu idei istorice clar etichetate.
CATEGORII
Serii recurente, topuri și clasamente, controverse și dezbateri, știri actuale, povești istorice, analiză tactică și profiluri de jucători.
FORMATUL FIECĂREI IDEI
- title: titlu specific, cu subiect identificabil
- category
- hook: introducere concretă, gata de rostit
- script: 4–6 replici cu informație reală și progresie narativă
- video_title
- hashtags
- justification: explică de ce merită testată, fără a inventa rezultate
- score
- score_breakdown
- evidence_type
- verification_needed: afirmații concrete de verificat
- test_plan
- metrics_to_track
Răspunde în română. Generează exact 5 idei distincte.
`;
const recentFootballNews = await fetchRecentFootballNews(requestedFocus);
console.log(
  `Football RSS: ${recentFootballNews.length} articole recente găsite.`
);
    const userPayload = {
     focus: requestedFocus || "",
      live_dataset: {
        source: "Supabase tiktok_videos",
        total_videos: allVideos.length,
        videos_with_views: valid.length,
        total_views: totalViews,
        total_interactions: totalInteractions,
        weighted_engagement_rate_percent:
          totalViews > 0
            ? Number(
                ((totalInteractions / totalViews) * 100).toFixed(3)
              )
            : null,
        mean_video_engagement_rate_percent:
          averageVideoEngagement === null
            ? null
            : Number(averageVideoEngagement.toFixed(3)),
        top_by_views: topByViews,
        top_by_engagement: topByEngagement,
        unavailable_metrics: [
          "followers_gained",
          "saves",
          "retention",
          "completion_rate",
          "profile_visits",
          "traffic_sources"
        ]
      },
     recent_news: recentFootballNews,
      historical_examples_not_live: historicalExamples
    };

   
    const geminiModel =
  process.env.GEMINI_MODEL || "gemini-3.8-flash";

    const prompt = `
Analizează datele următoare și generează exact 5 idei distincte.
SUBIECTUL PREFERAT:
- Citește câmpul "focus" din datele primite.
- Dacă "focus" conține un subiect introdus de utilizator, toate cele 5 idei trebuie să fie direct relevante pentru acel subiect.
- Dacă "focus" nu este gol, include în "justification" explicația concretă a legăturii fiecărei idei cu subiectul solicitat.
- Toate cele 5 idei trebuie să fie distincte între ele, dar să respecte același subiect preferat.
- Dacă subiectul nu are suficiente știri recente în recent_news, completează cu idei istorice sau evergreen despre acel subiect, fără să inventezi actualitate.
- Nu folosi știri despre alte subiecte doar pentru a completa numărul de idei.
- Nu devia către alte subiecte de fotbal doar pentru că au mai multe știri disponibile.
- Pentru un jucător, concentrează ideile pe acel jucător: știri recente verificate, performanțe, carieră, recorduri și povești istorice relevante.
- Pentru o competiție, concentrează ideile pe acea competiție, echipele participante, jucători și evenimente relevante.
- Respectă în continuare regulile privind sursele, actualitatea și verificarea informațiilor.
- Dacă "focus" este gol, folosește strategia generală și datele contului pentru a selecta ideile.

ACTUALITATE ȘI SURSE:
- Analizează articolele din recent_news înainte să alegi ideile.
- Dacă focus nu este gol, toate cele 5 idei trebuie să fie direct relevante pentru subiectul solicitat.
- Folosește o știre recentă numai dacă un articol din recent_news susține direct subiectul și afirmațiile principale ale ideii.
- Nu folosi articole despre alți jucători sau evenimente doar pentru că apar în același flux RSS.
- Pentru fiecare idee bazată pe o știre, evidence_type trebuie să fie "recent_news", iar sources trebuie să conțină cel puțin un articol relevant din recent_news.
- Copiază titlul și URL-ul exact al articolului din recent_news. Nu inventa și nu modifica URL-uri.
- Data din RSS este data declarată de feed, nu o dată originală verificată independent.
- Nu pretinde că ai verificat data originală sau conținutul paginii articolului.
- Dacă folosești o sursă RSS, menționează în verification_needed că data originală trebuie verificată înainte de publicare.
- Dacă nu există suficiente articole relevante, completează cu idei istorice despre același subiect.
- Pentru ideile istorice, folosește evidence_type: "historical", sources: [] și published_at: null.
- Nu inventa evenimente, statistici, date sau surse.
- Generează exact 5 idei distincte.


Returnează exclusiv un obiect JSON cu această structură:
{
  "summary": "Rezumatul analizei",
  "ideas": [
    {
      "title": "Titlul ideii",
      "category": "Categoria",
      "hook": "Hook-ul pentru primele secunde",
      "script": ["Replica 1", "Replica 2", "Replica 3"],
      "video_title": "Titlul clipului",
      "hashtags": ["#fotbal", "#romania"],
      "justification": "De ce merită testată ideea",
      "score": 80,
      "score_breakdown": {
        "follower_attraction": 4,
        "romanian_relevance": 5,
        "novelty": 4,
        "verifiability": 4,
        "shareability": 4
      },
      "evidence_type": "recent_news",
      "verification_needed": [],
      "sources": [
        {
          "title": "Titlul exact al articolului din recent_news",
          "url": "URL-ul exact al articolului din recent_news",
          "published_at": "Data publicării din recent_news"
        }
      ],
      "published_at": "Data publicării articolului principal sau null",
      "test_plan": "Cum testăm ideea",
      "metrics_to_track": ["views", "likes", "comments", "shares"]
    }
  ]
}

REGULI PENTRU SURSE:
- Folosește numai articole existente în recent_news.
- Copiază exact titlul, URL-ul și data publicării.
- Nu inventa și nu modifica URL-uri.
- Pentru ideile istorice folosește "evidence_type": "historical"
  și "sources": [].
- Pentru ideile de actualitate folosește "evidence_type": "recent_news".
- Dacă nu există un articol relevant, nu prezenta ideea drept știre.
- Nu pretinde că un articol confirmă detalii care nu apar în titlul
  sau descrierea lui.

Scorul trebuie să respecte ponderile din instrucțiunile sistemului.
Nu inventa statistici. Separă datele live de exemplele istorice.
Răspunde în limba română.

DATE:
${JSON.stringify(userPayload)}
`;

 
let response;

const maxAttempts = 4;
const retryableStatuses = [429, 500, 502, 503, 504];

for (let attempt = 0; attempt < maxAttempts; attempt++) {
  response = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/${geminiModel}:generateContent`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-goog-api-key": process.env.GEMINI_API_KEY
      },
      body: JSON.stringify({
        systemInstruction: {
          parts: [{ text: systemPrompt }]
        },
        contents: [
          {
            role: "user",
            parts: [{ text: prompt }]
          }
        ],
        generationConfig: {
          temperature: 0.7,
          responseMimeType: "application/json"
        }
      })
    }
  );

  if (response.ok) {
    break;
  }

  if (
    !retryableStatuses.includes(response.status) ||
    attempt === maxAttempts - 1
  ) {
    break;
  }

  const delayMs = 1000 * Math.pow(2, attempt);

  console.warn(
    `Gemini API returned ${response.status}. ` +
    `Retry ${attempt + 1}/${maxAttempts - 1} in ${delayMs}ms.`
  );

  await response.text();
  await new Promise(resolve => setTimeout(resolve, delayMs));
}


 if (!response.ok) {
  const errorText = await response.text();

  console.error("Gemini API request failed:", {
    status: response.status,
    details: errorText.slice(0, 1000)
  });

  return res.status(502).json({
    error:
      response.status === 400
        ? "Gemini rejected the request. Check the model and request format."
        : response.status === 401 || response.status === 403
          ? "Gemini API key is invalid or does not have access."
          : response.status === 429
            ? "Gemini API quota or rate limit reached. Check your Google AI Studio limits."
            : "The AI service could not generate ideas."
  });
}
    const result = await response.json();

const content = (result.candidates?.[0]?.content?.parts || [])
  .map(part => part.text || "")
  .join("");

    if (!content) {
      return res.status(502).json({
        error: "The AI service returned an empty response."
      });
    }

    let generated;

try {
  generated = JSON.parse(content);
} catch {
  return res.status(502).json({
    error: "The AI service returned invalid JSON. Try again."
  });
}

if (!generated || !Array.isArray(generated.ideas)) {
  return res.status(502).json({
    error: "The AI response did not contain a valid ideas array."
  });
}

generated.ideas = generated.ideas.map((idea) => ({
  ...idea,
  sources: Array.isArray(idea.sources) ? idea.sources : [],
  published_at: idea.published_at || null
}));

    // Validate generated sources against the actual RSS articles.
 
const trustedNews = new Map(
  recentFootballNews.map((article) => [
    article.url,
    article
  ])
);

console.log(
  "AI SOURCES DEBUG:",
  JSON.stringify(
    (generated.ideas || []).map((idea) => ({
      title: idea.title,
      evidence_type: idea.evidence_type,
      sources: idea.sources
    })),
    null,
    2
  )
);

console.log(
  "RSS URLS DEBUG:",
  JSON.stringify(
    recentFootballNews.slice(0, 5).map((article) => ({
      title: article.title,
      url: article.url
    })),
    null,
    2
  )
);

generated.ideas = (generated.ideas || []).map((idea) => {
  const validSources = Array.isArray(idea.sources)
    ? idea.sources
        .filter((source) =>
          source &&
          typeof source.url === "string" &&
          trustedNews.has(source.url)
        )
        .map((source) => {
          const article = trustedNews.get(source.url);

          return {
            title: article.title,
            url: article.url,
            published_at: article.published_at,
            published_at_source: "rss_feed",
            original_publication_date_verified: false
          };
        })
    : [];

  const hasInvalidSources =
    Array.isArray(idea.sources) &&
    idea.sources.length !== validSources.length;

  const hasUnverifiedOriginalDate = validSources.length > 0;

  const verificationNeeded = [
    ...(Array.isArray(idea.verification_needed)
      ? idea.verification_needed
      : []),
    ...(hasInvalidSources
      ? ["Unele surse furnizate de AI nu au fost găsite în RSS."]
      : []),
    ...(hasUnverifiedOriginalDate
      ? ["Data din RSS nu confirmă data publicării originale. Verifică articolul înainte de a-l prezenta ca știre recentă."]
      : [])
  ];

  return {
    ...idea,
    sources: validSources,
    published_at:
      validSources.length > 0
        ? validSources[0].published_at
        : null,
    verification_needed: verificationNeeded
  };
});

    const ideasWithoutValidNewsSources = generated.ideas.filter(
      (idea) =>
        idea.evidence_type === "recent_news" &&
        (!Array.isArray(idea.sources) || idea.sources.length === 0)
    );

    for (const idea of ideasWithoutValidNewsSources) {
      idea.evidence_type = "historical";
      idea.sources = [];
      idea.published_at = null;
      idea.verification_needed = [
        ...(Array.isArray(idea.verification_needed)
          ? idea.verification_needed
          : []),
        "Ideea nu are o sursă RSS validată; trateaz-o ca idee istorică și verifică informațiile înainte de publicare."
      ];
    }

    if (!Array.isArray(generated.ideas) || generated.ideas.length !== 5) {
      return res.status(502).json({
        error: "The AI response did not contain exactly five ideas. Try again."
      });
    }

    return res.json({
      success: true,
      generated_at: new Date().toISOString(),
    model: geminiModel,
      dataset_summary: {
        total_videos: allVideos.length,
        videos_with_views: valid.length,
        total_views: totalViews,
        weighted_engagement_rate_percent:
          totalViews > 0
            ? Number(
                ((totalInteractions / totalViews) * 100).toFixed(3)
              )
            : null,
        mean_video_engagement_rate_percent:
          averageVideoEngagement === null
            ? null
            : Number(averageVideoEngagement.toFixed(3))
      },
      ...generated
    });
  } catch (err) {
    console.error("AI Content Strategist failed:", err.message);

    return res.status(500).json({
      error: "AI Content Strategist encountered an unexpected error."
    });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Football AI Strategist listening on port ${PORT}`);
});
