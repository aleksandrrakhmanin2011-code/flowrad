const API_BASE = "https://idarkmeteo.host/api/v1";

const SESSION_COOKIE = "flowrad_session";
const ADMIN_COOKIE = "flowrad_admin";

const SESSION_MAX_AGE = 60 * 60 * 24 * 7; // 7 дней
const ADMIN_MAX_AGE = 60 * 60 * 24 * 7;

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Cache-Control": "no-store"
};


// ============================================================
// BASIC HELPERS
// ============================================================

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders
    }
  });
}

function html(data, status = 200, extraHeaders = {}) {
  return new Response(data, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders
    }
  });
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";

  const parts = cookie.split(";");

  for (const part of parts) {
    const [key, ...valueParts] = part.trim().split("=");

    if (key === name) {
      return decodeURIComponent(valueParts.join("="));
    }
  }

  return null;
}

function setCookie(name, value, maxAge) {
  return `${name}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`;
}

function deleteCookie(name) {
  return `${name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}

function randomString(length = 32) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);

  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function randomPassword(length = 16) {
  const chars =
    "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);

  let result = "";

  for (let i = 0; i < length; i++) {
    result += chars[bytes[i] % chars.length];
  }

  return result;
}


// ============================================================
// HASH
// ============================================================

async function sha256(value) {
  const data = new TextEncoder().encode(value);

  const hash = await crypto.subtle.digest("SHA-256", data);

  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}


// ============================================================
// HMAC
// ============================================================

async function hmac(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(value)
  );

  return Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function createSession(passwordId, env) {
  const timestamp = Date.now().toString();

  const payload = `${passwordId}.${timestamp}`;

  const signature = await hmac(
    payload,
    env.ADMIN_TOKEN_SECRET
  );

  return `${payload}.${signature}`;
}

async function verifySession(token, env) {
  if (!token) {
    return null;
  }

  const parts = token.split(".");

  if (parts.length !== 3) {
    return null;
  }

  const [passwordId, timestamp, signature] = parts;

  const time = Number(timestamp);

  if (!Number.isFinite(time)) {
    return null;
  }

  if (Date.now() - time > SESSION_MAX_AGE * 1000) {
    return null;
  }

  const payload = `${passwordId}.${timestamp}`;

  const expected = await hmac(
    payload,
    env.ADMIN_TOKEN_SECRET
  );

  if (signature !== expected) {
    return null;
  }

  return {
    passwordId: Number(passwordId),
    timestamp: time
  };
}


async function createAdminSession(env) {
  const timestamp = Date.now().toString();

  const payload = `admin.${timestamp}`;

  const signature = await hmac(
    payload,
    env.ADMIN_TOKEN_SECRET
  );

  return `${payload}.${signature}`;
}

async function verifyAdminSession(token, env) {
  if (!token) {
    return false;
  }

  const parts = token.split(".");

  if (parts.length !== 3) {
    return false;
  }

  const [type, timestamp, signature] = parts;

  if (type !== "admin") {
    return false;
  }

  const time = Number(timestamp);

  if (!Number.isFinite(time)) {
    return false;
  }

  if (Date.now() - time > ADMIN_MAX_AGE * 1000) {
    return false;
  }

  const payload = `admin.${timestamp}`;

  const expected = await hmac(
    payload,
    env.ADMIN_TOKEN_SECRET
  );

  return signature === expected;
}


// ============================================================
// DATABASE INITIALIZATION
// ============================================================

async function ensureDatabase(env) {
  if (!env.DB) {
    throw new Error("D1 binding DB is not configured");
  }

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS access_passwords (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      password_hash TEXT NOT NULL UNIQUE,
      active INTEGER NOT NULL DEFAULT 1,
      created_at INTEGER NOT NULL,
      revoked_at INTEGER
    )
  `).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS visitors (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      password_id INTEGER,
      ip TEXT,
      user_agent TEXT,
      path TEXT,
      created_at INTEGER NOT NULL
    )
  `).run();
}


// ============================================================
// ACCESS PASSWORD
// ============================================================

async function findPassword(env, password) {
  const hash = await sha256(password);

  return await env.DB
    .prepare(`
      SELECT id, password_hash, active
      FROM access_passwords
      WHERE password_hash = ? AND active = 1
      LIMIT 1
    `)
    .bind(hash)
    .first();
}


// ============================================================
// VISITOR LOG
// ============================================================

async function logVisit(request, env, passwordId = null) {
  try {
    const ip =
      request.headers.get("CF-Connecting-IP") ||
      request.headers.get("X-Forwarded-For") ||
      "";

    const userAgent =
      request.headers.get("User-Agent") || "";

    const url = new URL(request.url);

    await env.DB
      .prepare(`
        INSERT INTO visitors
        (
          password_id,
          ip,
          user_agent,
          path,
          created_at
        )
        VALUES (?, ?, ?, ?, ?)
      `)
      .bind(
        passwordId,
        ip,
        userAgent,
        url.pathname,
        Date.now()
      )
      .run();
  } catch (error) {
    console.error("Visitor log error:", error);
  }
}


// ============================================================
// AUTH CHECK
// ============================================================

async function requireUser(request, env) {
  const token = getCookie(request, SESSION_COOKIE);

  if (!token) {
    return null;
  }

  const session = await verifySession(token, env);

  if (!session) {
    return null;
  }

  const password = await env.DB
    .prepare(`
      SELECT id, active
      FROM access_passwords
      WHERE id = ?
      LIMIT 1
    `)
    .bind(session.passwordId)
    .first();

  if (!password || !password.active) {
    return null;
  }

  return session;
}


async function requireAdmin(request, env) {
  const cookieToken = getCookie(request, ADMIN_COOKIE);

  if (
    await verifyAdminSession(cookieToken, env)
  ) {
    return true;
  }

  const authorization =
    request.headers.get("Authorization") || "";

  if (authorization.startsWith("Bearer ")) {
    const token = authorization.slice(7);

    if (
      await verifyAdminSession(token, env)
    ) {
      return true;
    }
  }

  return false;
}


// ============================================================
// LOGIN
// ============================================================

async function handleLogin(request, env) {
  await ensureDatabase(env);

  let body = {};

  try {
    body = await request.json();
  } catch {
    body = {};
  }

  const password =
    typeof body.password === "string"
      ? body.password.trim()
      : "";

  if (!password) {
    return json(
      {
        error: "Password is required"
      },
      400,
      CORS_HEADERS
    );
  }

  const record =
    await findPassword(env, password);

  if (!record) {
    return json(
      {
        error: "Invalid password"
      },
      401,
      CORS_HEADERS
    );
  }

  const session =
    await createSession(record.id, env);

  await logVisit(
    request,
    env,
    record.id
  );

  return json(
    {
      success: true,
      authenticated: true
    },
    200,
    {
      ...CORS_HEADERS,
      "Set-Cookie": setCookie(
        SESSION_COOKIE,
        session,
        SESSION_MAX_AGE
      )
    }
  );
}


// ============================================================
// CHECK SESSION
// ============================================================

async function handleAccessCheck(request, env) {
  await ensureDatabase(env);

  const session =
    await requireUser(request, env);

  return json(
    {
      authenticated: !!session
    },
    200,
    CORS_HEADERS
  );
}


// ============================================================
// LOGOUT
// ============================================================

async function handleLogout() {
  return json(
    {
      success: true
    },
    200,
    {
      ...CORS_HEADERS,
      "Set-Cookie": deleteCookie(
        SESSION_COOKIE
      )
    }
  );
}


// ============================================================
// ADMIN LOGIN
// ============================================================

async function handleAdminLogin(request, env) {
  if (!env.ADMIN_PASSWORD) {
    return json(
      {
        error:
          "ADMIN_PASSWORD secret is not configured"
      },
      500,
      CORS_HEADERS
    );
  }

  let body = {};

  try {
    body = await request.json();
  } catch {
    body = {};
  }

  const password =
    typeof body.password === "string"
      ? body.password
      : "";

  if (password !== env.ADMIN_PASSWORD) {
    return json(
      {
        error: "Invalid admin password"
      },
      401,
      CORS_HEADERS
    );
  }

  const session =
    await createAdminSession(env);

  return json(
    {
      success: true,
      authenticated: true
    },
    200,
    {
      ...CORS_HEADERS,
      "Set-Cookie": setCookie(
        ADMIN_COOKIE,
        session,
        ADMIN_MAX_AGE
      )
    }
  );
}


// ============================================================
// ADMIN LOGOUT
// ============================================================

async function handleAdminLogout() {
  return json(
    {
      success: true
    },
    200,
    {
      ...CORS_HEADERS,
      "Set-Cookie": deleteCookie(
        ADMIN_COOKIE
      )
    }
  );
}


// ============================================================
// ADMIN CHECK
// ============================================================

async function handleAdminCheck(request, env) {
  return json(
    {
      authenticated:
        await requireAdmin(request, env)
    },
    200,
    CORS_HEADERS
  );
}


// ============================================================
// CREATE ACCESS PASSWORD
// ============================================================

async function handleCreatePassword(request, env) {
  await ensureDatabase(env);

  if (!(await requireAdmin(request, env))) {
    return json(
      {
        error: "Unauthorized"
      },
      401,
      CORS_HEADERS
    );
  }

  let body = {};

  try {
    body = await request.json();
  } catch {
    body = {};
  }

  let password =
    typeof body.password === "string"
      ? body.password.trim()
      : "";

  if (!password) {
    password = randomPassword(16);
  }

  if (password.length < 6) {
    return json(
      {
        error:
          "Password must contain at least 6 characters"
      },
      400,
      CORS_HEADERS
    );
  }

  const hash =
    await sha256(password);

  try {
    const result =
      await env.DB
        .prepare(`
          INSERT INTO access_passwords
          (
            password_hash,
            active,
            created_at
          )
          VALUES (?, 1, ?)
        `)
        .bind(
          hash,
          Date.now()
        )
        .run();

    return json(
      {
        success: true,
        id: result.meta.last_row_id,
        password
      },
      200,
      CORS_HEADERS
    );
  } catch (error) {
    return json(
      {
        error:
          "This password already exists"
      },
      409,
      CORS_HEADERS
    );
  }
}


// ============================================================
// LIST ACCESS PASSWORDS
// ============================================================

async function handleListPasswords(request, env) {
  await ensureDatabase(env);

  if (!(await requireAdmin(request, env))) {
    return json(
      {
        error: "Unauthorized"
      },
      401,
      CORS_HEADERS
    );
  }

  const result =
    await env.DB
      .prepare(`
        SELECT
          id,
          active,
          created_at,
          revoked_at
        FROM access_passwords
        ORDER BY id DESC
      `)
      .all();

  return json(
    {
      passwords: result.results || []
    },
    200,
    CORS_HEADERS
  );
}


// ============================================================
// REVOKE PASSWORD
// ============================================================

async function handleRevokePassword(request, env) {
  await ensureDatabase(env);

  if (!(await requireAdmin(request, env))) {
    return json(
      {
        error: "Unauthorized"
      },
      401,
      CORS_HEADERS
    );
  }

  let body = {};

  try {
    body = await request.json();
  } catch {
    body = {};
  }

  const id = Number(body.id);

  if (!Number.isInteger(id)) {
    return json(
      {
        error: "Invalid password id"
      },
      400,
      CORS_HEADERS
    );
  }

  await env.DB
    .prepare(`
      UPDATE access_passwords
      SET
        active = 0,
        revoked_at = ?
      WHERE id = ?
    `)
    .bind(
      Date.now(),
      id
    )
    .run();

  return json(
    {
      success: true
    },
    200,
    CORS_HEADERS
  );
}


// ============================================================
// VISITORS
// ============================================================

async function handleVisitors(request, env) {
  await ensureDatabase(env);

  if (!(await requireAdmin(request, env))) {
    return json(
      {
        error: "Unauthorized"
      },
      401,
      CORS_HEADERS
    );
  }

  const result =
    await env.DB
      .prepare(`
        SELECT
          id,
          password_id,
          ip,
          user_agent,
          path,
          created_at
        FROM visitors
        ORDER BY id DESC
        LIMIT 500
      `)
      .all();

  return json(
    {
      visitors: result.results || []
    },
    200,
    CORS_HEADERS
  );
}


// ============================================================
// RADAR API PROXY
// ============================================================

async function proxyRadar(request, env) {
  if (!(await requireUser(request, env))) {
    return json(
      {
        error: "Unauthorized"
      },
      401,
      CORS_HEADERS
    );
  }

  const incomingUrl =
    new URL(request.url);

  let path =
    incomingUrl.pathname;

  const prefix =
    "/api/radar";

  if (path.startsWith(prefix)) {
    path =
      path.slice(prefix.length);
  }

  if (!path) {
    path = "/";
  }

  const target =
    new URL(
      API_BASE + path
    );

  incomingUrl.searchParams.forEach(
    (value, key) => {
      if (
        key !== "access_token" &&
        key !== "key"
      ) {
        target.searchParams.append(
          key,
          value
        );
      }
    }
  );

  if (env.API_KEY) {
    target.searchParams.set(
      "key",
      env.API_KEY
    );
  }

  const headers =
    new Headers(request.headers);

  headers.delete("Host");
  headers.delete("Cookie");
  headers.delete("Authorization");

  const response =
    await fetch(
      target.toString(),
      {
        method: "GET",
        headers
      }
    );

  const responseHeaders =
    new Headers(
      response.headers
    );

  responseHeaders.set(
    "Access-Control-Allow-Origin",
    "*"
  );

  responseHeaders.set(
    "Access-Control-Allow-Methods",
    "GET,POST,OPTIONS"
  );

  responseHeaders.set(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization"
  );

  responseHeaders.set(
    "Cache-Control",
    "no-store"
  );

  return new Response(
    response.body,
    {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders
    }
  );
}


// ============================================================
// STATIC ASSETS
// ============================================================

async function serveAssets(request, env) {
  if (!env.ASSETS) {
    return new Response(
      "Static Assets binding ASSETS is not configured.",
      {
        status: 500
      }
    );
  }

  return env.ASSETS.fetch(request);
}


// ============================================================
// MAIN REQUEST HANDLER
// ============================================================

export default {
  async fetch(request, env) {

    // --------------------------------------------------------
    // OPTIONS
    // --------------------------------------------------------

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: CORS_HEADERS
      });
    }

    const url =
      new URL(request.url);

    const pathname =
      url.pathname;


    // --------------------------------------------------------
    // DATABASE INITIALIZATION
    // --------------------------------------------------------

    try {
      await ensureDatabase(env);
    } catch (error) {
      console.error(
        "Database initialization error:",
        error
      );

      return json(
        {
          error: "Database error",
          message: error.message
        },
        500
      );
    }


    // --------------------------------------------------------
    // ACCESS LOGIN
    // --------------------------------------------------------

    if (
      pathname === "/access/login" &&
      request.method === "POST"
    ) {
      return handleLogin(
        request,
        env
      );
    }


    // --------------------------------------------------------
    // LOGIN COMPATIBILITY
    // --------------------------------------------------------

    if (
      pathname === "/login" &&
      request.method === "POST"
    ) {
      return handleLogin(
        request,
        env
      );
    }


    // --------------------------------------------------------
    // ACCESS CHECK
    // --------------------------------------------------------

    if (
      pathname === "/access/check" &&
      request.method === "GET"
    ) {
      return handleAccessCheck(
        request,
        env
      );
    }


    // --------------------------------------------------------
    // ACCESS LOGOUT
    // --------------------------------------------------------

    if (
      pathname === "/access/logout" &&
      request.method === "POST"
    ) {
      return handleLogout();
    }


    // --------------------------------------------------------
    // ADMIN LOGIN
    // --------------------------------------------------------

    if (
      pathname === "/admin/login" &&
      request.method === "POST"
    ) {
      return handleAdminLogin(
        request,
        env
      );
    }


    // --------------------------------------------------------
    // ADMIN LOGOUT
    // --------------------------------------------------------

    if (
      pathname === "/admin/logout" &&
      request.method === "POST"
    ) {
      return handleAdminLogout();
    }


    // --------------------------------------------------------
    // ADMIN CHECK
    // --------------------------------------------------------

    if (
      pathname === "/admin/check" &&
      request.method === "GET"
    ) {
      return handleAdminCheck(
        request,
        env
      );
    }


    // --------------------------------------------------------
    // ADMIN CREATE PASSWORD
    // --------------------------------------------------------

    if (
      pathname === "/admin/passwords/create" &&
      request.method === "POST"
    ) {
      return handleCreatePassword(
        request,
        env
      );
    }


    // --------------------------------------------------------
    // ADMIN PASSWORD LIST
    // --------------------------------------------------------

    if (
      pathname === "/admin/passwords" &&
      request.method === "GET"
    ) {
      return handleListPasswords(
        request,
        env
      );
    }


    // --------------------------------------------------------
    // ADMIN PASSWORD REVOKE
    // --------------------------------------------------------

    if (
      pathname === "/admin/passwords/revoke" &&
      request.method === "POST"
    ) {
      return handleRevokePassword(
        request,
        env
      );
    }


    // --------------------------------------------------------
    // ADMIN VISITORS
    // --------------------------------------------------------

    if (
      pathname === "/admin/visitors" &&
      request.method === "GET"
    ) {
      return handleVisitors(
        request,
        env
      );
    }


    // --------------------------------------------------------
    // VISIT
    // --------------------------------------------------------

    if (
      pathname === "/visit" &&
      request.method === "POST"
    ) {
      const session =
        await requireUser(
          request,
          env
        );

      if (!session) {
        return json(
          {
            error: "Unauthorized"
          },
          401,
          CORS_HEADERS
        );
      }

      await logVisit(
        request,
        env,
        session.passwordId
      );

      return json(
        {
          success: true
        },
        200,
        CORS_HEADERS
      );
    }


    // --------------------------------------------------------
    // RADAR
    // --------------------------------------------------------

    if (
      pathname === "/api/radar" ||
      pathname.startsWith("/api/radar/")
    ) {
      if (
        request.method !== "GET"
      ) {
        return json(
          {
            error:
              "Method not allowed"
          },
          405,
          CORS_HEADERS
        );
      }

      return proxyRadar(
        request,
        env
      );
    }


    // --------------------------------------------------------
    // PROTECT INDEX.HTML
    // --------------------------------------------------------

    if (
      pathname === "/" ||
      pathname === "/index.html"
    ) {
      const session =
        await requireUser(
          request,
          env
        );

      if (!session) {
        const loginRequest =
          new Request(
            new URL(
              "/login.html",
              request.url
            ),
            request
          );

        return serveAssets(
          loginRequest,
          env
        );
      }

      return serveAssets(
        request,
        env
      );
    }


    // --------------------------------------------------------
    // ADMIN HTML
    // --------------------------------------------------------

    if (
      pathname === "/admin.html"
    ) {
      if (
        !(await requireAdmin(
          request,
          env
        ))
      ) {
        return new Response(
          "Unauthorized",
          {
            status: 401
          }
        );
      }

      return serveAssets(
        request,
        env
      );
    }


    // --------------------------------------------------------
    // EVERYTHING ELSE
    // --------------------------------------------------------

    return serveAssets(
      request,
      env
    );
  }
};
