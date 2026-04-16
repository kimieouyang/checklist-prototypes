// Cloudflare Pages middleware for password protection
// Set the password via Cloudflare Dashboard → Settings → Environment Variables → PROTOTYPE_PASSWORD

const COOKIE_NAME = "prototype_auth";
const COOKIE_MAX_AGE = 60 * 60 * 24 * 7; // 7 days

// Paths that don't require auth
const PUBLIC_PATHS = ["/", "/favicon.ico"];

function isPublicPath(pathname) {
  return PUBLIC_PATHS.includes(pathname);
}

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const cookies = cookieHeader.split(";").map((c) => c.trim());
  for (const cookie of cookies) {
    const [key, ...rest] = cookie.split("=");
    if (key === name) return rest.join("=");
  }
  return null;
}

function passwordPage(error = "") {
  const errorHtml = error
    ? `<p style="color:#dc2626;font-size:0.85rem;margin-bottom:1rem;">${error}</p>`
    : "";

  return new Response(
    `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Prototype Access</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    background: #f8f7f7;
    color: #201f1d;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 2rem;
  }
  .box {
    background: #fff;
    border: 1px solid #e4e1df;
    border-radius: 12px;
    padding: 2.5rem;
    max-width: 380px;
    width: 100%;
    text-align: center;
  }
  h1 {
    font-size: 1.25rem;
    font-weight: 700;
    color: #0C505D;
    margin-bottom: 0.4rem;
  }
  .subtitle {
    font-size: 0.875rem;
    color: #6b665e;
    margin-bottom: 1.5rem;
  }
  form { display: flex; flex-direction: column; gap: 0.75rem; }
  input[type="password"] {
    padding: 0.7rem 1rem;
    border: 1px solid #d6d1cd;
    border-radius: 8px;
    font-size: 0.9rem;
    font-family: inherit;
    outline: none;
    transition: border-color 0.15s;
  }
  input[type="password"]:focus { border-color: #0C505D; }
  button {
    padding: 0.7rem 1rem;
    background: #0C505D;
    color: #fff;
    border: none;
    border-radius: 8px;
    font-size: 0.9rem;
    font-weight: 600;
    font-family: inherit;
    cursor: pointer;
    transition: background 0.15s;
  }
  button:hover { background: #1A6B7A; }
  .footer {
    margin-top: 1.5rem;
    font-size: 0.75rem;
    color: #a8a39f;
  }
</style>
</head>
<body>
<div class="box">
  <h1>Prototype Access</h1>
  <p class="subtitle">Enter password to view prototypes</p>
  ${errorHtml}
  <form method="POST">
    <input type="password" name="password" placeholder="Password" autofocus required>
    <button type="submit">Access Prototypes</button>
  </form>
  <p class="footer">Contact the team for access credentials.</p>
</div>
</body>
</html>`,
    {
      status: 401,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    }
  );
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  // Allow public paths through
  if (isPublicPath(url.pathname)) {
    return next();
  }

  const password = env.PROTOTYPE_PASSWORD || "stensul2026";
  const expectedHash = await hashPassword(password);

  // Handle POST (password submission)
  if (request.method === "POST") {
    const formData = await request.formData();
    const submitted = formData.get("password") || "";
    const submittedHash = await hashPassword(submitted);

    if (submittedHash === expectedHash) {
      // Password correct — set cookie and redirect to same page
      const response = new Response(null, {
        status: 302,
        headers: { Location: url.pathname },
      });
      response.headers.append(
        "Set-Cookie",
        `${COOKIE_NAME}=${expectedHash}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${COOKIE_MAX_AGE}`
      );
      return response;
    }

    // Wrong password
    return passwordPage("Incorrect password. Please try again.");
  }

  // Check auth cookie for GET requests
  const authCookie = getCookie(request, COOKIE_NAME);
  if (authCookie === expectedHash) {
    return next(); // Authenticated — serve the page
  }

  // Not authenticated — show password form
  return passwordPage();
}
