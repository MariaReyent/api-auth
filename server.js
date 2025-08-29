const http = require("http");
const { URL } = require("url");
const { request } = require("https");
const fs = require("fs").promises;
require("dotenv").config();

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = "http://localhost:3000/oauth2/callback";
const TOKEN_PATH = "./token.json";
const PORT = 3000;

async function httpsRequest(options, postData = null) {
  return new Promise((resolve, reject) => {
    const req = request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          resolve(JSON.parse(data));
        } catch (err) {
          reject(err);
        }
      });
    });
    req.on("error", reject);
    if (postData) req.write(postData);
    req.end();
  });
}

function send(res, status, data, headers = {}) {
  const body = typeof data === "string" ? data : JSON.stringify(data, null, 2);
  res.writeHead(status, {
    "Content-Type": typeof data === "string" ? "text/html" : "application/json",
    ...headers,
  });
  res.end(body);
}

function googleAuthUrl() {
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "openid email profile",
    access_type: "offline",
  });
  return `https://accounts.google.com/o/oauth2/v2/auth?${params}`;
}

async function getUserInfo(accessToken) {
  return httpsRequest({
    method: "GET",
    host: "www.googleapis.com",
    path: "/oauth2/v2/userinfo",
    headers: { Authorization: `Bearer ${accessToken}` },
  });
}

async function exchangeCodeForToken(code) {
  const postData = new URLSearchParams({
    code,
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    redirect_uri: REDIRECT_URI,
    grant_type: "authorization_code",
  }).toString();

  return httpsRequest(
    {
      method: "POST",
      host: "oauth2.googleapis.com",
      path: "/token",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": Buffer.byteLength(postData),
      },
    },
    postData
  );
}

async function refreshAccessToken(refreshToken) {
  const postData = new URLSearchParams({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    refresh_token: refreshToken,
    grant_type: "refresh_token",
  }).toString();

  return httpsRequest(
    {
      method: "POST",
      host: "oauth2.googleapis.com",
      path: "/token",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": Buffer.byteLength(postData),
      },
    },
    postData
  );
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  try {
    let savedTokens;
    try {
      const tokenData = await fs.readFile(TOKEN_PATH, "utf-8");
      savedTokens = JSON.parse(tokenData);

      let accessToken = savedTokens.access_token;

      if (savedTokens.refresh_token) {
        const newTokens = await refreshAccessToken(savedTokens.refresh_token);
        accessToken = newTokens.access_token;
        savedTokens.access_token = accessToken;
        await fs.writeFile(TOKEN_PATH, JSON.stringify(savedTokens, null, 2));
      }

      const userInfo = await getUserInfo(accessToken);

      return send(
        res,
        200,
        `<h1>Welcome back, ${userInfo.name}</h1>
         <p>Email: ${userInfo.email}</p>`
      );
    } catch (err) {
      console.log("No valid token found or error using saved token.");
    }

    if (url.pathname === "/") {
      return send(
        res,
        200,
        `<a href="${googleAuthUrl()}">Login with Google</a>`
      );
    }

    if (url.pathname === "/oauth2/callback") {
      const code = url.searchParams.get("code");
      if (!code) return send(res, 400, { error: "No code provided" });

      const tokens = await exchangeCodeForToken(code);
      await fs.writeFile(TOKEN_PATH, JSON.stringify(tokens, null, 2));

      const userInfo = await getUserInfo(tokens.access_token);

      return send(
        res,
        200,
        `<h1>Welcome, ${userInfo.name}</h1>
         <p>Email: ${userInfo.email}</p>`
      );
    }

    send(res, 404, "Not found");
  } catch (err) {
    console.error(err);
    send(res, 500, { error: err.message });
  }
});

server.listen(PORT, () =>
  console.log(`Server running on http://localhost:${PORT}`)
);
