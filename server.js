const http = require("http");
const { URL } = require("url");
const { request } = require("https");
const fs = require("fs");
require("dotenv").config();

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = "http://localhost:3000/oauth2/callback";
const TOKEN_PATH = "./token.json";

const PORT = 3000;

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
  return new Promise((resolve, reject) => {
    const req = request(
      {
        method: "GET",
        host: "www.googleapis.com",
        path: "/oauth2/v2/userinfo",
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          try {
            resolve(JSON.parse(data));
          } catch (err) {
            reject(err);
          }
        });
      }
    );
    req.on("error", reject);
    req.end();
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

  return new Promise((resolve, reject) => {
    const req = request(
      {
        method: "POST",
        host: "oauth2.googleapis.com",
        path: "/token",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Content-Length": Buffer.byteLength(postData),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          try {
            resolve(JSON.parse(data));
          } catch (err) {
            reject(err);
          }
        });
      }
    );
    req.on("error", reject);
    req.write(postData);
    req.end();
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (fs.existsSync(TOKEN_PATH)) {
    try {
      let savedTokens = JSON.parse(fs.readFileSync(TOKEN_PATH));

      let accessToken = savedTokens.access_token;

      if (savedTokens.refresh_token) {
        const newTokens = await refreshAccessToken(savedTokens.refresh_token);
        accessToken = newTokens.access_token;
        savedTokens.access_token = accessToken;
        fs.writeFileSync(TOKEN_PATH, JSON.stringify(savedTokens));
      }

      const userInfo = await getUserInfo(accessToken);
      return send(
        res,
        200,
        `<h1>Welcome back, ${userInfo.name}</h1>
         <p>Email: ${userInfo.email}</p>`
      );
    } catch (err) {
      console.error("Error using saved token:", err);
    }
  }

  if (url.pathname === "/") {
    return send(res, 200, `<a href="${googleAuthUrl()}">Login with Google</a>`);
  }

  if (url.pathname === "/oauth2/callback") {
    const code = url.searchParams.get("code");
    if (!code) return send(res, 400, { error: "No code provided" });

    try {
      const tokens = await exchangeCodeForToken(code);

      fs.writeFileSync(TOKEN_PATH, JSON.stringify(tokens));
      const userInfo = await getUserInfo(tokens.access_token);

      return send(
        res,
        200,
        `<h1>Welcome, ${userInfo.name}</h1>
         <p>Email: ${userInfo.email}</p>`
      );
    } catch (err) {
      return send(res, 500, { error: err.message });
    }
  }

  send(res, 404, "Not found");
});

server.listen(PORT, () =>
  console.log(`Server running on http://localhost:${PORT}`)
);
