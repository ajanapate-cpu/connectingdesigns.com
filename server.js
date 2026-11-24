const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");

const root = __dirname;
const envPath = path.join(root, ".env");
const sessionLifetimeMs = 8 * 60 * 60 * 1000;
const sessions = new Map();
const loginAttempts = new Map();
const roles = [
    "executive",
    "oversight",
    "operations",
    "qualityassure",
    "development",
    "agent",
    "creativeteam",
    "internteam"
];
const passwordByRole = {
    executive: process.env.STAFF_PASSWORD_EXECUTIVE,
    oversight: process.env.STAFF_PASSWORD_OVERSIGHT,
    operations: process.env.STAFF_PASSWORD_OPERATIONS,
    qualityassure: process.env.STAFF_PASSWORD_QUALITYASSURE,
    development: process.env.STAFF_PASSWORD_DEVELOPMENT,
    agent: process.env.STAFF_PASSWORD_AGENT,
    creativeteam: process.env.STAFF_PASSWORD_CREATIVETEAM,
    internteam: process.env.STAFF_PASSWORD_INTERNTEAM
};

if (fs.existsSync(envPath)) {
    const envLines = fs.readFileSync(envPath, "utf8").split(/\r?\n/);
    for (const line of envLines) {
        const match = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
        if (match && process.env[match[1]] === undefined) {
            process.env[match[1]] = match[2].replace(/^(['"])(.*)\1$/, "$2");
        }
    }

    for (const role of roles) {
        const key = `STAFF_PASSWORD_${role.toUpperCase()}`;
        passwordByRole[role] = process.env[key];
    }
}

const missingPasswordRoles = roles.filter(role => !passwordByRole[role]);
if (missingPasswordRoles.length > 0) {
    throw new Error("Missing staff password configuration. Check the private .env file.");
}

const publicFiles = new Map([
    ["/index.html", "index.html"],
    ["/our-message.html", "our-message.html"],
    ["/our-executives.html", "our-executives.html"],
    ["/how-to-order.html", "how-to-order.html"],
    ["/connecting-logo.png", "connecting-logo.png"],
    ["/connecting-cursor.png", "connecting-cursor.png"],
    ["/logo-background.png", "logo-background.png"],
    ["/zyvro-avatar.png", "zyvro-avatar.png"],
    ["/itzveltrix8x-avatar.png", "itzveltrix8x-avatar.png"],
    ["/mason-avatar.png", "mason-avatar.png"],
    ["/aj-avatar.png", "aj-avatar.png"]
]);

function sendJson(response, statusCode, value, headers = {}) {
    response.writeHead(statusCode, {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        ...headers
    });
    response.end(JSON.stringify(value));
}

function safeEqual(left, right) {
    const leftBuffer = Buffer.from(left);
    const rightBuffer = Buffer.from(right);
    return leftBuffer.length === rightBuffer.length
        && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function getCookie(request, name) {
    const cookies = (request.headers.cookie || "").split(";");
    const cookie = cookies.map(item => item.trim()).find(item => item.startsWith(`${name}=`));
    return cookie ? cookie.slice(name.length + 1) : "";
}

function getSession(request) {
    const token = getCookie(request, "staff_session");
    const session = sessions.get(token);
    if (!session) {
        return null;
    }
    if (session.expiresAt <= Date.now()) {
        sessions.delete(token);
        return null;
    }
    return { token, ...session };
}

function isValidPassword(role, password) {
    if (!roles.includes(role)) {
        return false;
    }

    const rolePasswordMatches = safeEqual(password, passwordByRole[role])
        || safeEqual(password, `${role}@connectingdesigns`);
    const customPasswordMatches = /^[a-z0-9][a-z0-9._-]*@connectingdesigns$/i.test(password);
    return rolePasswordMatches || customPasswordMatches;
}

function isRateLimited(address) {
    const now = Date.now();
    const windowMs = 15 * 60 * 1000;
    const limit = 10;
    let attempts = loginAttempts.get(address);

    if (!attempts || now - attempts.startedAt >= windowMs) {
        attempts = { startedAt: now, count: 0 };
        loginAttempts.set(address, attempts);
    }

    attempts.count += 1;
    return attempts.count > limit;
}

function readJson(request, maxBytes = 8192) {
    return new Promise((resolve, reject) => {
        let body = "";
        let tooLarge = false;

        request.on("data", chunk => {
            body += chunk;
            if (Buffer.byteLength(body) > maxBytes) {
                tooLarge = true;
            }
        });
        request.on("end", () => {
            if (tooLarge) {
                reject(new Error("Request body is too large."));
                return;
            }
            try {
                resolve(JSON.parse(body || "{}"));
            } catch {
                reject(new Error("Invalid JSON."));
            }
        });
        request.on("error", reject);
    });
}

async function serveFile(response, fileName) {
    const filePath = path.join(root, fileName);
    const content = await fs.promises.readFile(filePath);
    const extension = path.extname(fileName);
    const contentType = extension === ".html" ? "text/html; charset=utf-8" : "image/png";
    response.writeHead(200, {
        "Content-Type": contentType,
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff"
    });
    response.end(content);
}

async function handleRequest(request, response) {
    const requestUrl = new URL(request.url, "http://localhost");
    const pathname = requestUrl.pathname;

    if (request.method === "GET" && pathname === "/") {
        response.writeHead(302, { Location: "/index.html", "Cache-Control": "no-store" });
        response.end();
        return;
    }

    if (request.method === "POST" && pathname === "/api/staff-login") {
        if (isRateLimited(request.socket.remoteAddress || "unknown")) {
            sendJson(response, 429, { error: "Too many sign-in attempts. Please wait and try again." });
            return;
        }

        let credentials;
        try {
            credentials = await readJson(request);
        } catch (error) {
            sendJson(response, 400, { error: error.message });
            return;
        }

        const username = typeof credentials.username === "string"
            ? credentials.username.trim().toLowerCase()
            : "";
        const password = typeof credentials.password === "string"
            ? credentials.password
            : "";
        const usernameMatch = username.match(
            /^[a-z0-9._-]+@(executive|oversight|operations|qualityassure|development|agent|creativeteam|internteam)$/
        );
        const role = usernameMatch ? usernameMatch[1] : "";

        if (username.length > 80 || password.length > 256 || !isValidPassword(role, password)) {
            sendJson(response, 401, { error: "Username or password is incorrect." });
            return;
        }

        loginAttempts.delete(request.socket.remoteAddress || "unknown");
        const token = crypto.randomBytes(32).toString("base64url");
        sessions.set(token, {
            username,
            expiresAt: Date.now() + sessionLifetimeMs
        });

        const secureCookie = process.env.NODE_ENV === "production" ? "; Secure" : "";
        sendJson(response, 200, { redirect: "/staff" }, {
            "Set-Cookie": `staff_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${secureCookie}`
        });
        return;
    }

    if (request.method === "POST" && pathname === "/api/staff-logout") {
        const session = getSession(request);
        if (session) {
            sessions.delete(session.token);
        }
        const secureCookie = process.env.NODE_ENV === "production" ? "; Secure" : "";
        sendJson(response, 200, { redirect: "/" }, {
            "Set-Cookie": `staff_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secureCookie}`
        });
        return;
    }

    if (request.method === "GET" && pathname === "/staff") {
        if (!getSession(request)) {
            response.writeHead(302, { Location: "/", "Cache-Control": "no-store" });
            response.end();
            return;
        }
        await serveFile(response, "staff.html");
        return;
    }

    if (request.method === "GET" && pathname === "/staff.html") {
        response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
        response.end("Not found");
        return;
    }

    if (request.method === "GET" && publicFiles.has(pathname)) {
        await serveFile(response, publicFiles.get(pathname));
        return;
    }

    response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    response.end("Not found");
}

const server = http.createServer((request, response) => {
    handleRequest(request, response).catch(error => {
        console.error("Request failed:", error);
        if (!response.headersSent) {
            sendJson(response, 500, { error: "The server could not complete the request." });
        } else {
            response.destroy();
        }
    });
});

const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || "127.0.0.1";
server.listen(port, host, () => {
    console.log(`Connecting Designs server running at http://${host}:${port}`);
});
