// Sets up an account for the live tests of signing in through WireCloud
// (`cargo test --lib cloud::wirecloud::live -- --ignored --test-threads=1`).
//
// Prerequisite: a running WireCloud (backend, Maildev, database) and a
// WireTerm backend in `wirecloud` mode, see the description at the top of
// `src-tauri/src/cloud/wirecloud.rs`. The script
//
//   - creates its **own** throwaway administrator (role `platform_admin` through
//     the database, second factor via TOTP, which WireCloud requires for admin
//     endpoints), so that no existing account is touched,
//   - creates (if needed) a tool instance for the backend's audience,
//   - registers a new account, confirms the address through Maildev and
//   - gives the account access to the backend.
//
// It writes the environment variables for the test to the file `WIRECLOUD_ENV_FILE`. Every run creates new accounts;
// nothing is cleaned up, this is a throwaway database.
//
//   WIRECLOUD_ENV_FILE=<file> node scripts/live-wirecloud.mjs
//   set -a; . <file>; set +a   # then the test run

import { createHmac } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chmodSync, writeFileSync } from "node:fs";

const API = process.env.WIRECLOUD_API ?? "http://localhost:8200";
const MAIL = process.env.WIRECLOUD_MAILDEV ?? "http://localhost:8202";
const AUDIENCE = process.env.WIRETERM_AUDIENCE ?? "http://localhost:18080";
// How the WireCloud backend reaches the tool backend (for events).
const BASE_URL = process.env.WIRETERM_BASE_URL ?? "http://wireterm_live_backend:8080";
// WireCloud's database container (for the administrator's role).
const DB_CONTAINER = process.env.WIRECLOUD_DB_CONTAINER ?? "wirecloud_db";
const DB_ROOT_PASSWORD = process.env.WIRECLOUD_DB_ROOT_PASSWORD ?? "password";
const ORIGIN = "http://localhost:5173";
const random = () => Math.random().toString(36).slice(2, 10);
const PASSWORD = `Live-Passw0rd!-${random()}`;

// TOTP per RFC 6238 (HMAC-SHA1, 30 seconds, 6 digits).
function totp(secret) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bits = [...secret.toUpperCase().replace(/=+$/, "")]
    .map((c) => alphabet.indexOf(c).toString(2).padStart(5, "0"))
    .join("");
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const hmac = createHmac("sha1", key).update(counter).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const code =
    ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
  return String(code % 1_000_000).padStart(6, "0");
}

class Client {
  cookies = new Map();
  async call(method, path, body) {
    const cookie = [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ");
    const response = await fetch(API + path, {
      method,
      headers: {
        origin: ORIGIN,
        ...(body ? { "content-type": "application/json" } : {}),
        ...(cookie ? { cookie } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    for (const line of response.headers.getSetCookie()) {
      const [pair, ...attrs] = line.split(";").map((s) => s.trim());
      const at = pair.indexOf("=");
      if (attrs.some((a) => a.toLowerCase() === "max-age=0")) this.cookies.delete(pair.slice(0, at));
      else this.cookies.set(pair.slice(0, at), pair.slice(at + 1));
    }
    const text = await response.text();
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      json = undefined;
    }
    return { status: response.status, json, text };
  }
}

async function register(client, email, name) {
  const signUp = await client.call("POST", "/api/auth/sign-up/email", { email, password: PASSWORD, name });
  if (signUp.status !== 200) throw new Error(`Sign-up: ${signUp.text}`);
}

// A throwaway administrator. The database sets the role (there is no way through
// the API, and that is a good thing), the second factor comes through the
// API like for any account.
const adminEmail = `live-admin-${random()}@example.test`;
const admin = new Client();
await register(admin, adminEmail, "Live Admin");
execFileSync("docker", [
  "exec", DB_CONTAINER, "mariadb", "-uroot", `-p${DB_ROOT_PASSWORD}`, "wirecloud", "-e",
  `UPDATE user SET role='platform_admin', emailVerified=1 WHERE email='${adminEmail}'`,
]);
// WireCloud does not sign in on sign-up (`autoSignIn: false`).
const signIn = await admin.call("POST", "/api/auth/sign-in/email", { email: adminEmail, password: PASSWORD });
if (signIn.status !== 200) throw new Error(`Administrator sign-in: ${signIn.text}`);
const enabled = await admin.call("POST", "/api/auth/two-factor/enable", { password: PASSWORD });
if (enabled.status !== 200) throw new Error(`Setting up two-factor: ${enabled.text}`);
const secret = new URL(enabled.json.totpURI).searchParams.get("secret");
const confirmed = await admin.call("POST", "/api/auth/two-factor/verify-totp", { code: totp(secret) });
if (confirmed.status !== 200) throw new Error(`Confirming two-factor: ${confirmed.text}`);

// Tool instance for the audience, if it does not exist yet.
let instances = await admin.call("GET", "/v1/admin/tool-instances");
if (instances.status !== 200) throw new Error(`Tool instances: ${instances.status} ${instances.text}`);
let instance = instances.json.find((i) => i.audience === AUDIENCE);
if (!instance) {
  const tool = await admin.call("POST", "/v1/admin/tools", {
    key: `wireterm-live-${Math.random().toString(36).slice(2, 8)}`,
    name: "WireTerm (live test)",
  });
  const created = await admin.call("POST", "/v1/admin/tool-instances", {
    toolId: tool.json.id,
    audience: AUDIENCE,
    baseUrl: BASE_URL,
    roleKeys: ["owner", "admin", "member"],
  });
  if (created.status !== 201) throw new Error(`Tool instance: ${created.text}`);
  instance = created.json;
}

// A new account with a confirmed address.
const email = `live-${Math.random().toString(36).slice(2, 10)}@example.test`;
const user = new Client();
await register(user, email, "Live Test");
let verifyUrl;
for (let i = 0; i < 40 && !verifyUrl; i++) {
  const list = await (await fetch(`${MAIL}/api/email`)).json();
  const mail = list.reverse().find((m) => m.to.some((t) => t.address === email));
  verifyUrl = /https?:\/\/[^"'\s<>]*verify-email[^"'\s<>]*/.exec(mail?.html ?? mail?.text ?? "")?.[0]?.replace(/&amp;/g, "&");
  if (!verifyUrl) await new Promise((r) => setTimeout(r, 250));
}
if (!verifyUrl) throw new Error("no confirmation mail");
await fetch(verifyUrl, { headers: { origin: ORIGIN }, redirect: "manual" });
const userSignIn = await user.call("POST", "/api/auth/sign-in/email", { email, password: PASSWORD });
if (userSignIn.status !== 200) throw new Error(`Test account sign-in: ${userSignIn.text}`);

// Access to the backend: a grant of its own, without a company (private use).
const account = await user.call("GET", "/api/auth/get-session");
const grant = await admin.call("POST", "/v1/admin/grants", {
  toolInstanceId: instance.id,
  subjectType: "account",
  subjectId: account.json.user.id,
  toolRoleKey: "member",
});
if (grant.status !== 201) throw new Error(`Grant: ${grant.text}`);

// The credentials go into a file (mode 0600, `KEY=VALUE`), never to standard
// output or onto a command line. `WIRECLOUD_ENV_FILE` sets the path.
const target = process.env.WIRECLOUD_ENV_FILE;
if (!target) throw new Error("WIRECLOUD_ENV_FILE names the file for the credentials");
writeFileSync(
  target,
  `WIRECLOUD_API=${API}\nWIRECLOUD_TEST_EMAIL=${email}\nWIRECLOUD_TEST_PASSWORD=${PASSWORD}\n`,
  { mode: 0o600 },
);
chmodSync(target, 0o600);
console.log(`Credentials written to ${target}`);
