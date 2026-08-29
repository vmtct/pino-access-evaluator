import test from "node:test";
import assert from "node:assert/strict";
import { canonicalTosAllowed, identityFromClaims } from "./index";

const claims = {
  exp: Math.floor(Date.now() / 1000) + 300,
  identity: { email: " Staff@Example.com ", user_uuid: "cf-user-123" },
};

test("maps Cloudflare full identity to canonical Core identity", () => {
  assert.deepEqual(identityFromClaims(claims, "team.cloudflareaccess.com"), {
    provider: "cloudflare_access",
    subject: "cf-user-123",
    email: "staff@example.com",
    issuer: "https://team.cloudflareaccess.com",
    audience: [],
    expiresAt: claims.exp,
  });
});

test("fails closed when Cloudflare user_uuid is absent", () => {
  assert.equal(identityFromClaims({ ...claims, identity: { email: "staff@example.com" } }, "team.cloudflareaccess.com"), null);
});
test("allows only when pino-core authorizes the TOS context", async () => {
  const calls: unknown[] = [];
  const allowed = await canonicalTosAllowed({
    TEAM_DOMAIN: "team.cloudflareaccess.com",
    PINO_WORKFORCE_CORE: { execute: async (request, identity) => { calls.push({ request, identity }); return { status: 200, body: {}, requestId: "ok" }; } },
  }, claims);
  assert.equal(allowed, true);
  assert.equal(calls.length, 1);
});

test("denies Core 403, unknown users, and binding failures", async () => {
  const denied = await canonicalTosAllowed({
    TEAM_DOMAIN: "team.cloudflareaccess.com",
    PINO_WORKFORCE_CORE: { execute: async () => ({ status: 403, body: {}, requestId: "deny" }) },
  }, claims);
  const failed = await canonicalTosAllowed({
    TEAM_DOMAIN: "team.cloudflareaccess.com",
    PINO_WORKFORCE_CORE: { execute: async () => { throw new Error("binding failed"); } },
  }, claims);
  assert.equal(denied, false);
  assert.equal(failed, false);
});
