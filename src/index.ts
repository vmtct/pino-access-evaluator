import { createRemoteJWKSet, importJWK, jwtVerify, SignJWT } from "jose";
import { publicJwk } from "./public-jwk";

type CoreIdentity = {
  provider: "cloudflare_access";
  subject: string;
  email: string;
  issuer: string;
  audience: string[];
  expiresAt: number;
};

type CoreResponse = { status: number; body: unknown; requestId: string };
type CoreBinding = { execute(request: { method: string; path: string; body?: unknown }, identity: CoreIdentity): Promise<CoreResponse> };

type Env = {
  TEAM_DOMAIN: string;
  EVALUATOR_PRIVATE_JWK: string;
  PINO_WORKFORCE_CORE: CoreBinding;
};

type IncomingClaims = {
  nonce?: unknown;
  exp?: unknown;
  identity?: unknown;
};
let keyPromise: Promise<CryptoKey | Uint8Array> | null = null;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "GET" && (url.pathname === "/keys" || url.pathname === "/keys/")) {
      return json({ keys: [publicJwk] }, 200, { "cache-control": "public, max-age=300" });
    }
    if (request.method === "GET" && url.pathname === "/health") return json({ ok: true });
    if (request.method !== "POST" || !["/", "/evaluate", "/evaluate/"].includes(url.pathname)) {
      return json({ error: "not_found" }, 404);
    }
    return evaluateRequest(request, env);
  },
};

async function evaluateRequest(request: Request, env: Env): Promise<Response> {
  const now = Math.floor(Date.now() / 1000);
  try {
    const body = await request.json() as { token?: unknown };
    if (typeof body.token !== "string" || !body.token) return json({ error: "invalid_request" }, 400);
    const claims = await verifyAccessToken(body.token, env.TEAM_DOMAIN);
    const nonce = typeof claims.nonce === "string" ? claims.nonce : "";
    if (!nonce) return json({ error: "invalid_nonce" }, 403);
    const allowed = await canonicalTosAllowed(env, claims);
    const token = await signDecision(env, { success: allowed, nonce, iat: now, exp: now + 60 });
    return json({ token });
  } catch {
    return json({ error: "evaluation_failed" }, 403);
  }
}

export async function canonicalTosAllowed(env: Pick<Env, "PINO_WORKFORCE_CORE" | "TEAM_DOMAIN">, claims: IncomingClaims): Promise<boolean> {
  const identity = identityFromClaims(claims, env.TEAM_DOMAIN);
  if (!identity) return false;
  try {
    const result = await env.PINO_WORKFORCE_CORE.execute({ method: "GET", path: "/context" }, identity);
    return result.status === 200;
  } catch {
    return false;
  }
}

export function identityFromClaims(claims: IncomingClaims, teamDomain: string): CoreIdentity | null {
  if (!claims.identity || typeof claims.identity !== "object" || Array.isArray(claims.identity)) return null;
  const row = claims.identity as Record<string, unknown>;
  const email = typeof row.email === "string" ? row.email.trim().toLowerCase() : "";
  const subject = typeof row.user_uuid === "string" ? row.user_uuid.trim() : "";
  if (!email || !subject || typeof claims.exp !== "number") return null;
  return {
    provider: "cloudflare_access",
    subject,
    email,
    issuer: `https://${teamDomain}`,
    audience: [],
    expiresAt: claims.exp,
  };
}

async function verifyAccessToken(token: string, teamDomain: string): Promise<IncomingClaims> {
  const issuer = `https://${teamDomain}`;
  const keys = createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`));
  const { payload } = await jwtVerify(token, keys, { issuer });
  return payload as IncomingClaims;
}

async function signDecision(env: Pick<Env, "EVALUATOR_PRIVATE_JWK">, payload: { success: boolean; nonce: string; iat: number; exp: number }) {
  if (!keyPromise) {
    const jwk = JSON.parse(env.EVALUATOR_PRIVATE_JWK) as JsonWebKey;
    keyPromise = importJWK(jwk, "RS256");
  }
  const key = await keyPromise;
  return new SignJWT({ success: payload.success, nonce: payload.nonce })
    .setProtectedHeader({ alg: "RS256", kid: publicJwk.kid })
    .setIssuedAt(payload.iat).setExpirationTime(payload.exp).sign(key);
}

function json(body: unknown, status = 200, headers: HeadersInit = {}) {
  return Response.json(body, { status, headers: { "content-type": "application/json", "cache-control": "no-store", ...headers } });
}
