import { WorkerEntrypoint } from "cloudflare:workers";
import { buildStaffPolicyPayload, canonicalTosAllowed, normalizeStaffEmails, type CoreBinding, type IncomingClaims } from "./logic";
import { createRemoteJWKSet, exportJWK, generateKeyPair, importJWK, jwtVerify, SignJWT } from "jose";

type Env = {
  TEAM_DOMAIN: string;
  CF_ACCOUNT_ID: string;
  CF_ACCESS_API_TOKEN: string;
  TOS_AUD: string;
  EVALUATE_URL: string;
  KEYS_URL: string;
  EVALUATOR_KEYS: KVNamespace;
  PINO_WORKFORCE_CORE: CoreBinding;
};

type StoredKeyset = { kid: string; public: JsonWebKey; private: JsonWebKey };
const KEYSET_KEY = "external-evaluation-rs256-v1";
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "GET" && (url.pathname === "/keys" || url.pathname === "/keys/")) {
      const keyset = await ensureKeyset(env.EVALUATOR_KEYS);
      return json({ keys: [{ ...keyset.public, kid: keyset.kid, alg: "RS256", use: "sig" }] }, 200, { "cache-control": "public, max-age=300" });
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
    const token = await signDecision(env.EVALUATOR_KEYS, { success: allowed, nonce, iat: now, exp: now + 60 });
    return json({ token });
  } catch {
    return json({ error: "evaluation_failed" }, 403);
  }
}

async function verifyAccessToken(token: string, teamDomain: string): Promise<IncomingClaims> {
  const issuer = `https://${teamDomain}`;
  const keys = createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`));
  const { payload } = await jwtVerify(token, keys, { issuer });
  return payload as IncomingClaims;
}

async function ensureKeyset(kv: KVNamespace): Promise<StoredKeyset> {
  const stored = await kv.get<StoredKeyset>(KEYSET_KEY, "json");
  if (stored?.kid && stored.public && stored.private) return stored;
  const { publicKey, privateKey } = await generateKeyPair("RS256", { extractable: true });
  const kid = crypto.randomUUID();
  const keyset: StoredKeyset = {
    kid,
    public: await exportJWK(publicKey),
    private: await exportJWK(privateKey),
  };
  await kv.put(KEYSET_KEY, JSON.stringify(keyset));
  return keyset;
}
async function signDecision(kv: KVNamespace, payload: { success: boolean; nonce: string; iat: number; exp: number }) {
  const keyset = await ensureKeyset(kv);
  const key = await importJWK(keyset.private, "RS256");
  return new SignJWT({ success: payload.success, nonce: payload.nonce })
    .setProtectedHeader({ alg: "RS256", kid: keyset.kid })
    .setIssuedAt(payload.iat)
    .setExpirationTime(payload.exp)
    .sign(key);
}

function json(body: unknown, status = 200, headers: HeadersInit = {}) {
  return Response.json(body, {
    status,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
      ...headers,
    },
  });
}


export class AccessSyncControlPlane extends WorkerEntrypoint<Env> {
  async reconcile(input: { emails: string[] }) {
    return reconcileTosStaffPolicy(this.env, input.emails);
  }
}

async function reconcileTosStaffPolicy(env: Env, rawEmails: string[]) {
  const emails = normalizeStaffEmails(rawEmails);
  if (!env.CF_ACCOUNT_ID || !env.CF_ACCESS_API_TOKEN || !env.TOS_AUD) throw new Error("access sync configuration missing");
  const api = `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}`;
  const apps = await cfJson(env, `${api}/access/apps?per_page=100`);
  const matches = apps.result.filter((app: any) => app?.aud === env.TOS_AUD);
  if (matches.length !== 1) throw new Error("TOS Access application must resolve uniquely");
  const appId = matches[0].id as string;
  const policies = await cfJson(env, `${api}/access/apps/${appId}/policies?per_page=100`);
  const named = policies.result.filter((policy: any) => policy?.name === "PINO Staff Canonical External Evaluation" && policy?.decision === "allow");
  if (named.length > 1) throw new Error("TOS staff policy is ambiguous");
  const existing = named[0] as any | undefined;
  if (emails.length === 0) {
    if (existing?.id) await cfJson(env, `${api}/access/apps/${appId}/policies/${existing.id}`, { method: "DELETE" });
    return { state: existing ? "deleted" : "absent", emailCount: 0, policyId: null };
  }
  const payload = buildStaffPolicyPayload(emails, env, typeof existing?.precedence === "number" ? existing.precedence : 50);
  const targetUrl = existing?.id ? `${api}/access/apps/${appId}/policies/${existing.id}` : `${api}/access/apps/${appId}/policies`;
  const updated = await cfJson(env, targetUrl, { method: existing?.id ? "PUT" : "POST", body: JSON.stringify(payload) });
  const policyId = updated.result?.id as string | undefined;
  if (!policyId) throw new Error("Cloudflare did not return the TOS staff policy id");
  const verify = await cfJson(env, `${api}/access/apps/${appId}/policies?per_page=100`);
  const policy = verify.result.find((item: any) => item?.id === policyId);
  const actualEmails = Array.isArray(policy?.include) ? policy.include.map((item: any) => item?.email?.email).filter(Boolean).sort() : [];
  const hasEveryone = verify.result.some((item: any) => item?.decision === "allow" && Array.isArray(item?.include) && item.include.some((rule: any) => rule?.everyone));
  const hasEvaluator = Array.isArray(policy?.require) && policy.require.some((rule: any) => rule?.external_evaluation?.evaluate_url === env.EVALUATE_URL && rule?.external_evaluation?.keys_url === env.KEYS_URL);
  if (hasEveryone || !hasEvaluator || JSON.stringify(actualEmails) !== JSON.stringify(emails)) throw new Error("TOS staff policy verification failed");
  return { state: existing ? "updated" : "created", emailCount: emails.length, policyId };
}

async function cfJson(env: Pick<Env, "CF_ACCESS_API_TOKEN">, url: string, init: RequestInit = {}): Promise<any> {
  const response = await fetch(url, { ...init, headers: { authorization: `Bearer ${env.CF_ACCESS_API_TOKEN}`, "content-type": "application/json", ...(init.headers ?? {}) } });
  const body = await response.json() as any;
  if (!response.ok || body?.success !== true || !Array.isArray(body?.errors) || body.errors.length > 0) throw new Error(`Cloudflare Access API failed (${response.status})`);
  return body;
}
