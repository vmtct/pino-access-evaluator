export type CoreIdentity = {
  provider: "cloudflare_access";
  subject: string;
  email: string;
  issuer: string;
  audience: string[];
  expiresAt: number;
};

export type CoreResponse = { status: number; body: unknown; requestId: string };
export type CoreBinding = {
  execute(request: { method: string; path: string; body?: unknown }, identity: CoreIdentity): Promise<CoreResponse>;
};
export type IncomingClaims = { nonce?: unknown; exp?: unknown; identity?: unknown };

export async function canonicalTosAllowed(
  env: { PINO_WORKFORCE_CORE: CoreBinding; TEAM_DOMAIN: string },
  claims: IncomingClaims,
): Promise<boolean> {
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

export function normalizeStaffEmails(input: unknown): string[] {
  if (!Array.isArray(input)) throw new Error("emails must be an array");
  const normalized = input.map((value) => typeof value === "string" ? value.trim().toLowerCase() : "");
  const emails = [...new Set(normalized.filter((value) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)))].sort();
  if (emails.length !== input.length) throw new Error("emails must be unique valid addresses");
  if (emails.length > 250) throw new Error("staff allowlist exceeds safe limit");
  return emails;
}
export function buildStaffPolicyPayload(
  emails: string[],
  env: { EVALUATE_URL: string; KEYS_URL: string },
  precedence = 50,
) {
  return {
    name: "PINO Staff Canonical External Evaluation",
    decision: "allow",
    precedence,
    include: emails.map((email) => ({ email: { email } })),
    exclude: [],
    require: [{ external_evaluation: { evaluate_url: env.EVALUATE_URL, keys_url: env.KEYS_URL } }],
  };
}
