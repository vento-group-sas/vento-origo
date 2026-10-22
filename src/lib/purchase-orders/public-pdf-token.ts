import crypto from "node:crypto";

// Public links are short lived; authenticated PDF access remains separate.
const TOKEN_MAX_AGE_SECONDS = 60 * 60 * 24;
const MAX_CLOCK_SKEW_SECONDS = 60;

function getSecret(): string {
  const secret = process.env.PURCHASE_ORDER_PDF_SECRET?.trim();
  if (!secret || Buffer.byteLength(secret, "utf8") < 32) {
    throw new Error("PURCHASE_ORDER_PDF_SECRET must be configured with at least 32 bytes");
  }
  return secret;
}

function sign(poId: string, issuedAtSec: number): string {
  const payload = `${poId}.${issuedAtSec}`;
  return crypto.createHmac("sha256", getSecret()).update(payload).digest("hex");
}

export function createPurchaseOrderPdfToken(poId: string): string {
  const issuedAtSec = Math.floor(Date.now() / 1000);
  const signature = sign(poId, issuedAtSec);
  return `${issuedAtSec}.${signature}`;
}

export function verifyPurchaseOrderPdfToken(poId: string, token: string): boolean {
  const match = /^([0-9]{10})\.([a-f0-9]{64})$/.exec(String(token ?? "").trim());
  if (!match) return false;

  const issuedAtSec = Number(match[1]);
  const nowSec = Math.floor(Date.now() / 1000);
  if (issuedAtSec > nowSec + MAX_CLOCK_SKEW_SECONDS ||
      nowSec - issuedAtSec > TOKEN_MAX_AGE_SECONDS) return false;

  try {
    const expected = Buffer.from(sign(poId, issuedAtSec), "hex");
    const supplied = Buffer.from(match[2], "hex");
    return expected.length === supplied.length && crypto.timingSafeEqual(supplied, expected);
  } catch {
    return false;
  }
}

