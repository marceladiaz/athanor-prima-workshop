// Verification policy (prd.md R-6). Pure rules: `now` is a parameter, no storage, no clock.
// Checks run in a fixed order and stop at the first failure.

import { base64urlToBytes, base64urlToText } from '../lib/base64url';
import { isBlocked } from './blocklist';
import { isPassUsed, type Ledger } from './ledger';
import type { Pass } from './pass';

export const REASONS = {
  unreadable: 'No valid pass in this link',
  notAuthentic: 'Pass is not authentic',
  blocked: 'Visitor is blocked',
  notYetValid: 'Pass is not valid yet',
  expired: 'Pass has expired',
  alreadyUsed: 'Pass already used',
  couldNotRecord: 'Could not record pass use',
  valid: 'Pass is valid',
} as const;

export type Reason = (typeof REASONS)[keyof typeof REASONS];

/** `pass` is present only when the signature was valid, so its fields can be trusted. */
export interface VerifyResult {
  readonly result: 'granted' | 'denied';
  readonly reason: Reason;
  readonly pass?: Pass;
}

const SIGN_PARAMS = { name: 'ECDSA', hash: 'SHA-256' } as const;

function isIsoTime(value: unknown): value is string {
  return typeof value === 'string' && !Number.isNaN(Date.parse(value));
}

function isPass(value: unknown): value is Pass {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const p = value as Record<string, unknown>;
  return (
    p.v === 1 &&
    typeof p.id === 'string' &&
    typeof p.unit === 'string' &&
    (p.type === 'one-time' || p.type === 'date-range') &&
    isIsoTime(p.validFrom) &&
    isIsoTime(p.validUntil) &&
    typeof p.visitorAlias === 'string'
  );
}

/** Step 0: split the token and decode the payload. Returns null when it cannot be read. */
function readToken(token: string | null): { payload: string; signature: string; pass: Pass } | null {
  const parts = (token ?? '').split('.');
  if (parts.length !== 2) {
    return null;
  }
  const [payload = '', signature = ''] = parts;
  try {
    const pass: unknown = JSON.parse(base64urlToText(payload));
    return isPass(pass) ? { payload, signature, pass } : null;
  } catch {
    return null;
  }
}

async function hasValidSignature(payload: string, signature: string, publicKey: CryptoKey): Promise<boolean> {
  try {
    return await crypto.subtle.verify(
      SIGN_PARAMS,
      publicKey,
      base64urlToBytes(signature),
      new TextEncoder().encode(payload),
    );
  } catch {
    return false;
  }
}

export async function verifyPass(
  token: string | null,
  now: Date,
  ledger: Ledger,
  blocklist: readonly string[],
  publicKey: CryptoKey,
): Promise<VerifyResult> {
  const read = readToken(token);
  if (read === null) {
    return { result: 'denied', reason: REASONS.unreadable };
  }
  if (!(await hasValidSignature(read.payload, read.signature, publicKey))) {
    return { result: 'denied', reason: REASONS.notAuthentic };
  }

  const { pass } = read;
  const deny = (reason: Reason): VerifyResult => ({ result: 'denied', reason, pass });
  const time = now.getTime();

  if (isBlocked(pass.visitorAlias, blocklist)) {
    return deny(REASONS.blocked);
  }
  if (time < Date.parse(pass.validFrom)) {
    return deny(REASONS.notYetValid);
  }
  if (time > Date.parse(pass.validUntil)) {
    return deny(REASONS.expired);
  }
  if (pass.type === 'one-time' && isPassUsed(ledger, pass.id)) {
    return deny(REASONS.alreadyUsed);
  }
  return { result: 'granted', reason: REASONS.valid, pass };
}
