import { describe, expect, it } from 'vitest';
import { DEMO_KEYS } from '../data/demo-keys';
import { textToBase64url } from '../lib/base64url';
import { importPrivateKey, importPublicKey, signPass } from '../services/signing';
import type { Ledger } from './ledger';
import type { Pass } from './pass';
import { verifyPass } from './verify';

const basePass: Pass = {
  v: 1,
  id: '7d1e2f30-4a5b-4c6d-8e9f-0a1b2c3d4e5f',
  unit: 'Unit 07',
  type: 'date-range',
  validFrom: '2026-06-06T08:00:00.000Z',
  validUntil: '2026-06-07T20:00:00.000Z',
  visitorAlias: 'Aunt B',
};
const BLOCKLIST = ['Mr Nobody', 'XX'];
const EMPTY_LEDGER: Ledger = {};
const INSIDE = new Date('2026-06-06T12:00:00.000Z');

async function sign(overrides: Partial<Pass> = {}): Promise<{ pass: Pass; token: string }> {
  const pass = { ...basePass, ...overrides };
  return { pass, token: await signPass(pass, await importPrivateKey(DEMO_KEYS.privateKey)) };
}

async function verify(token: string | null, now: Date, ledger: Ledger = EMPTY_LEDGER) {
  return verifyPass(token, now, ledger, BLOCKLIST, await importPublicKey(DEMO_KEYS.publicKey));
}

const ms = (iso: string, delta: number) => new Date(Date.parse(iso) + delta);

describe('verifyPass', () => {
  it('AC-1: grants a valid date-range pass inside its window', async () => {
    const { pass, token } = await sign();
    expect(await verify(token, INSIDE)).toEqual({ result: 'granted', reason: 'Pass is valid', pass });
  });

  describe('AC-2: unreadable tokens', () => {
    const payloadOf = (value: unknown) => textToBase64url(JSON.stringify(value));
    const cases: [string, string | null][] = [
      ['null', null],
      ['empty', ''],
      ['one segment', 'abc'],
      ['three segments', 'a.b.c'],
      ['payload not base64url', '!!!.abc'],
      ['payload not JSON', `${textToBase64url('not json')}.abc`],
      ['wrong version', `${payloadOf({ ...basePass, v: 2 })}.abc`],
      ['missing field', `${payloadOf({ ...basePass, unit: undefined })}.abc`],
      ['unknown type', `${payloadOf({ ...basePass, type: 'forever' })}.abc`],
      ['bad date', `${payloadOf({ ...basePass, validFrom: 'soon' })}.abc`],
    ];
    it.each(cases)('denies %s with "No valid pass in this link"', async (_name, token) => {
      expect(await verify(token, INSIDE)).toEqual({ result: 'denied', reason: 'No valid pass in this link' });
    });
  });

  it('AC-3: denies a payload changed after signing as not authentic', async () => {
    const { token } = await sign();
    const [, signature] = token.split('.');
    const forged = `${textToBase64url(JSON.stringify({ ...basePass, validUntil: '2027-01-01T00:00:00.000Z' }))}.${signature}`;
    expect(await verify(forged, INSIDE)).toEqual({ result: 'denied', reason: 'Pass is not authentic' });
  });

  it('AC-3: denies a signature that is not valid base64url as not authentic', async () => {
    const { token } = await sign();
    const [payload] = token.split('.');
    expect(await verify(`${payload}.@@@`, INSIDE)).toEqual({ result: 'denied', reason: 'Pass is not authentic' });
  });

  it('AC-4: denies a blocked alias even with valid dates and an unused pass', async () => {
    const { pass, token } = await sign({ visitorAlias: 'Mr Nobody' });
    expect(await verify(token, INSIDE)).toEqual({ result: 'denied', reason: 'Visitor is blocked', pass });
  });

  it('AC-5: denies 1 ms before validFrom as not valid yet', async () => {
    const { token } = await sign();
    expect(await verify(token, ms(basePass.validFrom, -1))).toMatchObject({
      result: 'denied',
      reason: 'Pass is not valid yet',
    });
  });

  it('AC-5: grants exactly at validFrom', async () => {
    const { token } = await sign();
    expect(await verify(token, ms(basePass.validFrom, 0))).toMatchObject({ result: 'granted' });
  });

  it('AC-6: grants exactly at validUntil', async () => {
    const { token } = await sign();
    expect(await verify(token, ms(basePass.validUntil, 0))).toMatchObject({ result: 'granted' });
  });

  it('AC-6: denies 1 ms after validUntil as expired', async () => {
    const { token } = await sign();
    expect(await verify(token, ms(basePass.validUntil, 1))).toMatchObject({
      result: 'denied',
      reason: 'Pass has expired',
    });
  });

  it('AC-7: grants a pass with validFrom equal to validUntil at that instant', async () => {
    const instant = '2026-06-06T09:30:00.000Z';
    const { token } = await sign({ validFrom: instant, validUntil: instant });
    expect(await verify(token, new Date(instant))).toMatchObject({ result: 'granted' });
  });

  it('AC-8: denies a one-time pass that is already in the ledger', async () => {
    const { pass, token } = await sign({ type: 'one-time' });
    const ledger: Ledger = { [pass.id]: '2026-06-06T10:00:00.000Z' };
    expect(await verify(token, INSIDE, ledger)).toEqual({ result: 'denied', reason: 'Pass already used', pass });
  });

  it('AC-8: grants an unused one-time pass', async () => {
    const { token } = await sign({ type: 'one-time' });
    expect(await verify(token, INSIDE)).toMatchObject({ result: 'granted', reason: 'Pass is valid' });
  });

  it('AC-8: ignores the ledger for a date-range pass', async () => {
    const { pass, token } = await sign();
    const ledger: Ledger = { [pass.id]: '2026-06-06T10:00:00.000Z' };
    expect(await verify(token, INSIDE, ledger)).toMatchObject({ result: 'granted' });
  });

  it('AC-9: a blocked alias wins over an expired pass', async () => {
    const { token } = await sign({ visitorAlias: 'XX' });
    expect(await verify(token, ms(basePass.validUntil, 1))).toMatchObject({ reason: 'Visitor is blocked' });
  });

  it('AC-10: an alias that differs only in case is not blocked (D-8)', async () => {
    const { token } = await sign({ visitorAlias: 'mr nobody' });
    expect(await verify(token, INSIDE)).toMatchObject({ result: 'granted' });
  });

  it('edge: a bad signature wins over a blocked alias', async () => {
    const { token } = await sign({ visitorAlias: 'XX' });
    const [, signature] = token.split('.');
    const forged = `${textToBase64url(JSON.stringify({ ...basePass, visitorAlias: 'XX', unit: 'Unit 01' }))}.${signature}`;
    expect(await verify(forged, INSIDE)).toEqual({ result: 'denied', reason: 'Pass is not authentic' });
  });
});
