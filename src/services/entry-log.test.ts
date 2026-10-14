import { describe, expect, it } from 'vitest';
import type { Pass } from '../domain/pass';
import { REASONS } from '../domain/verify';
import { appendEntry, entryFromResult, listEntries, toCsv, type EntryRecord } from './entry-log';
import { createMemoryStore } from './storage';

const granted: EntryRecord = {
  at: '2026-06-02T10:00:00.000Z',
  result: 'granted',
  reason: 'Valid pass',
  passId: 'p1',
  unit: 'Unit 01',
  visitorAlias: 'JR',
};
const denied: EntryRecord = { at: '2026-06-02T11:00:00.000Z', result: 'denied', reason: 'Invalid signature' };

describe('entry log', () => {
  it('is empty for a new store', () => {
    expect(listEntries(createMemoryStore())).toEqual([]);
  });

  it('appends entries in order', () => {
    const store = createMemoryStore();
    appendEntry(store, granted);
    appendEntry(store, denied);
    expect(listEntries(store)).toEqual([granted, denied]);
  });
});

describe('toCsv', () => {
  it('writes a header only for no entries', () => {
    expect(toCsv([])).toBe('at,result,reason,passId,unit,visitorAlias\n');
  });

  it('writes one row per entry and leaves missing fields empty', () => {
    expect(toCsv([granted, denied])).toBe(
      [
        'at,result,reason,passId,unit,visitorAlias',
        '2026-06-02T10:00:00.000Z,granted,Valid pass,p1,Unit 01,JR',
        '2026-06-02T11:00:00.000Z,denied,Invalid signature,,,',
        '',
      ].join('\n'),
    );
  });

  it('quotes cells with commas, quotes and newlines', () => {
    const csv = toCsv([{ ...denied, reason: 'a,"b"\nc' }]);
    expect(csv).toContain('"a,""b""\nc"');
  });

  it('neutralises spreadsheet formulas', () => {
    const csv = toCsv([{ ...denied, visitorAlias: '=HYPERLINK("x")' }]);
    expect(csv).toContain(`"'=HYPERLINK(""x"")"`);
  });
});

describe('entryFromResult', () => {
  const pass: Pass = {
    v: 1,
    id: 'p-42',
    unit: 'Unit 07',
    type: 'one-time',
    validFrom: '2026-06-06T08:00:00.000Z',
    validUntil: '2026-06-07T20:00:00.000Z',
    visitorAlias: 'Aunt B',
  };
  const at = new Date('2026-06-06T12:00:00.000Z');

  it('AC-1: maps a grant to a full entry with the time as ISO UTC', () => {
    expect(entryFromResult({ result: 'granted', reason: REASONS.valid, pass }, at)).toEqual({
      at: '2026-06-06T12:00:00.000Z',
      result: 'granted',
      reason: 'Pass is valid',
      passId: 'p-42',
      unit: 'Unit 07',
      visitorAlias: 'Aunt B',
    });
  });

  it.each([REASONS.blocked, REASONS.notYetValid, REASONS.expired, REASONS.alreadyUsed, REASONS.couldNotRecord])(
    'AC-2: a denial with a valid signature (%s) keeps the pass fields',
    (reason) => {
      expect(entryFromResult({ result: 'denied', reason, pass }, at)).toEqual({
        at: '2026-06-06T12:00:00.000Z',
        result: 'denied',
        reason,
        passId: 'p-42',
        unit: 'Unit 07',
        visitorAlias: 'Aunt B',
      });
    },
  );

  it.each([REASONS.unreadable, REASONS.notAuthentic])('AC-3: a denial for "%s" has no pass fields', (reason) => {
    const entry = entryFromResult({ result: 'denied', reason }, at);
    expect(entry).toEqual({ at: '2026-06-06T12:00:00.000Z', result: 'denied', reason });
    expect(Object.keys(entry)).toEqual(['at', 'result', 'reason']);
  });
});
