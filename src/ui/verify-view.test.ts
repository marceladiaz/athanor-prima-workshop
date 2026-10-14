// @vitest-environment jsdom
import { describe, expect, it } from 'vitest';
import { DEMO_KEYS } from '../data/demo-keys';
import type { Pass } from '../domain/pass';
import { ENTRIES_KEY, listEntries } from '../services/entry-log';
import { LEDGER_KEY } from '../services/ledger';
import { importPrivateKey, importPublicKey, signPass } from '../services/signing';
import { createMemoryStore, type KeyValueStore } from '../services/storage';
import { renderVerifyView } from './verify-view';

const basePass: Pass = {
  v: 1,
  id: '5b6c7d8e-9f0a-4b1c-8d2e-3f4a5b6c7d8e',
  unit: 'Unit 07',
  type: 'date-range',
  validFrom: '2026-06-06T08:00:00.000Z',
  validUntil: '2026-06-07T20:00:00.000Z',
  visitorAlias: 'Aunt B',
};
const NOW = new Date('2026-06-06T12:00:00.000Z');

async function tokenFor(overrides: Partial<Pass> = {}): Promise<string> {
  return signPass({ ...basePass, ...overrides }, await importPrivateKey(DEMO_KEYS.privateKey));
}

async function render(token: string | null, store: KeyValueStore = createMemoryStore()): Promise<HTMLElement> {
  const root = document.createElement('main');
  await renderVerifyView(root, {
    token,
    now: NOW,
    store,
    blocklist: ['Mr Nobody'],
    publicKey: await importPublicKey(DEMO_KEYS.publicKey),
  });
  return root;
}

function failingLedgerStore(): KeyValueStore {
  const inner = createMemoryStore();
  return {
    getItem: (key) => inner.getItem(key),
    setItem: (key, value) => {
      if (key === LEDGER_KEY) {
        throw new Error('QuotaExceededError');
      }
      inner.setItem(key, value);
    },
  };
}

describe('renderVerifyView', () => {
  it('AC-1: shows ACCESS GRANTED, the reason, unit and alias for a valid date-range pass', async () => {
    const text = (await render(await tokenFor())).textContent ?? '';
    expect(text).toContain('ACCESS GRANTED');
    expect(text).toContain('Pass is valid');
    expect(text).toContain('Unit 07');
    expect(text).toContain('Aunt B');
    expect(text).not.toContain('One-time pass');
  });

  it('AC-2: grants an unused one-time pass, adds the one-time line, and records it in the ledger', async () => {
    const store = createMemoryStore();
    const text = (await render(await tokenFor({ type: 'one-time' }), store)).textContent ?? '';
    expect(text).toContain('ACCESS GRANTED');
    expect(text).toContain('One-time pass. It cannot be used again.');
    expect(JSON.parse(store.getItem(LEDGER_KEY) ?? '{}')).toEqual({ [basePass.id]: NOW.toISOString() });
  });

  it('AC-3: denies the same one-time link on a second load with "Pass already used"', async () => {
    const store = createMemoryStore();
    const token = await tokenFor({ type: 'one-time' });
    await render(token, store);
    const text = (await render(token, store)).textContent ?? '';
    expect(text).toContain('ACCESS DENIED');
    expect(text).toContain('Pass already used');
  });

  it('AC-4: a denied result shows the reason only and leaves the ledger unchanged', async () => {
    const store = createMemoryStore();
    const root = await render(await tokenFor({ type: 'one-time', visitorAlias: 'Mr Nobody' }), store);
    const text = root.textContent ?? '';
    expect(text).toContain('ACCESS DENIED');
    expect(text).toContain('Visitor is blocked');
    expect(text).not.toContain('Unit 07');
    expect(text).not.toContain('Mr Nobody');
    expect(store.getItem(LEDGER_KEY)).toBeNull();
  });

  it('AC-5: denies a one-time pass with "Could not record pass use" when the ledger write fails', async () => {
    const text = (await render(await tokenFor({ type: 'one-time' }), failingLedgerStore())).textContent ?? '';
    expect(text).toContain('ACCESS DENIED');
    expect(text).toContain('Could not record pass use');
    expect(text).not.toContain('ACCESS GRANTED');
  });

  it('AC-6: a granted date-range pass does not write the ledger', async () => {
    const store = createMemoryStore();
    await render(await tokenFor(), store);
    expect(store.getItem(LEDGER_KEY)).toBeNull();
  });

  it('AC-7: shows markup in the alias as literal text', async () => {
    const root = await render(await tokenFor({ visitorAlias: '<b>x</b>' }));
    expect(root.querySelector('b')).toBeNull();
    expect(root.textContent).toContain('<b>x</b>');
  });

  it('AC-8: every result has text and an icon hidden from screen readers, and no navigation', async () => {
    for (const root of [await render(await tokenFor()), await render(null)]) {
      const icon = root.querySelector('.result-icon');
      expect(icon?.getAttribute('aria-hidden')).toBe('true');
      expect(icon?.textContent).not.toBe('');
      expect(root.querySelector('h1')?.textContent).toMatch(/^ACCESS (GRANTED|DENIED)$/);
      expect(root.querySelector('nav, a')).toBeNull();
    }
  });

  it('AC-9: a link with no token shows "No valid pass in this link"', async () => {
    const text = (await render(null)).textContent ?? '';
    expect(text).toContain('ACCESS DENIED');
    expect(text).toContain('No valid pass in this link');
  });
});

describe('renderVerifyView log entry (US-11)', () => {
  function failingLogStore(): KeyValueStore {
    const inner = createMemoryStore();
    return {
      getItem: (key) => inner.getItem(key),
      setItem: (key, value) => {
        if (key === ENTRIES_KEY) {
          throw new Error('QuotaExceededError');
        }
        inner.setItem(key, value);
      },
    };
  }

  it('AC-4: appends exactly one entry per page load', async () => {
    const store = createMemoryStore();
    const token = await tokenFor();
    await render(token, store);
    expect(listEntries(store)).toEqual([
      {
        at: NOW.toISOString(),
        result: 'granted',
        reason: 'Pass is valid',
        passId: basePass.id,
        unit: 'Unit 07',
        visitorAlias: 'Aunt B',
      },
    ]);
    await render(token, store);
    expect(listEntries(store)).toHaveLength(2);
  });

  it('AC-4: logs a denied attempt with no trusted fields when there is no token', async () => {
    const store = createMemoryStore();
    await render(null, store);
    expect(listEntries(store)).toEqual([
      { at: NOW.toISOString(), result: 'denied', reason: 'No valid pass in this link' },
    ]);
  });

  it('AC-5: a failed log write does not change the screen', async () => {
    const token = await tokenFor();
    const ok = (await render(token)).innerHTML;
    const failed = (await render(token, failingLogStore())).innerHTML;
    expect(failed).toBe(ok);
  });

  it('AC-6: a failed ledger write is logged as "Could not record pass use" with the pass fields', async () => {
    const store = failingLedgerStore();
    await render(await tokenFor({ type: 'one-time' }), store);
    expect(listEntries(store)).toEqual([
      {
        at: NOW.toISOString(),
        result: 'denied',
        reason: 'Could not record pass use',
        passId: basePass.id,
        unit: 'Unit 07',
        visitorAlias: 'Aunt B',
      },
    ]);
  });
});
