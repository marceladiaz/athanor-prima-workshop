// Verify screen (PG-3). Runs the verification policy and shows a full-screen result.
// The caller reads the clock once and passes `now` in, so the screen stays testable.

import type { Ledger } from '../domain/ledger';
import { REASONS, verifyPass, type VerifyResult } from '../domain/verify';
import { appendEntry, entryFromResult } from '../services/entry-log';
import { markPassUsed, readLedger } from '../services/ledger';
import type { KeyValueStore } from '../services/storage';
import { el } from './dom';

export interface VerifyViewInput {
  readonly token: string | null;
  readonly now: Date;
  readonly store: KeyValueStore;
  readonly blocklist: readonly string[];
  readonly publicKey: CryptoKey;
}

/** An unreadable ledger counts as empty; recording a one-time pass then fails and denies it (D-12). */
function safeReadLedger(store: KeyValueStore): Ledger {
  try {
    return readLedger(store);
  } catch {
    return {};
  }
}

/** Runs the policy, then records a granted one-time pass as used (D-7). A failed write denies (D-12). */
async function decide(input: VerifyViewInput): Promise<VerifyResult> {
  const { token, now, store, blocklist, publicKey } = input;
  const outcome = await verifyPass(token, now, safeReadLedger(store), blocklist, publicKey);
  if (outcome.result !== 'granted' || outcome.pass?.type !== 'one-time') {
    return outcome;
  }
  try {
    markPassUsed(store, outcome.pass.id, now.toISOString());
    return outcome;
  } catch {
    return { result: 'denied', reason: REASONS.couldNotRecord, pass: outcome.pass };
  }
}

function resultPanel(outcome: VerifyResult): HTMLElement {
  const granted = outcome.result === 'granted';
  const panel = el(
    'section',
    { class: `result ${granted ? 'result-granted' : 'result-denied'}`, role: 'status' },
    el('span', { class: 'result-icon', 'aria-hidden': 'true' }, granted ? '✓' : '✗'),
    el('h1', {}, granted ? 'ACCESS GRANTED' : 'ACCESS DENIED'),
    el('p', { class: 'result-reason' }, outcome.reason),
  );
  if (granted && outcome.pass) {
    panel.append(
      el('p', {}, `Unit: ${outcome.pass.unit}`),
      el('p', {}, `Visitor: ${outcome.pass.visitorAlias}`),
    );
    if (outcome.pass.type === 'one-time') {
      panel.append(el('p', {}, 'One-time pass. It cannot be used again.'));
    }
  }
  return panel;
}

/** Appends one entry per attempt (D-9). A failed write never changes the result on screen (D-12). */
function logAttempt(store: KeyValueStore, outcome: VerifyResult, now: Date): void {
  try {
    appendEntry(store, entryFromResult(outcome, now));
  } catch {
    // Ignored on purpose: the guard still needs the result.
  }
}

export async function renderVerifyView(root: HTMLElement, input: VerifyViewInput): Promise<void> {
  const outcome = await decide(input);
  logAttempt(input.store, outcome, input.now);
  root.replaceChildren(resultPanel(outcome));
}
