-- EMV-8 — account indices must never be reissued.
--
-- `next_account_idx` / `next_elements_account_idx` were
-- `SELECT COALESCE(MAX(account_idx) + 1, 0)` over the live table. That is a
-- high-water mark of *surviving* rows, not an allocator: delete a wallet and its
-- index is handed out again, so the next user provisioned derives
-- `m/48'/{coin}'/{account_idx}'/2'` to the **same HSM keys, the same
-- wsh(sortedmulti(..)) descriptor and the same addresses** as the deleted user.
-- They can spend whatever is still sitting there and silently receive any later
-- deposit meant for the previous holder.
--
-- ▶ `UNIQUE (account_idx)` never fired and never could. It constrains rows that
-- EXIST; the invariant being violated is over rows that EVER existed. Deleting
-- before re-inserting passes the constraint without it ever being consulted,
-- which is why the column was `UNIQUE` throughout and the defect was still
-- silent. Observed 2026-11-24: two users, two wallet rows, account index 110
-- both times, byte-identical descriptor and address, one shared on-chain wallet.
--
-- Sequences fix it because `nextval` is monotonic, is NOT rolled back by a
-- failed transaction, and is indifferent to deletes.

CREATE SEQUENCE IF NOT EXISTS wallets_account_idx_seq AS integer MINVALUE 0;
CREATE SEQUENCE IF NOT EXISTS elements_wallets_account_idx_seq AS integer MINVALUE 0;

-- Seed each sequence above its table's current maximum, plus a margin.
--
-- ▶ The margin is the load-bearing part, not padding. Indices belonging to rows
-- that have ALREADY been deleted are unknowable from the surviving table, so
-- seeding at exactly `MAX` would re-issue any index sitting in a gap — the very
-- bug this migration closes, reintroduced by its own fix. 1000 covers every gap
-- these databases can plausibly hold.
--
-- `setval` sets `last_value`, so the first `nextval` returns MAX + 1001.
--
-- ▶ Deliberately seeded per table rather than from the maximum across both.
-- The plan's wording said "across both tables"; that was over-cautious and I am
-- not implementing it. The two index spaces are independent — a gap in
-- `wallets` tells you nothing about `elements_wallets` — and coupling them would
-- drag Bitcoin indices up into the 1.4-million range on this dev database purely
-- because an unrelated Elements contract test seeds high indices. The margin,
-- not cross-table coupling, is what covers deleted rows.
SELECT setval(
    'wallets_account_idx_seq',
    COALESCE((SELECT MAX(account_idx) FROM wallets), 0) + 1000
);
SELECT setval(
    'elements_wallets_account_idx_seq',
    COALESCE((SELECT MAX(account_idx) FROM elements_wallets), 0) + 1000
);

-- `UNIQUE (account_idx)` stays on both tables. It is useless against reuse, but
-- it is the guard that catches two *concurrent* allocations landing on one
-- index, which is a different failure and still worth failing loudly.

-- ▶ A UNIQUE index on `descriptor` was drafted here and DELIBERATELY REMOVED.
-- Tracked separately as EMV-11.
--
-- The idea is sound and borrowed from GroupVault's `federations.descriptor_hash`
-- live partial unique index: the descriptor is what actually identifies an
-- on-chain wallet, so no two rows should carry the same one. It would not have
-- caught EMV-8 — that is a guard over live rows and EMV-8's two rows never
-- coexisted — but it does catch every *other* route to one shared wallet, most
-- importantly an identical signer set and threshold assembling the same
-- `wsh(sortedmulti(..))`, which is GroupVault F13 proper.
--
-- It cannot land yet, and the reason is worth recording rather than retrying:
--
--     could not create unique index "elements_wallets_descriptor_key"
--     Key (descriptor)=(desc) is duplicated.
--
-- The duplicates are **test fixtures**, not wallets. `elements_sync`'s
-- `seed_wallet` inserts the literal `descriptor = 'desc'` for every row it
-- creates, and those rows accumulate in the shared `asterism_pkcs11` database —
-- the same non-hermetic-fixture problem as EMV-7. Landing the guard therefore
-- needs the fixtures to use distinct descriptors AND the existing duplicate rows
-- resolved first; doing it here would mean either deleting data this migration
-- has no business touching, or encoding the fixture's placeholder value into a
-- production index predicate.
