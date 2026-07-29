-- Bind a completed migration's sweep txid to its federation version.
--
-- Reorg-reconciliation (Gap 2) needs to answer "was version V's migration sweep
-- reversed?" from wallet ground-truth. Detection compares the backend's
-- `evicted_txids` set against the sweep txid recorded for each `complete`
-- version, so that txid must live on the version row — not only in the
-- `transactions` table keyed by a display `label`.
--
-- Set when the migration tool flips a version to 'complete'; cleared (NULL) when
-- `reconcile_migration` reverts a version back to 'pending' after its sweep was
-- reorged out. This is the minimal test-app-electrum analog of GroupVault's
-- `proposals.txid`.

ALTER TABLE federation_versions
    ADD COLUMN migration_sweep_txid TEXT;  -- set on enact, cleared on revert
