CREATE TABLE SpendPlans (
    plan_id TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('PREPARED', 'SIGNED', 'BROADCAST_UNKNOWN', 'BROADCASTED', 'CANCELLED', 'EXPIRED')),
    plan_json TEXT NOT NULL,
    fee_rate INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    signed_raw TEXT,
    txid TEXT,
    date_updated INTEGER NOT NULL
);
CREATE UNIQUE INDEX idx_SpendPlans_txid ON SpendPlans(txid) WHERE txid IS NOT NULL;
CREATE TABLE SpendReservations (
    tx_hash BLOB NOT NULL,
    tx_index INTEGER NOT NULL,
    plan_id TEXT NOT NULL REFERENCES SpendPlans(plan_id),
    PRIMARY KEY(tx_hash, tx_index)
);
