-- Existing deltas cannot be distinguished from historical placeholders.
ALTER TABLE TransactionDeltas ADD COLUMN value_known INTEGER NOT NULL DEFAULT 0;
