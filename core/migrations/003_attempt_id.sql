-- Correlation ID for log lines: every row of oauth_transactions gets a
-- short random attempt_id issued when the flow starts (auth-url) and
-- echoed by the callback + token-exchange log lines, so a single login
-- attempt can be traced end-to-end in gauth.log. Not a security token —
-- safe to log.
ALTER TABLE oauth_transactions ADD COLUMN attempt_id TEXT NOT NULL DEFAULT '';
