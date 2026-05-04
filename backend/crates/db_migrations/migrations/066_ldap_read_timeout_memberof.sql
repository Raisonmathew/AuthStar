-- Migration 066: Add read_timeout_secs and memberof_attr to ldap_connections
-- read_timeout_secs: per-operation read timeout (separate from connect timeout)
-- memberof_attr: attribute used for reverse group-membership lookup (AD: memberOf)

ALTER TABLE ldap_connections
    ADD COLUMN IF NOT EXISTS read_timeout_secs INTEGER NOT NULL DEFAULT 30,
    ADD COLUMN IF NOT EXISTS memberof_attr     VARCHAR(64) NOT NULL DEFAULT 'memberOf';
