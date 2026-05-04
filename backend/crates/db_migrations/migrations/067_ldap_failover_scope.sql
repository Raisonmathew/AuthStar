-- Migration 067: LDAP connection failover hosts + search scope
--
-- failover_hosts: comma-separated list of fallback LDAP hosts tried in order
--                 when the primary host is unreachable (enterprise HA / multi-DC).
-- search_scope:   LDAP search scope for user and group searches.
--                 'subtree' (default) = recursive from base DN
--                 'onelevel'          = direct children only (flat OUs)
--                 'base'              = the base DN entry itself

ALTER TABLE ldap_connections
    ADD COLUMN IF NOT EXISTS failover_hosts  TEXT         NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS search_scope    VARCHAR(10)  NOT NULL DEFAULT 'subtree';
