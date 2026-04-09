-- Fix trigger_refresh_policy_compiled: on policy_builder_configs the PK is 'id',
-- not 'config_id' which only exists on child tables (rule_groups, rules, conditions).
-- PL/pgSQL validates ALL record field references at compile time even in untaken CASE branches,
-- so we must use separate trigger functions for the configs table vs child tables.

-- 1. Trigger function for the parent configs table (uses NEW.id)
CREATE OR REPLACE FUNCTION trigger_refresh_policy_compiled_config()
RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('policy_compiled_refresh',
        json_build_object(
            'config_id', COALESCE(NEW.id, OLD.id),
            'operation', TG_OP
        )::text
    );
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

-- 2. Trigger function for child tables (uses NEW.config_id)
CREATE OR REPLACE FUNCTION trigger_refresh_policy_compiled_child()
RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('policy_compiled_refresh',
        json_build_object(
            'config_id', COALESCE(NEW.config_id, OLD.config_id),
            'operation', TG_OP
        )::text
    );
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

-- 3. Re-attach triggers with the correct function
DROP TRIGGER IF EXISTS trigger_config_refresh ON policy_builder_configs;
CREATE TRIGGER trigger_config_refresh
    AFTER INSERT OR UPDATE OR DELETE ON policy_builder_configs
    FOR EACH ROW EXECUTE FUNCTION trigger_refresh_policy_compiled_config();

DROP TRIGGER IF EXISTS trigger_group_refresh ON policy_builder_rule_groups;
CREATE TRIGGER trigger_group_refresh
    AFTER INSERT OR UPDATE OR DELETE ON policy_builder_rule_groups
    FOR EACH ROW EXECUTE FUNCTION trigger_refresh_policy_compiled_child();

DROP TRIGGER IF EXISTS trigger_rule_refresh ON policy_builder_rules;
CREATE TRIGGER trigger_rule_refresh
    AFTER INSERT OR UPDATE OR DELETE ON policy_builder_rules
    FOR EACH ROW EXECUTE FUNCTION trigger_refresh_policy_compiled_child();

DROP TRIGGER IF EXISTS trigger_condition_refresh ON policy_builder_conditions;
CREATE TRIGGER trigger_condition_refresh
    AFTER INSERT OR UPDATE OR DELETE ON policy_builder_conditions
    FOR EACH ROW EXECUTE FUNCTION trigger_refresh_policy_compiled_child();
