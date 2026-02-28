-- Rollback: 030_password_history.sql
-- Drops the password_history table and removes the trigger/function.

DROP TRIGGER IF EXISTS enforce_password_history ON users;
DROP FUNCTION IF EXISTS check_password_history();
DROP TABLE IF EXISTS password_history;

-- Made with Bob
