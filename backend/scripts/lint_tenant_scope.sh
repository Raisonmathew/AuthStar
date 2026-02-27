#!/bin/bash
# Tenant Scope Lint — CI Check for G16
#
# Scans all sqlx::query calls in backend crates and flags queries on
# tenant-scoped tables that are missing a tenant_id filter.
#
# Exit code: 0 if all pass, 1 if violations found.
# Usage: bash scripts/lint_tenant_scope.sh

set -e

# Tables that MUST have tenant_id in every query
TENANT_TABLES="sessions|eiaa_executions|audit_logs|eiaa_policies|sso_connections|user_factors"

# Tables that MUST have organization_id in every mutating query
ORG_TABLES="custom_domains|subscriptions|apps|invitations"

VIOLATIONS=0
CHECKED=0

echo "=== Tenant Scope Lint ==="
echo ""

# Check tenant-scoped tables
for raw_file in $(find crates -type d -name src | xargs grep -rl "sqlx::query" --include="*.rs"); do
    file=$(echo "$raw_file" | tr -d '\r')
    # Extract SQL blocks (rough: lines between sqlx::query and .bind or .fetch)
    while IFS= read -r line_info; do
        line_num=$(echo "$line_info" | cut -d: -f1)
        line_content=$(echo "$line_info" | cut -d: -f2-)

        # Check if line contains a tenant-scoped table reference
        if echo "$line_content" | grep -qiE "FROM\s+($TENANT_TABLES)" || \
           echo "$line_content" | grep -qiE "INTO\s+($TENANT_TABLES)" || \
           echo "$line_content" | grep -qiE "UPDATE\s+($TENANT_TABLES)"; then
            CHECKED=$((CHECKED + 1))

            # Check if tenant_id appears in the same query context (within 15 lines)
            context=$(sed -n "$((line_num)),$((line_num + 15))p" "$file")
            if ! echo "$context" | grep -q "tenant_id"; then
                echo "VIOLATION: $file:$line_num"
                echo "  Table query without tenant_id filter:"
                echo "  $line_content"
                echo ""
                VIOLATIONS=$((VIOLATIONS + 1))
            fi
        fi
    done < <(grep -n "FROM\|INTO\|UPDATE" "$file" 2>/dev/null || true)
done

echo "Checked $CHECKED scoped queries"

if [ "$VIOLATIONS" -gt 0 ]; then
    echo ""
    echo "FAILED: $VIOLATIONS violation(s) found"
    echo "All queries on tenant-scoped tables must include 'AND tenant_id = \$N'"
    exit 1
else
    echo "PASSED: All scoped queries have tenant_id filters"
    exit 0
fi
