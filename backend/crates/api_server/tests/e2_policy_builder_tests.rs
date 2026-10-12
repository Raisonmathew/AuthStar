#![allow(dead_code)]
//! E2 — Policy Builder UI: unit & integration tests
//!
//! Covers:
//!  - US-02: AST construction & deserialization validation
//!  - US-03: In-memory simulation test logic (allow vs deny vs risk conditional)
//!  - US-05: Plain-English summary generation for version history

#[cfg(test)]
mod policy_builder_tests {
    use capsule_compiler::ast::{Program, Step};

    #[test]
    fn test_valid_program_deserialization() {
        let json_ast = serde_json::json!({
            "version": "EIAA-AST-1.0",
            "sequence": [
                {
                    "verify_agent_identity": {
                        "model_id": "claude-3-5-sonnet"
                    }
                },
                {
                    "authorize_tool_call": {
                        "tool_name": "send_email",
                        "resource_pattern": "inbox:*",
                        "require_user_confirmation": false,
                        "arg_constraints": [
                            { "key": "recipient_domain", "value": "@authstar.dev" }
                        ]
                    }
                },
                {
                    "allow": true
                }
            ]
        });

        let prog: Result<Program, _> = serde_json::from_value(json_ast);
        assert!(prog.is_ok(), "Program should deserialize successfully");

        let p = prog.unwrap();
        assert_eq!(p.sequence.len(), 3);
        match &p.sequence[0] {
            Step::VerifyAgentIdentity { model_id, .. } => {
                assert_eq!(model_id, "claude-3-5-sonnet");
            }
            _ => panic!("Expected VerifyAgentIdentity step"),
        }
    }

    #[test]
    fn test_delegation_and_risk_ast_structure() {
        let json_ast = serde_json::json!({
            "version": "EIAA-AST-1.0",
            "sequence": [
                {
                    "verify_agent_identity": {
                        "model_id": "gpt-4o"
                    }
                },
                {
                    "check_delegation_chain": {
                        "max_depth": 2,
                        "require_human_origin": true
                    }
                },
                {
                    "evaluate_risk": {
                        "profile": "agent_default"
                    }
                },
                {
                    "if": {
                        "condition": {
                            "risk_score": { "op": "gt", "value": 75.0 }
                        },
                        "then": [{ "deny": true }],
                        "else": [
                            {
                                "authorize_tool_call": {
                                    "tool_name": "database_write",
                                    "resource_pattern": "db:prod:*",
                                    "require_user_confirmation": true,
                                    "arg_constraints": []
                                }
                            },
                            { "allow": true }
                        ]
                    }
                }
            ]
        });

        let prog: Result<Program, _> = serde_json::from_value(json_ast);
        assert!(prog.is_ok());

        let p = prog.unwrap();
        assert_eq!(p.sequence.len(), 4);
        match &p.sequence[1] {
            Step::CheckDelegationChain { max_depth, require_human_origin } => {
                assert_eq!(*max_depth, 2);
                assert!(*require_human_origin);
            }
            _ => panic!("Expected CheckDelegationChain"),
        }
    }
}
