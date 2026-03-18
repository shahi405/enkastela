//! Access context — carries caller identity for access control decisions.

/// Represents the caller's identity and role for access control.
#[derive(Debug, Clone)]
pub struct AccessContext {
    /// The caller's role (e.g., "support", "admin", "analytics").
    pub role: String,
    /// Optional caller identifier for audit purposes.
    pub caller_id: Option<String>,
    /// Optional reason for access (for audit trail).
    pub reason: Option<String>,
}

impl AccessContext {
    /// Creates a new access context with the given role.
    pub fn new(role: &str) -> Self {
        Self {
            role: role.to_string(),
            caller_id: None,
            reason: None,
        }
    }

    /// Sets the caller identifier.
    pub fn with_caller(mut self, caller_id: &str) -> Self {
        self.caller_id = Some(caller_id.to_string());
        self
    }

    /// Sets the access reason.
    pub fn with_reason(mut self, reason: &str) -> Self {
        self.reason = Some(reason.to_string());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_context() {
        let ctx = AccessContext::new("support")
            .with_caller("user-123")
            .with_reason("customer support ticket #456");

        assert_eq!(ctx.role, "support");
        assert_eq!(ctx.caller_id.as_deref(), Some("user-123"));
        assert_eq!(ctx.reason.as_deref(), Some("customer support ticket #456"));
    }

    #[test]
    fn context_minimal() {
        let ctx = AccessContext::new("admin");
        assert_eq!(ctx.role, "admin");
        assert!(ctx.caller_id.is_none());
        assert!(ctx.reason.is_none());
    }

    #[test]
    fn with_caller_only() {
        let ctx = AccessContext::new("analyst").with_caller("user-789");
        assert_eq!(ctx.role, "analyst");
        assert_eq!(ctx.caller_id.as_deref(), Some("user-789"));
        assert!(ctx.reason.is_none());
    }

    #[test]
    fn with_reason_only() {
        let ctx = AccessContext::new("auditor").with_reason("quarterly audit");
        assert_eq!(ctx.role, "auditor");
        assert!(ctx.caller_id.is_none());
        assert_eq!(ctx.reason.as_deref(), Some("quarterly audit"));
    }

    #[test]
    fn clone_preserves_all_fields() {
        let ctx = AccessContext::new("support")
            .with_caller("agent-42")
            .with_reason("escalation");
        let cloned = ctx.clone();
        assert_eq!(cloned.role, ctx.role);
        assert_eq!(cloned.caller_id, ctx.caller_id);
        assert_eq!(cloned.reason, ctx.reason);
    }

    #[test]
    fn debug_format_includes_fields() {
        let ctx = AccessContext::new("admin").with_caller("root");
        let debug = format!("{ctx:?}");
        assert!(debug.contains("admin"));
        assert!(debug.contains("root"));
    }
}
