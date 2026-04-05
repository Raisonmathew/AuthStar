use nanoid::nanoid;

/// Generate a prefixed ID (e.g., "user_abc123xyz")
///
/// # Examples
/// ```
/// use shared_types::generate_id;
/// let user_id = generate_id("user");  // "user_xyz123abc"
/// let org_id = generate_id("org");    // "org_def456ghi"
/// ```
pub fn generate_id(prefix: &str) -> String {
    let alphabet: [char; 62] = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
        'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
        'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    ];

    let id = nanoid!(21, &alphabet);
    format!("{prefix}_{id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_id_format() {
        let id = generate_id("user");
        assert!(id.starts_with("user_"));
        assert_eq!(id.len(), 5 + 21); // "user_" + 21 chars
    }

    #[test]
    fn test_generate_id_unique() {
        let id1 = generate_id("org");
        let id2 = generate_id("org");
        assert_ne!(id1, id2);
    }
}
