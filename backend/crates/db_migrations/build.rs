fn main() {
    // Ensure migration metadata is refreshed when SQL files change.
    println!("cargo:rerun-if-changed=migrations");
}
