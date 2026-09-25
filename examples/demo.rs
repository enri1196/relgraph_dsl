use openfga_dsl::parse_fga_schema;

// Main function for example usage (similar to before)
fn main() {
    let fga_dsl_example_refined = r#"
# This is a model header comment
model
schema 1.1

# This is a module header comment (alternative, only one header is allowed)
# module my_store

# Comment before user type
type user
  # relations for user (if any)

# Comment before group type
type group
  relations
    # 'member' relation allows users or other groups
    define member: [user, group#member with is_self] or [user with is_admin]
    define admin: [user] with is_group_admin # an admin must be a user

# Document type definition
type document
  relations
    define owner: [user]
    # An editor is a user or inherits from writer
    define editor: [user] or writer
    # A writer is a user who can write the doc
    define writer: [user] with can_write_doc
    # Viewer can be a user, a group member, an editor, or inherited
    define viewer: [user, group#member] or editor or (viewer from parent_folder)
    # Can share if owner or admin from parent folder, AND not suspended
    define can_share: (owner or (admin from parent_folder)) and not_suspended_globally
    define parent_folder: [folder] # Relation to another type 'folder'
    define direct_member_with_cond: [user with specific_user_cond]

type folder
  relations
    define viewer: [user, group#member]
    define admin: [user]

# A condition definition
condition is_group_admin(user_id: string, group_id: string) {
  user_id == group_id // Example CEL
}

condition can_write_doc(user_agent: string, ip_addr: ipaddress) {
  user_agent.startsWith("secure_client") && ip_addr.inRange("192.168.1.0/24")
}

condition not_suspended_globally() {
  request.user.status != "suspended"
}

condition is_admin() { true }
condition is_self() { request.user.id == resource.owner_id }
condition specific_user_cond(param1: list<string>, param2: map<int>) {
  param1.size() > 0 && param2.exists(x, x == 42)
}

"#;

    match parse_fga_schema(fga_dsl_example_refined) {
        Ok(schema) => {
            println!("Successfully parsed refined schema: \n{:#?}", schema);
        }
        Err(e) => {
            eprintln!("Failed to parse refined schema:\n{}", e);
        }
    }

    let fga_invalid_mix = r#"
model
schema 1.1
type test
  relations
    define r: writer and editor or owner # Invalid mixing
"#;
    println!(
        "\nAttempting to parse invalid mixing (should fail or parse differently based on new rules):"
    );
    match parse_fga_schema(fga_invalid_mix) {
        Ok(schema) => {
            println!(
                "Parsed invalid mix (unexpected success): \n{:#?}",
                schema.type_definitions[0].relations[0]
                    .definition
                    .expression
            );
        }
        Err(e) => {
            eprintln!("Failed to parse invalid mix (expected):\n{}", e);
        }
    }

    let fga_valid_mix_parens = r#"
model
schema 1.1
type test
  relations
    define r: (writer and editor) or owner # Valid mixing with parens
"#;
    println!("\nAttempting to parse valid mixing with parens:");
    match parse_fga_schema(fga_valid_mix_parens) {
        Ok(schema) => {
            println!(
                "Parsed valid mix with parens: \n{:#?}",
                schema.type_definitions[0].relations[0]
                    .definition
                    .expression
            );
        }
        Err(e) => {
            eprintln!(
                "Failed to parse valid mix with parens (unexpected failure):\n{}",
                e
            );
        }
    }
}
