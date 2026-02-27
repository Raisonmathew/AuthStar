//! Exclusive XML Canonicalization (http://www.w3.org/2001/10/xml-exc-c14n#)
//!
//! This module implements a subset of Exclusive C14N required for verifying SAML signatures.
//! It canonicalizes a roxmltree::Node and its descendants.

use roxmltree::Node;
use std::collections::{BTreeMap, HashSet};
use std::fmt::Write;
use shared_types::Result;

#[derive(Clone, Copy)]
pub enum CanonicalizeFilter {
    None,
    ExcludeSignature,
}

/// Canonicalize an XML Node using Exclusive C14N
pub fn canonicalize(node: &Node) -> Result<String> {
    canonicalize_with_filter(node, CanonicalizeFilter::None)
}

pub fn canonicalize_excluding_signature(node: &Node) -> Result<String> {
    canonicalize_with_filter(node, CanonicalizeFilter::ExcludeSignature)
}

fn canonicalize_with_filter(node: &Node, filter: CanonicalizeFilter) -> Result<String> {
    let mut buffer = String::new();
    // For Exclusive C14N, we need to track rendered namespaces.
    // Map prefix -> uri
    let mut rendered_namespaces: Vec<BTreeMap<String, String>> = Vec::new();
    rendered_namespaces.push(BTreeMap::new()); // Root scope

    process_node(node, &mut buffer, &mut rendered_namespaces, filter)?;

    Ok(buffer)
}

fn process_node(
    node: &Node, 
    buf: &mut String, 
    rendered_scopes: &mut Vec<BTreeMap<String, String>>,
    filter: CanonicalizeFilter,
) -> Result<()> {
    if matches!(filter, CanonicalizeFilter::ExcludeSignature) && node.has_tag_name("Signature") {
        return Ok(());
    }
    match node.node_type() {
        roxmltree::NodeType::Element => process_element(node, buf, rendered_scopes, filter),
        roxmltree::NodeType::Text => {
            let text = node.text().unwrap_or("");
            buf.push_str(&escape_text(text));
            Ok(())
        },
        roxmltree::NodeType::Root => {
            for child in node.children() {
                process_node(&child, buf, rendered_scopes, filter)?;
            }
            Ok(())
        },
        _ => Ok(()), 
    }
}

fn process_element(
    node: &Node, 
    buf: &mut String,
    rendered_scopes: &mut Vec<BTreeMap<String, String>>,
    filter: CanonicalizeFilter,
) -> Result<()> {
    // 1. Determine QName
    let qname = get_qname(node);
    
    // 2. Open Tag
    write!(buf, "<{}", qname).unwrap();
    
    // 3. Namespace Handling (Exclusive C14N)
    // We need to render namespaces that are:
    // a) Visibly utilized (by element or attributes)
    // b) NOT already in the rendered scope with the same URI
    
    let mut new_scope = rendered_scopes.last().unwrap().clone();
    let mut namespaces_to_render = BTreeMap::new();
    
    // 3.1 Identify Utilized Prefixes
    let mut utilized_prefixes = HashSet::new();
    
    // Element prefix
    let (tag_prefix, _) = split_qname(&qname);
    utilized_prefixes.insert(tag_prefix.to_string());
    
    // Attribute prefixes
    // Also collect attributes for sorting later
    let mut attributes = BTreeMap::new();
    for attr in node.attributes() {
        let attr_qname = get_attr_qname(node, &attr);
        let (attr_prefix, _) = split_qname(&attr_qname);
        if !attr_prefix.is_empty() {
             utilized_prefixes.insert(attr_prefix.to_string());
        }
        attributes.insert(attr_qname, escape_attribute(attr.value()));
    }
    
    // 3.2 Determine Namespace Declarations needed
    for prefix in utilized_prefixes {
        let uri = if prefix.is_empty() {
            node.default_namespace().unwrap_or("")
        } else {
            node.lookup_namespace_uri(Some(prefix.as_str())).unwrap_or("")
        };
        
        if uri.is_empty() && prefix.is_empty() {
            // Default namespace empty, and not used? checking if we need to emit xmlns=""
            // If xmlns default is currently mapped to something in scope, we MUST emit xmlns="" to undeclare it
            if let Some(current_def) = new_scope.get("") {
                if !current_def.is_empty() {
                    namespaces_to_render.insert("".to_string(), "".to_string());
                    new_scope.insert("".to_string(), "".to_string());
                }
            }
            continue;
        }

        if uri.is_empty() {
            continue; // Should not happen for valid XML if prefix is used
        }

        // Check availability in scope
        let current_uri = new_scope.get(&prefix).map(|s| s.as_str());
        if current_uri != Some(uri) {
            // Needs declaration
            namespaces_to_render.insert(prefix.clone(), uri.to_string());
            new_scope.insert(prefix, uri.to_string());
        }
    }
    
    // 3.3 Explicit declarations on the node (that might not be utilized but ARE declared)
    // Exclusive C14N: We behave as if we only render utilized.
    
    // 4. Render Namespaces (Sorted by prefix)
    let mut sorted_ns_output = BTreeMap::new();
    for (prefix, uri) in namespaces_to_render {
        if prefix.is_empty() {
            sorted_ns_output.insert("xmlns".to_string(), uri);
        } else {
            sorted_ns_output.insert(format!("xmlns:{}", prefix), uri);
        }
    }
    
    for (key, uri) in sorted_ns_output {
        write!(buf, " {}=\"{}\"", key, uri).unwrap();
    }
    
    // 5. Render Attributes (Sorted by QName)
    let mut sorted_attrs = BTreeMap::new();
    for attr in node.attributes() {
        let attr_local = attr.name();
        let attr_ns = attr.namespace().unwrap_or(""); 
        let attr_qname = get_attr_qname(node, &attr);
        let val = escape_attribute(attr.value());
        
        // Key: (NS_URI, LocalName) -> (QName, Value)
        sorted_attrs.insert((attr_ns, attr_local), (attr_qname, val));
    }
    
    for (_, (q, v)) in sorted_attrs {
        write!(buf, " {}=\"{}\"", q, v).unwrap();
    }
    
    write!(buf, ">").unwrap();
    
    // 6. Push scope and Process Children
    rendered_scopes.push(new_scope);
    
    for child in node.children() {
        process_node(&child, buf, rendered_scopes, filter)?;
    }
    
    // Pop Scope
    rendered_scopes.pop();
    
    // 7. End Tag
    write!(buf, "</{}>", qname).unwrap();
    
    Ok(())
}

fn get_qname(node: &Node) -> String {
    let tag_ns_uri = node.tag_name().namespace();
    let tag_prefix = if let Some(uri) = tag_ns_uri {
        node.lookup_prefix(uri).unwrap_or("")
    } else {
        ""
    };
    let tag_local = node.tag_name().name();
    if tag_prefix.is_empty() { tag_local.to_string() } else { format!("{}:{}", tag_prefix, tag_local) }
}

fn get_attr_qname(node: &Node, attr: &roxmltree::Attribute) -> String {
    let prefix = attr.namespace().and_then(|ns| node.lookup_prefix(ns)).unwrap_or("");
    let local = attr.name();
    if prefix.is_empty() { local.to_string() } else { format!("{}:{}", prefix, local) }
}

fn split_qname(qname: &str) -> (&str, &str) {
    if let Some(idx) = qname.find(':') {
        (&qname[..idx], &qname[idx+1..])
    } else {
        ("", qname)
    }
}

fn escape_text(s: &str) -> String {
    s.replace("&", "&amp;")
     .replace("<", "&lt;")
     .replace(">", "&gt;")
     .replace("\r", "
")
}

fn escape_attribute(s: &str) -> String {
    s.replace("&", "&amp;")
     .replace("<", "&lt;")
     .replace("\"", "&quot;")
     .replace("\t", "&#x9;")
     .replace("\n", "&#xA;")
     .replace("\r", "&#xD;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    #[test]
    fn test_simple_element_with_attributes() {
        let xml = r#"<e a="2" b="1"></e>"#;
        let doc = Document::parse(xml).unwrap();
        let canonical = canonicalize(&doc.root_element()).unwrap();
        // Attributes sorted: a, b (Wait, b < a? No, 'a' < 'b')
        // But logic is sorting by NS then local. Both empty ns.
        // Sorted: a="2", b="1"
        assert_eq!(canonical, r#"<e a="2" b="1"></e>"#);
        
        let xml2 = r#"<e b="1" a="2"></e>"#;
        let doc2 = Document::parse(xml2).unwrap();
        let canonical2 = canonicalize(&doc2.root_element()).unwrap();
        assert_eq!(canonical2, r#"<e a="2" b="1"></e>"#);
    }
    
    #[test]
    fn test_namespace_rendering() {
        let xml = r#"<n1:e xmlns:n1="http://example.org"><n1:b/></n1:e>"#;
        let doc = Document::parse(xml).unwrap();
        let canonical = canonicalize(&doc.root_element()).unwrap();
        // n1 used in 'e' and 'b'.
        // e: declares n1.
        // b: inherits n1.
        
        // Expected: <n1:e xmlns:n1="http://example.org"><n1:b></n1:b></n1:e>
        assert_eq!(canonical, r#"<n1:e xmlns:n1="http://example.org"><n1:b></n1:b></n1:e>"#);
    }
    
    #[test]
    fn test_default_namespace() {
        let xml = r#"<e xmlns="http://default"><b/></e>"#;
        let doc = Document::parse(xml).unwrap();
        let canonical = canonicalize(&doc.root_element()).unwrap();
        
        // e uses default ns.
        // b uses default ns.
        assert_eq!(canonical, r#"<e xmlns="http://default"><b></b></e>"#);
    }
    
    #[test]
    fn test_nested_visibly_utilized() {
        // Exclusive C14N: only render if used.
        let xml = r#"<e xmlns:start="http://start" xmlns:unused="http://unused"><start:b/></e>"#;
        let doc = Document::parse(xml).unwrap();
        let canonical = canonicalize(&doc.root_element()).unwrap();
        
        // e uses... no prefix? It's in default "" (empty).
        // e attrs? None.
        // e doesn't use 'start' or 'unused'.
        // b uses 'start'.
        
        // <e><start:b xmlns:start="http://start"></start:b></e>
        // Note: roxmltree might consider 'e' as in no namespace unless defined. 
        // Here xmlns:start is decl in e.
        
        assert_eq!(canonical, r#"<e><start:b xmlns:start="http://start"></start:b></e>"#);
    }
}
