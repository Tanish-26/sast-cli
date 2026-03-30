use sast_core::{Confidence, Language};

#[test]
fn validates_interprocedural_source_to_sink_path() {
    let src = r#"
        #include <stdlib.h>
        #include <stdio.h>
        char* get_input() { return getenv("USER"); }
        int main() {
            char buf[64];
            char* x = get_input();
            sprintf(buf, x);
        }
    "#;

    let findings = sast_c::scan(src, "a.c", Language::C).unwrap();
    assert!(!findings.is_empty());

    let mut ast_map = std::collections::BTreeMap::new();
    ast_map.insert(
        "a.c".to_string(),
        crate::parse_file("a.c", src, Language::C).unwrap(),
    );
    let cg = crate::build_call_graph(&ast_map);
    let validated = crate::validate_findings(findings, &ast_map, &cg);

    assert!(
        validated
            .iter()
            .any(|f| f.confidence == Some(Confidence::High) && f.validated_path.is_some()),
        "expected at least one validated high-confidence finding"
    );
}

#[test]
fn validates_alias_propagation_to_sink_path() {
    let src = r#"
        #include <stdlib.h>
        int main() {
            char *a = getenv("USER");
            char *b = a;
            system(b);
        }
    "#;

    let findings = sast_c::scan(src, "a.c", Language::C).unwrap();
    assert!(!findings.is_empty());

    let mut ast_map = std::collections::BTreeMap::new();
    ast_map.insert(
        "a.c".to_string(),
        crate::parse_file("a.c", src, Language::C).unwrap(),
    );
    let cg = crate::build_call_graph(&ast_map);
    let validated = crate::validate_findings(findings, &ast_map, &cg);

    let f = validated
        .iter()
        .find(|f| f.rule_id == "c.command_injection")
        .expect("expected command injection finding");
    assert_eq!(f.confidence, Some(Confidence::High));
    let p = f.validated_path.as_ref().expect("expected validated path");
    assert!(p.iter().any(|s| s.contains("getenv@")), "path should include getenv source");
    assert!(p.iter().any(|s| s.contains("system@")), "path should include sink system");
}

#[test]
fn validates_structural_pointer_arithmetic_overflow() {
    let src = r#"
        #include <stdio.h>
        int main() {
            char buf[16];
            int sz = 8;
            sprintf(buf + sz, "x");
        }
    "#;

    let findings = sast_c::scan(src, "a.c", Language::C).unwrap();
    assert!(findings.iter().any(|f| f.rule_id.starts_with("c.buffer_overflow")));

    let mut ast_map = std::collections::BTreeMap::new();
    ast_map.insert(
        "a.c".to_string(),
        crate::parse_file("a.c", src, Language::C).unwrap(),
    );
    let cg = crate::build_call_graph(&ast_map);
    let validated = crate::validate_findings(findings, &ast_map, &cg);

    assert!(
        validated
            .iter()
            .any(|f| f.rule_id.contains("pointer_arithmetic") && f.validated && f.confidence == Some(Confidence::High)),
        "expected structural pointer arithmetic overflow to be validated with HIGH confidence"
    );
}

#[test]
fn validates_structural_strcpy_without_bounds() {
    let src = r#"
        #include <string.h>
        int main() {
            char dst[8];
            char src[32];
            strcpy(dst, src);
        }
    "#;

    let findings = sast_c::scan(src, "a.c", Language::C).unwrap();
    assert!(findings.iter().any(|f| f.rule_id.starts_with("c.buffer_overflow")));

    let mut ast_map = std::collections::BTreeMap::new();
    ast_map.insert(
        "a.c".to_string(),
        crate::parse_file("a.c", src, Language::C).unwrap(),
    );
    let cg = crate::build_call_graph(&ast_map);
    let validated = crate::validate_findings(findings, &ast_map, &cg);

    assert!(
        validated
            .iter()
            .any(|f| f.rule_id.starts_with("c.buffer_overflow") && f.validated),
        "expected strcpy buffer overflow pattern to be structurally validated"
    );
}

#[test]
fn validates_uaf_free_in_if_use_outside() {
    let src = r#"
        #include <stdlib.h>
        int main(int argc, char **argv) {
            char *p = (char*)malloc(8);
            int flag = argc;
            if (flag) {
                free(p);
            }
            p[0] = 'A';
            return 0;
        }
    "#;

    let findings = sast_c::scan(src, "a.c", Language::C).unwrap();
    assert!(findings.iter().any(|f| f.rule_id == "c.use_after_free"));

    let mut ast_map = std::collections::BTreeMap::new();
    ast_map.insert(
        "a.c".to_string(),
        crate::parse_file("a.c", src, Language::C).unwrap(),
    );
    let cg = crate::build_call_graph(&ast_map);
    let validated = crate::validate_findings(findings, &ast_map, &cg);

    let f = validated
        .iter()
        .find(|f| f.rule_id == "c.use_after_free")
        .unwrap();
    assert!(f.validated);
    // Conditional free: feasible path exists but not guaranteed on all paths.
    assert_eq!(f.confidence, Some(Confidence::Medium));
    assert!(f.validated_path.as_ref().is_some_and(|p| p.len() >= 2));
}

#[test]
fn validates_uaf_alias_based() {
    let src = r#"
        #include <stdlib.h>
        int main() {
            char *p = (char*)malloc(8);
            char *q = p;
            free(p);
            q[0] = 'A';
            return 0;
        }
    "#;

    let findings = sast_c::scan(src, "a.c", Language::C).unwrap();
    assert!(findings.iter().any(|f| f.rule_id == "c.use_after_free"));

    let mut ast_map = std::collections::BTreeMap::new();
    ast_map.insert(
        "a.c".to_string(),
        crate::parse_file("a.c", src, Language::C).unwrap(),
    );
    let cg = crate::build_call_graph(&ast_map);
    let validated = crate::validate_findings(findings, &ast_map, &cg);

    let f = validated
        .iter()
        .find(|f| f.rule_id == "c.use_after_free")
        .unwrap();
    assert!(f.validated);
    assert_eq!(f.confidence, Some(Confidence::High));
}

#[test]
fn validates_uaf_loop_free_then_use() {
    let src = r#"
        #include <stdlib.h>
        int main(int argc) {
            char *p = (char*)malloc(8);
            int i = 0;
            while (i < argc) {
                free(p);
                break;
            }
            p[0] = 'A';
            return 0;
        }
    "#;

    let findings = sast_c::scan(src, "a.c", Language::C).unwrap();
    assert!(findings.iter().any(|f| f.rule_id == "c.use_after_free"));

    let mut ast_map = std::collections::BTreeMap::new();
    ast_map.insert(
        "a.c".to_string(),
        crate::parse_file("a.c", src, Language::C).unwrap(),
    );
    let cg = crate::build_call_graph(&ast_map);
    let validated = crate::validate_findings(findings, &ast_map, &cg);

    let f = validated
        .iter()
        .find(|f| f.rule_id == "c.use_after_free")
        .unwrap();
    assert!(f.validated);
    // Loop may not execute: feasible path exists but not guaranteed.
    assert_eq!(f.confidence, Some(Confidence::Medium));
}

#[test]
fn validates_uaf_dominance_guaranteed() {
    let src = r#"
        #include <stdlib.h>
        int main() {
            char *p = (char*)malloc(8);
            free(p);
            p[0] = 'A';
            return 0;
        }
    "#;

    let findings = sast_c::scan(src, "a.c", Language::C).unwrap();
    assert!(findings.iter().any(|f| f.rule_id == "c.use_after_free"));

    let mut ast_map = std::collections::BTreeMap::new();
    ast_map.insert(
        "a.c".to_string(),
        crate::parse_file("a.c", src, Language::C).unwrap(),
    );
    let cg = crate::build_call_graph(&ast_map);
    let validated = crate::validate_findings(findings, &ast_map, &cg);

    let f = validated
        .iter()
        .find(|f| f.rule_id == "c.use_after_free")
        .unwrap();
    assert!(f.validated);
    assert_eq!(f.confidence, Some(Confidence::High));
    assert!(f.validation_notes.as_ref().is_some_and(|ns| ns.iter().any(|n| n == "dominance_confirmed")));
}

#[test]
fn does_not_validate_contradictory_null_conditions() {
    let src = r#"
        #include <stdlib.h>
        int main() {
            char *p = (char*)malloc(8);
            if (p != NULL) {
                free(p);
            }
            if (p == NULL) {
                p[0] = 'A';
            }
            return 0;
        }
    "#;

    let findings = sast_c::scan(src, "a.c", Language::C).unwrap();
    assert!(findings.iter().any(|f| f.rule_id == "c.use_after_free"));

    let mut ast_map = std::collections::BTreeMap::new();
    ast_map.insert(
        "a.c".to_string(),
        crate::parse_file("a.c", src, Language::C).unwrap(),
    );
    let cg = crate::build_call_graph(&ast_map);
    let validated = crate::validate_findings(findings, &ast_map, &cg);

    let f = validated
        .iter()
        .find(|f| f.rule_id == "c.use_after_free")
        .unwrap();
    assert!(!f.validated, "should not validate UAF on contradictory path");
    assert_ne!(f.confidence, Some(Confidence::High));
}
