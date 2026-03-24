#[cfg(test)]
mod tests {
    use sast_core::Language;

    #[test]
    fn detects_command_injection_system_getenv() {
        let src = r#"
            #include <stdlib.h>
            int main() {
                char *x = getenv("X");
                system(x);
            }
        "#;
        let findings = crate::scan(src, "a.c", Language::C).unwrap();
        assert!(findings.iter().any(|f| f.rule_id == "c.command_injection"));
    }

    #[test]
    fn detects_format_string_printf_argv() {
        let src = r#"
            #include <stdio.h>
            int main(int argc, char **argv) {
                printf(argv[1]);
            }
        "#;
        let findings = crate::scan(src, "a.c", Language::C).unwrap();
        let f = findings
            .iter()
            .find(|f| f.rule_id == "c.format_string")
            .expect("missing");
        assert_eq!(f.severity, sast_core::Severity::Critical);
    }

    #[test]
    fn printf_with_literal_format_and_tainted_arg_is_ok() {
        let src = r#"
            #include <stdio.h>
            int main(int argc, char **argv) {
                printf("%s", argv[1]);
            }
        "#;
        let findings = crate::scan(src, "a.c", Language::C).unwrap();
        assert!(!findings.iter().any(|f| f.rule_id == "c.format_string"));
    }

    #[test]
    fn sprintf_tainted_format_is_critical_format_string() {
        let src = r#"
            #include <stdlib.h>
            #include <stdio.h>
            int main() {
                char buf[64];
                char *fmt = getenv("X");
                sprintf(buf, fmt, 1);
            }
        "#;
        let findings = crate::scan(src, "a.c", Language::C).unwrap();
        let f = findings.iter().find(|f| f.rule_id == "c.format_string").expect("missing");
        assert_eq!(f.severity, sast_core::Severity::Critical);
    }

    #[test]
    fn sprintf_constant_overflow_is_buffer_overflow() {
        let src = r#"
            #include <stdio.h>
            int main() {
                char buf[4];
                sprintf(buf, "hello");
            }
        "#;
        let findings = crate::scan(src, "a.c", Language::C).unwrap();
        assert!(findings.iter().any(|f| f.rule_id == "c.buffer_overflow"));
    }

    #[test]
    fn alias_taint_propagation_var_to_var() {
        let src = r#"
            #include <stdlib.h>
            int main() {
                char *a = getenv("USER");
                char *b = a;
                system(b);
            }
        "#;
        let findings = crate::scan(src, "a.c", Language::C).unwrap();
        assert!(findings.iter().any(|f| f.rule_id == "c.command_injection"));
    }

    #[test]
    fn alias_taint_propagation_buffer_via_pointer() {
        let src = r#"
            #include <unistd.h>
            #include <stdlib.h>
            int main() {
                char buf[32];
                char *p = buf;
                read(0, p, 10);
                system(buf);
            }
        "#;
        let findings = crate::scan(src, "a.c", Language::C).unwrap();
        assert!(findings.iter().any(|f| f.rule_id == "c.command_injection"));
    }

    #[test]
    fn alias_taint_multi_step_pointer_flow() {
        let src = r#"
            #include <unistd.h>
            #include <stdlib.h>
            int main() {
                char buf[32];
                char *p = buf;
                char *q = p;
                read(0, q, 10);
                system(p);
            }
        "#;
        let findings = crate::scan(src, "a.c", Language::C).unwrap();
        assert!(findings.iter().any(|f| f.rule_id == "c.command_injection"));
    }

    #[test]
    fn finding_inside_if_branch_is_marked_conditional() {
        let src = r#"
            #include <stdlib.h>
            int main(int argc, char **argv) {
                if (argc > 1) {
                    char *x = getenv("USER");
                    system(x);
                }
            }
        "#;
        let findings = crate::scan(src, "a.c", Language::C).unwrap();
        let f = findings
            .iter()
            .find(|f| f.rule_id == "c.command_injection")
            .expect("missing");
        assert!(f.conditional);
    }

    #[test]
    fn guarded_pointer_arithmetic_downgrades_high_to_medium() {
        let src = r#"
            #include <stdio.h>
            #include <string.h>
            int main() {
                char buf[32];
                int sz = 0;
                if (sz < sizeof(buf)) {
                    sprintf(buf+sz, "hello");
                }
            }
        "#;
        let findings = crate::scan(src, "a.c", Language::C).unwrap();
        let f = findings
            .iter()
            .find(|f| f.rule_id == "c.buffer_overflow.pointer_arithmetic")
            .expect("missing");
        assert!(f.guarded);
        assert_eq!(f.severity, sast_core::Severity::Medium);
    }

    #[test]
    fn implicit_pointer_arithmetic_includes_lightweight_path() {
        let src = r#"
            #include <stdio.h>
            int main() {
                char buf[32];
                int sz = 0;
                sprintf(buf+sz, "hello");
            }
        "#;
        let findings = crate::scan(src, "a.c", Language::C).unwrap();
        let f = findings
            .iter()
            .find(|f| f.rule_id == "c.buffer_overflow.pointer_arithmetic")
            .expect("missing");
        let expected = vec!["buf", "buf+sz", "sprintf"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>();
        assert_eq!(f.path.clone().unwrap_or_default(), expected);
    }

    #[test]
    fn strongly_guarded_downgrades_medium_to_low() {
        let src = r#"
            #include <string.h>
            int main() {
                char buf[16];
                char *src = "hello";
                if (strlen(src) < sizeof(buf)) {
                    strcpy(buf, src);
                }
            }
        "#;
        let findings = crate::scan(src, "a.c", Language::C).unwrap();
        let f = findings
            .iter()
            .find(|f| f.rule_id == "c.buffer_overflow")
            .expect("missing");
        assert!(f.guarded);
        assert_eq!(f.severity, sast_core::Severity::Low);
    }

    #[test]
    fn interprocedural_return_source_to_sprintf_is_detected() {
        let src = r#"
            #include <stdlib.h>
            #include <stdio.h>
            char* get_input() { return getenv("USER"); }
            int main() {
                char buf[64];
                char *x = get_input();
                sprintf(buf, x);
            }
        "#;
        let findings = crate::scan(src, "a.c", Language::C).unwrap();
        assert!(findings.iter().any(|f| f.rule_id == "c.format_string"));
    }

    #[test]
    fn interprocedural_param_passthrough_taint_is_detected() {
        let src = r#"
            #include <stdlib.h>
            char* id(char* x) { return x; }
            char* get_cmd() { return getenv("CMD"); }
            int main() {
                char *x = id(get_cmd());
                system(x);
            }
        "#;
        let findings = crate::scan(src, "a.c", Language::C).unwrap();
        assert!(findings.iter().any(|f| f.rule_id == "c.command_injection"));
    }

    #[test]
    fn interprocedural_safe_flow_literal_format_is_not_format_string() {
        let src = r#"
            #include <stdlib.h>
            #include <stdio.h>
            char* get_input() { return getenv("USER"); }
            int main() {
                printf("%s", get_input());
            }
        "#;
        let findings = crate::scan(src, "a.c", Language::C).unwrap();
        assert!(!findings.iter().any(|f| f.rule_id == "c.format_string"));
    }

    #[test]
    fn detects_double_free() {
        let src = r#"
            #include <stdlib.h>
            int main() {
                char *p = (char*)malloc(10);
                free(p);
                free(p);
            }
        "#;
        let findings = crate::scan(src, "a.c", Language::C).unwrap();
        let f = findings
            .iter()
            .find(|f| f.rule_id == "c.double_free")
            .expect("missing");
        let expected = vec!["p", "free", "free"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>();
        assert_eq!(f.path.clone().unwrap_or_default(), expected);
    }

    #[test]
    fn detects_use_after_free() {
        let src = r#"
            #include <stdlib.h>
            int main() {
                char *p = (char*)malloc(10);
                free(p);
                p[0] = 'A';
            }
        "#;
        let findings = crate::scan(src, "a.c", Language::C).unwrap();
        assert!(findings.iter().any(|f| f.rule_id == "c.use_after_free"));
    }

    #[test]
    fn detects_buffer_overflow_strcpy() {
        let src = r#"
            #include <string.h>
            int main(int argc, char **argv) {
                char buf[8];
                strcpy(buf, argv[1]);
            }
        "#;
        let findings = crate::scan(src, "a.c", Language::C).unwrap();
        assert!(findings.iter().any(|f| f.rule_id == "c.buffer_overflow"));
    }

    #[test]
    fn sprintf_without_taint_is_low_buffer_overflow() {
        let src = r#"
            #include <stdio.h>
            int main() {
                char buf[32];
                int x = 7;
                sprintf(buf, "x=%d", x);
            }
        "#;
        let findings = crate::scan(src, "a.c", Language::C).unwrap();
        let f = findings
            .iter()
            .find(|f| f.rule_id == "c.buffer_overflow")
            .expect("missing");
        assert_eq!(f.severity, sast_core::Severity::Low);
        assert!(!findings
            .iter()
            .any(|f| f.rule_id == "c.buffer_overflow.pointer_arithmetic"));
    }

    #[test]
    fn sprintf_constant_literal_that_fits_is_suppressed() {
        let src = r#"
            #include <stdio.h>
            int main() {
                char buf[16];
                sprintf(buf, "hello");
            }
        "#;
        let findings = crate::scan(src, "a.c", Language::C).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn strcpy_constant_literal_that_fits_is_suppressed() {
        let src = r#"
            #include <string.h>
            int main() {
                char buf[16];
                strcpy(buf, "hello");
            }
        "#;
        let findings = crate::scan(src, "a.c", Language::C).unwrap();
        assert!(findings.is_empty());
    }
}
