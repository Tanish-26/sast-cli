pub(crate) mod cfg;
pub mod parser;
pub mod rules;
pub mod rule_engine;
pub mod rulesets;
pub mod taint;

use sast_core::{Finding, Language};

pub fn scan(source: &str, path: &str, lang: Language) -> Result<Vec<Finding>, String> {
    match lang {
        Language::C => taint::scan_c_family(source, path, parser::CFamilyLanguage::C),
        Language::Cpp => taint::scan_c_family(source, path, parser::CFamilyLanguage::Cpp),
        _ => Err("sast-c only supports C/C++".to_string()),
    }
}

#[cfg(test)]
mod tests;
