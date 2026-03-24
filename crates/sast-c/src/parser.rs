use tree_sitter::{Language, Parser, Tree};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CFamilyLanguage {
    C,
    Cpp,
}

fn lang(lang: CFamilyLanguage) -> Language {
    match lang {
        CFamilyLanguage::C => tree_sitter_c::LANGUAGE.into(),
        CFamilyLanguage::Cpp => tree_sitter_cpp::LANGUAGE.into(),
    }
}

pub fn parse(source: &str, language: CFamilyLanguage) -> Result<Tree, String> {
    let mut parser = Parser::new();
    parser
        .set_language(&lang(language))
        .map_err(|e| format!("failed to set C/C++ language: {e:?}"))?;
    Ok(parser.parse(source, None).ok_or("parse returned None")?)
}

