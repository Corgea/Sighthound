use anyhow::Result;
use std::cell::RefCell;
use std::path::Path;

use crate::parser::LanguageParser;

thread_local! {
    static TLS_PARSER: RefCell<Option<(String, LanguageParser)>> = const { RefCell::new(None) };
    static TLS_EMBEDDED_JAVASCRIPT_PARSER: RefCell<Option<LanguageParser>> =
        const { RefCell::new(None) };
}

pub(crate) fn with_local_embedded_javascript_parser<F, R>(f: F) -> Result<R>
where
    F: FnOnce(&mut LanguageParser) -> Result<R>,
{
    TLS_EMBEDDED_JAVASCRIPT_PARSER.try_with(|cell| {
        let mut cached = cell.borrow_mut();
        if cached.is_none() {
            *cached = Some(LanguageParser::new("javascript")?);
        }
        f(cached.as_mut().expect("embedded JavaScript parser initialized"))
    })?
}

pub(crate) fn with_local_parser_for_path<F, R>(language: &str, path: &Path, f: F) -> Result<R>
where
    F: FnOnce(&mut LanguageParser) -> Result<R>,
{
    let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or_default();
    let cache_key = if language.eq_ignore_ascii_case("objectscript")
        && matches!(extension.to_ascii_lowercase().as_str(), "mac" | "inc" | "int" | "rtn")
    {
        "objectscript:routine".to_string()
    } else if language.eq_ignore_ascii_case("objectscript") {
        "objectscript:udl".to_string()
    } else {
        language.to_string()
    };

    TLS_PARSER.try_with(|cell| {
        let mut opt = cell.borrow_mut();
        match *opt {
            Some((ref key, ref mut parser)) if key == &cache_key => f(parser),
            _ => {
                let mut parser = LanguageParser::new_for_path(language, path)?;
                let result = f(&mut parser)?;
                *opt = Some((cache_key, parser));
                Ok(result)
            }
        }
    })?
}
