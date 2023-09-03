use crate::re;
use crate::re::fast::compiler::Compiler;
use yara_x_parser::ast;

macro_rules! assert_re_code {
    ($re:expr, $fwd:expr, $bck:expr) => {{
        let parser = re::parser::Parser::new();
        let mut code = Vec::new();

        let result = Compiler::new()
            .compile(
                &parser
                    .parse(&ast::Regexp {
                        literal: format!("/{}/", $re).as_str(),
                        src: $re,
                        case_insensitive: false,
                        dot_matches_new_line: true,
                        span: ast::Span::default(),
                    })
                    .unwrap(),
                &mut code,
            )
            .unwrap();
    }};
}

//#[test]
//fn test_fast_re() {
//    assert_re_code!("(?s)abcd", "", "");
//}
