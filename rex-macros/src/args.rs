use std::collections::HashMap;

use proc_macro2::TokenStream;
use proc_macro_error::abort;
use syn::spanned::Spanned;
use syn::{parse_str, Expr, ExprAssign, Lit, LitStr, Result};

macro_rules! pop_string_args {
    ($self:expr, $key:expr) => {
        $self.get($key).map(|v| v.value())
    };
}

pub(crate) fn parse_string_args(
    input: TokenStream,
) -> Result<HashMap<String, LitStr>> {
    let parsed: syn::ExprArray = parse_str(&format!("[{}]", input))?;
    let mut map = HashMap::new();

    // Iterate over the expressions and extract key-value pairs
    let parse_and_insert = |expr| {
        let Expr::Assign(ExprAssign { left, right, .. }) = expr else {
            return;
        };
        let Expr::Path(path) = *left else { return };
        let Some(ident) = path.path.get_ident() else {
            return;
        };

        let key = ident.to_string();
        let value = match *right {
            Expr::Lit(syn::ExprLit {
                lit: Lit::Str(lit_str),
                ..
            }) => lit_str,
            _ => {
                abort!(input.span(), "Macro processing failed, please follow the syntax `key` = `value`");
            }
        };
        map.insert(key, value);
    };

    parsed.elems.into_iter().for_each(parse_and_insert);

    // println!("{:?}", map);
    Ok(map)
}
