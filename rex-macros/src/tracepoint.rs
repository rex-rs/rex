use proc_macro2::TokenStream;
use proc_macro_error::OptionExt;
use quote::{format_ident, quote};
use syn::{parse2, ItemFn, Result};

use crate::args::parse_string_args;

pub(crate) struct TracePoint {
    tp_type: Option<String>,
    name: Option<String>,
    item: ItemFn,
}

// follow the sytle from aya
// https://github.com/aya-rs/aya/blob/1cf3d3c222bda0351ee6a2bacf9cee5349556764/aya-ebpf-macros/src/tracepoint.rs
impl TracePoint {
    // parse the argument of function
    pub(crate) fn parse(
        attrs: TokenStream,
        item: TokenStream,
    ) -> Result<TracePoint> {
        let item: ItemFn = parse2(item)?;
        let args = parse_string_args(attrs)?;

        let name = pop_string_args!(args, "name");
        let tp_type = pop_string_args!(args, "tp_type");

        Ok(TracePoint {
            tp_type,
            name,
            item,
        })
    }

    pub(crate) fn expand(&self) -> Result<TokenStream> {
        let fn_name = self.item.sig.ident.clone();
        let item = &self.item;
        let function_name = format!("{}", fn_name);
        let prog_ident =
            format_ident!("PROG_{}", fn_name.to_string().to_uppercase());

        let attached_name = format!(
            "rex/tracepoint/{}",
            self.name.as_ref().expect_or_abort(
                "Please provide valid tracepoint attached point"
            )
        );

        let tp_type_str = self
            .tp_type
            .as_ref()
            .expect_or_abort("Please provide valid tracepoint attached point")
            .as_str();

        let tp_type = match tp_type_str {
            "Void" => quote!(tp_type::Void),
            "SyscallsEnterOpen" => quote!(tp_type::SyscallsExitOpen),
            "SyscallsExitOpen" => quote!(tp_type::SyscallsExitOpen),
            "RawSyscallsEnter" => quote!(tp_type::RawSyscallsEnter),
            "RawSyscallsExit" => quote!(tp_type::RawSyscallsExit),
            _ => panic!("Please provide valid tp_type"),
        };

        let function_body_tokens = quote! {
            #[inline(always)]
            #item

            #[used]
            #[unsafe(link_section = #attached_name)]
            static #prog_ident: tracepoint =
                tracepoint::new(#fn_name, #function_name, #tp_type);
        };

        Ok(function_body_tokens)
    }
}
