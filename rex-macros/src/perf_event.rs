use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{ItemFn, Result};

pub(crate) struct PerfEvent {
    item: ItemFn,
}

impl PerfEvent {
    // parse the argument of function
    pub(crate) fn parse(
        _: TokenStream,
        item: TokenStream,
    ) -> Result<PerfEvent> {
        let item = syn::parse2(item)?;
        Ok(PerfEvent { item })
    }

    pub(crate) fn expand(&self) -> Result<TokenStream> {
        // TODO: section may update in the future
        let fn_name = self.item.sig.ident.clone();
        let item = &self.item;
        let function_name = format!("{fn_name}");
        let prog_ident =
            format_ident!("PROG_{}", fn_name.to_string().to_uppercase());

        let entry_name = format_ident!("__rex_entry_{}", fn_name);

        let function_body_tokens = quote! {
            #[inline(always)]
            #item

            #[used]
            static #prog_ident: perf_event = unsafe { perf_event::new() };

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = "rex/perf_event")]
            extern "C" fn #entry_name(ctx: *mut ()) -> u32 {
                let newctx = unsafe { #prog_ident.convert_ctx(ctx) };
                #fn_name(&#prog_ident, newctx).unwrap_or_else(|e| e) as u32
            }
        };
        Ok(function_body_tokens)
    }
}
