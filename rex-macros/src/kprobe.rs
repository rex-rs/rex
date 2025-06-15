use std::fmt;

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{parse2, ItemFn, Result};

use crate::args::parse_string_args;

#[allow(dead_code)]
pub enum KprobeFlavor {
    Kprobe,
    Kretprobe,
    Uprobe,
    Uretprobe,
}

impl fmt::Display for KprobeFlavor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KprobeFlavor::Kprobe => write!(f, "kprobe"),
            KprobeFlavor::Kretprobe => write!(f, "kretprobe"),
            KprobeFlavor::Uprobe => write!(f, "uprobe"),
            KprobeFlavor::Uretprobe => write!(f, "uretprobe"),
        }
    }
}

pub(crate) struct KProbe {
    function: Option<String>,
    item: ItemFn,
}

impl KProbe {
    // parse the argument of function
    pub(crate) fn parse(
        attrs: TokenStream,
        item: TokenStream,
    ) -> Result<KProbe> {
        let item: ItemFn = parse2(item)?;
        let args = parse_string_args(attrs)?;

        let function = pop_string_args!(args, "function");

        Ok(KProbe { function, item })
    }

    pub(crate) fn expand(&self, flavor: KprobeFlavor) -> Result<TokenStream> {
        let fn_name = self.item.sig.ident.clone();
        let item = &self.item;
        let function_name = format!("{}", fn_name);
        let prog_ident =
            format_ident!("PROG_{}", fn_name.to_string().to_uppercase());

        let attached_function = if self.function.is_some() {
            format!("rex/{}/{}", flavor, self.function.as_ref().unwrap())
        } else {
            format!("rex/{}", flavor)
        };

        let entry_name = format_ident!("__rex_entry_{}", fn_name);

        let function_body_tokens = quote! {
            #[inline(always)]
            #item

            #[used]
            static #prog_ident: kprobe =
                kprobe::new(#fn_name, #function_name);

            #[unsafe(export_name = #function_name)]
            #[unsafe(link_section = #attached_function)]
            extern "C" fn #entry_name(ctx: *mut ()) -> u32 {
                use rex::prog_type::rex_prog;
                #prog_ident.prog_run(ctx)
            }
        };

        Ok(function_body_tokens)
    }
}
