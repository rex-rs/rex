#[macro_use]
pub(crate) mod args;
mod kprobe;
mod perf_event;
mod tc;
mod tracepoint;
mod xdp;

use std::borrow::Cow;

use kprobe::{KProbe, KprobeFlavor};
use perf_event::PerfEvent;
use proc_macro::TokenStream;
use proc_macro_error::{abort, proc_macro_error};
use quote::quote;
use syn::ItemStatic;
use tc::SchedCls;
use tracepoint::TracePoint;
use xdp::Xdp;

#[proc_macro_error]
#[proc_macro_attribute]
pub fn rex_xdp(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match Xdp::parse(attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
}

#[proc_macro_error]
#[proc_macro_attribute]
pub fn rex_tc(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match SchedCls::parse(attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
}

#[proc_macro_error]
#[proc_macro_attribute]
pub fn rex_kprobe(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match KProbe::parse(attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand(KprobeFlavor::Kprobe)
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
}

#[proc_macro_error]
#[proc_macro_attribute]
pub fn rex_uprobe(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match KProbe::parse(attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand(KprobeFlavor::Uprobe)
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
}

#[proc_macro_error]
#[proc_macro_attribute]
pub fn rex_tracepoint(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match TracePoint::parse(attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
}

#[proc_macro_error]
#[proc_macro_attribute]
pub fn rex_perf_event(attrs: TokenStream, item: TokenStream) -> TokenStream {
    match PerfEvent::parse(attrs.into(), item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
}

/// Ref: <https://github.com/aya-rs/aya/blob/1cf3d3c222bda0351ee6a2bacf9cee5349556764/aya-ebpf-macros/src/lib.rs#L53>
#[proc_macro_attribute]
pub fn rex_map(_: TokenStream, item: TokenStream) -> TokenStream {
    let item: ItemStatic = syn::parse(item).unwrap();
    let name = item.ident.to_string();
    let section_name: Cow<'_, _> = ".maps".to_string().into();
    (quote! {
        #[unsafe(link_section = #section_name)]
        #[unsafe(export_name = #name)]
        #[allow(non_upper_case_globals)]
        #item
    })
    .into()
}
