use proc_macro2::TokenStream;
use proc_macro_error::{abort_call_site, OptionExt};
use quote::{format_ident, quote, ToTokens};
use syn::{parse2, FnArg, Ident, ItemFn, Result, Type};

pub(crate) struct TracePoint {
    item: ItemFn,
}

// follow the sytle from aya
// https://github.com/aya-rs/aya/blob/1cf3d3c222bda0351ee6a2bacf9cee5349556764/aya-ebpf-macros/src/tracepoint.rs
impl TracePoint {
    // parse the argument of function
    pub(crate) fn parse(
        _attrs: TokenStream,
        item: TokenStream,
    ) -> Result<TracePoint> {
        let item: ItemFn = parse2(item)?;
        Ok(TracePoint { item })
    }

    pub(crate) fn expand(&self) -> Result<TokenStream> {
        let fn_name = self.item.sig.ident.clone();

        // get context type
        let FnArg::Typed(context_arg) =
            self.item.sig.inputs.last().unwrap().clone()
        else {
            abort_call_site!("Program needs non-self arguments");
        };
        let Type::Reference(context_type_ref) = *context_arg.ty else {
            abort_call_site!("Context type needs to be behind a reference");
        };
        if context_type_ref
            .lifetime
            .expect_or_abort("Context reference needs to be static")
            .ident !=
            "static"
        {
            abort_call_site!("Context reference needs to be static");
        }
        let context_type = match *context_type_ref.elem.clone() {
            Type::Verbatim(t) => parse2(t).unwrap(),
            Type::Path(p) => p.path.segments.last().unwrap().clone().ident,
            _ => {
                abort_call_site!("Tracepoint context needs to be a literal type or a path to such")
            }
        };
        let full_context_type: Ident = match *context_type_ref.elem {
            Type::Verbatim(t) => parse2(t).unwrap(),
            Type::Path(p) => parse2(p.to_token_stream()).unwrap(),
            _ => unreachable!(),
        };

        // other tracepoint pieces
        let item = &self.item;
        let function_name = format!("{}", fn_name);
        let prog_ident =
            format_ident!("PROG_{}", fn_name.to_string().to_uppercase());

        let hook_point_name = match context_type.to_string().as_str() {
            "SyscallsEnterOpenCtx" => "syscalls/sys_enter_open",
            "SyscallsEnterOpenatCtx" => "syscalls/sys_enter_openat",
            "SyscallsExitOpenCtx" => "syscalls/sys_exit_open",
            "SyscallsExitOpenatCtx" => "syscalls/sys_exit_openat",
            "SyscallsEnterDupCtx" => "syscalls/sys_enter_dup",
            "RawSyscallsEnterCtx" => "raw_syscalls/sys_enter",
            "RawSyscallsExitCtx" => "raw_syscalls/sys_exit",
            _ => abort_call_site!("Please provide a valid context type. If your needed context isn't supported consider opening a PR!"),
        };
        let attached_name = format!("rex/tracepoint/{}", hook_point_name);

        let wrapper_name = format_ident!("{}_wrapper", fn_name);

        let function_body_tokens = quote! {
            #[inline(always)]
            #item

            #[inline(always)]
            fn #wrapper_name(obj: &tracepoint, raw_ctx: *mut ()) -> Result {
                let ctx = unsafe { &*(raw_ctx as *mut #full_context_type) };
                #fn_name(obj, ctx)
            }

            #[used]
            #[unsafe(link_section = #attached_name)]
            static #prog_ident: tracepoint =
                tracepoint::new(#wrapper_name, #function_name);
        };

        Ok(function_body_tokens)
    }
}
