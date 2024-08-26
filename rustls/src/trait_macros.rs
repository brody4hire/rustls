/// pub trait - version with doc - version that includes Send & Sync - supports use with alloc::sync::Arc
#[cfg(all(
    target_has_atomic = "ptr",
    not(rustls_no_atomic_ptr)
))]
macro_rules! pub_api_trait_with_doc {
    ($doc_text: literal, $name:ident, $body:tt) => {
        #[doc = $doc_text]
        pub trait $name: core::fmt::Debug + Send + Sync $body
    }
}

/////// XXX TODO REPLACE ALL USE OF THIS MACRO WITH pub_api_trait_with_doc! (with doc fixed) & REMOVE THIS MACRO
/// pub trait - version with no doc - version that includes Send & Sync - supports use with alloc::sync::Arc
#[cfg(all(
    target_has_atomic = "ptr",
    not(rustls_no_atomic_ptr)
))]
macro_rules! pub_api_trait {
    ($name:ident, $body:tt) => {
        pub trait $name: core::fmt::Debug + Send + Sync $body
    }
}

/// pub trait - version with doc - version with no Send / Sync - supports use with alloc::rc::Rc
#[cfg(any(
    not(target_has_atomic = "ptr"),
    rustls_no_atomic_ptr
))]
macro_rules! pub_api_trait_with_doc {
    ($doc_text: literal, $name:ident, $body:tt) => {
        #[doc = $doc_text]
        pub trait $name: core::fmt::Debug $body
    }
}

/////// XXX TODO REPLACE ALL USE OF THIS MACRO WITH pub_api_trait_with_doc! (with doc fixed) & REMOVE THIS MACRO
/// pub trait - version with no doc - version with no Send / Sync - supports use with alloc::rc::Rc
#[cfg(any(
    not(target_has_atomic = "ptr"),
    rustls_no_atomic_ptr
))]
macro_rules! pub_api_trait {
    ($name:ident, $body:tt) => {
        pub trait $name: core::fmt::Debug $body
    }
}

/// internal pub(crate) trait that includes Send & Sync - supports use with alloc::sync::Arc
#[cfg(all(
    target_has_atomic = "ptr",
    not(rustls_no_atomic_ptr)
))]
macro_rules! internal_generic_state_trait {
    // XXX QUICK HACKY MACRO API WITH SEPARATE NAME & GENERIC TYPE PARAMETERS
    ($name:ident, $generic_type_parameter:ident, $body:tt) => {
        pub(crate) trait $name<$generic_type_parameter>: Send + Sync $body
    }
}

/// internal pub(crate) trait with no Send / Sync - supports use with alloc::rc::Rc
#[cfg(any(
    not(target_has_atomic = "ptr"),
    rustls_no_atomic_ptr
))]
macro_rules! internal_generic_state_trait {
    // XXX QUICK HACKY MACRO API WITH SEPARATE NAME & GENERIC TYPE PARAMETERS
    ($name:ident, $generic_type_parameter:ident, $body:tt) => {
        pub(crate) trait $name<$generic_type_parameter> $body
    }
}
