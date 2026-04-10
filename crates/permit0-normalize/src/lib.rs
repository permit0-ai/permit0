#![forbid(unsafe_code)]
#![doc = "Normalizer trait and registry for the permit0 agent permission framework."]

mod context;
mod error;
mod fallback;
mod registry;
mod traits;

pub use context::NormalizeCtx;
pub use error::{NormalizeError, RegistryError};
pub use fallback::FallbackNormalizer;
pub use registry::NormalizerRegistry;
pub use traits::Normalizer;
