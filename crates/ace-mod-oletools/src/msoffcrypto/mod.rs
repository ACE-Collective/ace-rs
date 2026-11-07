//! The parts of msoffcrypto-tool 6.0.0 that `ace-mod-msoffice` and XLMMacroDeobfuscator's port use. It's
//! here and not in `ace-mod-msoffice` because olevba, here, reaches it through the deobfuscator.

mod crypto;
pub mod method;
pub mod office;
