"""The modules the pool can run, by manifest name (crates/ace-mod-python), each with where its code
is. A worker imports only the ones the supervisor names, so nothing registers at import (#1030) and
one module's libraries don't load for another (#1029). A name in the Rust manifest that's missing
here stops the worker at startup, and so the pool, before it leases anything.
"""

MODULES = {
    "python_probe": "ace4_python.modules.python_probe",
}
