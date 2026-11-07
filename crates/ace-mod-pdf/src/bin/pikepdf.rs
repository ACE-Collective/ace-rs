//! The Rust side of `tools/library-diff/run pikepdf`: what `tools/library-diff/adapters/pikepdf.py`
//! reads of a file, on libqpdf.

use std::path::Path;

use ace_mod_pdf::objects::{Objects, Py, bytes_json};
use ace_mod_pdf::qpdf::{Document, Raised};
use ace_mod_pdf::side;
use serde_json::{Map, Value, json};

/// One of what the adapter reads, each under its own `try`.
type Part = fn(&Objects<'_>) -> Result<Value, Raised>;

fn raised(error: &Raised) -> Value {
    json!({"raised": {"type": error.kind, "message": error.message}})
}

fn annotation_uris(objects: &Objects<'_>) -> Result<Value, Raised> {
    let mut uris = Vec::new();
    for uri in objects.annotation_uris()? {
        uris.push(objects.value_of(&uri)?);
    }
    Ok(Value::Array(uris))
}

fn form_fields(objects: &Objects<'_>) -> Result<Value, Raised> {
    let mut fields = Vec::new();
    for field in objects.form_fields()? {
        let value = objects.get(&field, "/V")?;
        let name = objects.field_name(&field)?;
        fields.push(json!({
            "name": objects.value_of(&name)?,
            "value": if matches!(value, Py::None) { Value::Null } else { objects.value_of(&value)? },
        }));
    }
    Ok(Value::Array(fields))
}

fn javascript(objects: &Objects<'_>) -> Result<Value, Raised> {
    let mut scripts = Vec::new();
    for (name, action) in objects.javascript()? {
        let js = objects.get(&action, "/JS")?;
        scripts.push(json!({
            "name": objects.value_of(&name)?,
            "js": if matches!(js, Py::None) { Value::Null } else { objects.value_of(&js)? },
        }));
    }
    Ok(Value::Array(scripts))
}

fn read(path: &Path) -> Result<Value, Raised> {
    let document = Document::open(path)?;
    let objects = Objects {
        document: &document,
    };
    let mut output = Map::new();
    output.insert("pages".to_owned(), json!(document.page_count()?));
    output.insert("is_encrypted".to_owned(), json!(document.is_encrypted()));
    if document.is_encrypted() {
        output.insert(
            "encryption".to_owned(),
            match objects.encryption(path) {
                Ok(encryption) => serde_json::to_value(encryption).unwrap_or(Value::Null),
                Err(error) => raised(&error),
            },
        );
        let copy = objects
            .fix_page_tree_counts()
            .and_then(|()| document.save_decrypted());
        output.insert(
            "decrypted".to_owned(),
            match copy {
                Ok(copy) => bytes_json(copy),
                Err(error) => raised(&error),
            },
        );
    }
    let parts: [(&str, Part); 3] = [
        ("annotation_uris", annotation_uris),
        ("form_fields", form_fields),
        ("javascript", javascript),
    ];
    for (name, part) in parts {
        let value = part(&objects).unwrap_or_else(|error| raised(&error));
        output.insert(name.to_owned(), value);
    }
    Ok(Value::Object(output))
}

fn main() {
    let path = std::env::args_os().nth(1).expect("a file");
    side::answer(&match read(Path::new(&path)) {
        Ok(output) => json!({"output": output}),
        Err(error) => side::error(&error.kind, &error.message),
    });
}
