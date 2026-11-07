//! olevba's side of `tools/library-diff/run`, what `adapters/olevba.py` does with the library.

use ace_mod_oletools::olevba::VbaParser;
use ace_mod_oletools::py::PyErr;
use ace_mod_oletools::scanner::filter_vba;
use serde_json::{Value, json};

fn error_data(error: &PyErr) -> Value {
    json!({"type": error.kind, "message": error.message})
}

fn run(path: &str, data: Vec<u8>) -> Value {
    let mut output = json!({"type": null, "detected": null, "analysis": null, "macros": null});
    let mut parser = match VbaParser::open(path, data) {
        Ok(parser) => parser,
        Err(error) => {
            output["raised"] = error_data(&error);
            return output;
        }
    };
    output["type"] = json!(parser.kind);
    let result = (|| -> Result<(), PyErr> {
        let detected = parser.detect_vba_macros()?;
        output["detected"] = json!(detected);
        if detected {
            let analysis = parser.analyze_macros()?;
            output["analysis"] = json!(
                analysis
                    .iter()
                    .map(|row| vec![&row.0, &row.1, &row.2])
                    .collect::<Vec<_>>()
            );
            output["macros"] = json!([]);
            let macros = parser.extract_all_macros()?.to_vec();
            for item in macros {
                let Some(code) = &item.code else {
                    return Err(PyErr::new(
                        "AttributeError",
                        "'NoneType' object has no attribute 'splitlines'",
                    ));
                };
                output["macros"]
                    .as_array_mut()
                    .expect("just made")
                    .push(json!({
                        "file_name": item.file_name,
                        "stream_path": item.stream_path,
                        "vba_filename": item.vba_filename,
                        "code": code,
                        "filtered": filter_vba(code),
                    }));
            }
        }
        Ok(())
    })();
    if let Err(error) = result {
        output["raised"] = error_data(&error);
    }
    output
}

fn main() {
    let path = std::env::args().nth(1).expect("a file");
    let data = std::fs::read(&path).expect("a readable file");
    let output = run(&path, data);
    let mut reply = json!({"output": output});
    if output_is_empty(&reply["output"]) {
        reply["content"] = json!(false);
    }
    println!("{reply}");
}

fn output_is_empty(output: &Value) -> bool {
    output["macros"].as_array().is_none_or(Vec::is_empty)
}
