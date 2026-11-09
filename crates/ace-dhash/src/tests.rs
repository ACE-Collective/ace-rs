//! Compares the crate with Pillow 13.0.0's answers, recorded by tests/data/oracle.py over the
//! files tests/data/gen.py writes (tests/data/cases).

use super::*;

fn data_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data")
}

/// Cases where this crate is known to differ from Pillow, with the reason.
fn known_difference(name: &str) -> Option<&'static str> {
    const UNPORTED: &str = "Pillow decodes this with a library this crate does not port";
    Some(match name {
        n if n.starts_with("other_avif") || n.starts_with("mut_other_avif") => {
            "AVIF: libavif's parser and decoder are not ported (open is approximated)"
        }
        "other_blp_P.blp"
        | "other_dds_L.dds"
        | "other_dds_LA.dds"
        | "other_dds_RGB.dds"
        | "other_dds_RGBA.dds"
        | "other_icns_RGBA.icns"
        | "other_jp2_RGB.jp2"
        | "tiff_ccitt_g4.tif"
        | "tiff_jpeg.tif"
        | "other_eps_RGB.eps" => UNPORTED,
        "mut_webp_grad100x75_q10_junk.webp"
        | "mut_webp_noisea50_q10_flip1.webp"
        | "mut_webp_noisea50_q10_flip3.webp"
        | "mut_webp_shapes320x240_q50_junk.webp" => {
            "corrupt lossy WebP: libwebp fails (premature end of partition) or differs where image-webp decodes"
        }
        "mut_jpeg_4_q5_s2_flip2.jpg" => {
            "corrupt JPEG: coefficient overflow inside libjpeg-turbo's NEON IDCT is not emulated"
        }
        _ => return None,
    })
}

#[derive(Default)]
struct Tally {
    total: usize,
    same: usize,
    diffs: Vec<String>,
}

#[test]
fn oracle() {
    let dir = data_dir();
    let oracle: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("oracle.json")).expect("oracle.json"))
            .expect("json");
    let only = std::env::var("DHASH_ONLY").ok();
    let mut t = Tally::default();
    let mut unexpected = Vec::new();
    for (name, want) in oracle.as_object().expect("object") {
        if let Some(o) = &only {
            if !name.contains(o.as_str()) {
                continue;
            }
        }
        let data = std::fs::read(dir.join("cases").join(name)).expect("case file");
        t.total += 1;
        let got_is = is_image(&data);
        let want_is = want["is_image"].as_bool().expect("is_image");
        let got_hash = image_hash(&data);
        let want_hash = want.get("hash").and_then(|h| h.as_str());
        let mut problems = Vec::new();
        if got_is != want_is {
            problems.push(format!("is_image {got_is} want {want_is}"));
        }
        match (&got_hash, want_hash) {
            (Ok(h), Some(w)) if h.to_hex() == w => {}
            (Ok(h), Some(w)) => {
                let wb = hex_to_hash(w);
                problems.push(format!("hash differs by {} bits", h.bits_different(&wb)));
            }
            (Ok(_), None) => problems.push(format!("hashed, want {}", want["error"])),
            (Err(e), Some(_)) => problems.push(format!("error {e}, want a hash")),
            (Err(_), None) => {}
        }
        if problems.is_empty() {
            t.same += 1;
        } else {
            let fmt = want.get("format").and_then(|f| f.as_str()).unwrap_or("-");
            let line = format!(
                "{name} [{fmt} {}]: {}",
                want.get("mode").and_then(|m| m.as_str()).unwrap_or("-"),
                problems.join("; ")
            );
            if known_difference(name).is_none() {
                unexpected.push(line.clone());
            }
            t.diffs.push(line);
        }
    }
    eprintln!("{} of {} cases match Pillow", t.same, t.total);
    for d in &t.diffs {
        eprintln!("  {d}");
    }
    assert!(
        unexpected.is_empty(),
        "{} unexpected differences",
        unexpected.len()
    );
}

fn hex_to_hash(h: &str) -> ImageHash {
    let padded = format!("{h:0>128}");
    let mut b = [0u8; 64];
    for i in 0..64 {
        b[i] = u8::from_str_radix(&padded[i * 2..i * 2 + 2], 16).expect("hex");
    }
    let mut row = [0u8; 32];
    let mut col = [0u8; 32];
    row.copy_from_slice(&b[..32]);
    col.copy_from_slice(&b[32..]);
    ImageHash { row, col }
}

#[test]
fn score_helpers() {
    assert_eq!(percent_similar(0), 100.0);
    assert_eq!(format_percent(percent_similar(16)), "96.88");
    assert_eq!(format_percent(percent_similar(48)), "90.62");
    assert_eq!(score_json(percent_similar(1)), "99.8046875");
    assert_eq!(score_json(100.0), "100.0");
    assert_eq!(format_percent(percent_similar(512)), "0.00");
}
