//! Pillow 13's identification of an image, as ace3's ocr and qrcode modules ask it (`Image.open`):
//! each format it registers, in its order, by the first bytes its plugin accepts and, where its
//! plugin checks the header before taking the file, by that check too. It leaves out the formats
//! Pillow opens only through olefile (FlashPix, MIC) and those with no signature whose checks are
//! their whole parser (IM, IMT, IPTC, PCD, SPIDER); a file of one of those isn't an image here.
//! Pillow opens lazily, so a file whose header it takes is an image even when its pixels don't
//! decode.
//!
//! The type step records it as a file's `is_image`, on its first 1024 bytes, as the modules read it
//! (`ace_mod_sandbox::image::is_image`), so their declarations take only images (PLAN.md decision 25).

fn i16le(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn i32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn i16be(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn i32be(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// The format Pillow would open `head` as, the first in its order that takes it.
pub fn identify(head: &[u8]) -> Option<&'static str> {
    let starts = |magic: &[u8]| head.starts_with(magic);
    let len = head.len();
    let checks: &[(&str, &dyn Fn() -> bool)] = &[
        ("AVIF", &|| {
            len >= 12
                && &head[4..8] == b"ftyp"
                && matches!(&head[8..12], b"avif" | b"avis" | b"mif1" | b"msf1")
        }),
        ("BLP", &|| starts(b"BLP1") || starts(b"BLP2")),
        ("BMP", &|| starts(b"BM") && bmp_header(head, 14)),
        ("DIB", &|| len >= 4 && dib_header(head, 0)),
        ("BUFR", &|| starts(b"BUFR") || starts(b"ZCZC")),
        ("CUR", &|| starts(b"\0\0\x02\0")),
        ("PCX", &|| {
            len >= 2 && head[0] == 10 && matches!(head[1], 0 | 2 | 3 | 5)
        }),
        ("DCX", &|| len >= 4 && i32le(head, 0) == 987_654_321),
        ("DDS", &|| starts(b"DDS ")),
        ("EPS", &|| {
            (starts(b"%!PS") || (len >= 4 && i32le(head, 0) == 0xC6D3_D0C5))
                && head.windows(14).any(|w| w == b"%%BoundingBox:")
        }),
        ("FITS", &|| starts(b"SIMPLE")),
        ("FLI", &|| {
            len >= 16
                && matches!(i16le(head, 4), 0xAF11 | 0xAF12)
                && matches!(i16le(head, 14), 0 | 3)
        }),
        ("FTEX", &|| starts(b"FTEX")),
        ("GBR", &|| {
            len >= 28
                && i32be(head, 0) >= 20
                && matches!(i32be(head, 4), 1 | 2)
                && (i32be(head, 4) == 1 || &head[20..24] == b"GIMP")
                && i32be(head, 8) > 0
                && i32be(head, 12) > 0
        }),
        ("GIF", &|| starts(b"GIF87a") || starts(b"GIF89a")),
        ("GRIB", &|| len >= 8 && starts(b"GRIB") && head[7] == 1),
        ("HDF5", &|| starts(b"\x89HDF\r\n\x1a\n")),
        ("PNG", &|| starts(b"\x89PNG\r\n\x1a\n")),
        ("JPEG2000", &|| {
            starts(b"\xff\x4f\xff\x51") || starts(b"\x00\x00\x00\x0cjP  \x0d\x0a\x87\x0a")
        }),
        ("ICNS", &|| starts(b"icns")),
        ("ICO", &|| starts(b"\0\0\x01\0")),
        ("JPEG", &|| starts(b"\xff\xd8\xff")),
        ("MCIDAS", &|| starts(b"\0\0\0\0\0\0\0\x04")),
        ("TIFF", &|| {
            [
                &b"MM\x00\x2a"[..],
                b"II\x2a\x00",
                b"MM\x2a\x00",
                b"II\x00\x2a",
                b"MM\x00\x2b",
                b"II\x2b\x00",
            ]
            .iter()
            .any(|m| starts(m))
        }),
        ("MPEG", &|| starts(b"\0\0\x01\xb3")),
        ("MSP", &|| starts(b"DanM") || starts(b"LinS")),
        ("PIXAR", &|| starts(b"\x80\xe8\0\0")),
        ("PPM", &|| {
            len >= 2 && head[0] == b'P' && b"0123456fy".contains(&head[1])
        }),
        ("PSD", &|| {
            starts(b"8BPS") && len >= 6 && i16be(head, 4) == 1
        }),
        ("QOI", &|| starts(b"qoif")),
        ("SGI", &|| len >= 2 && i16be(head, 0) == 474),
        ("SUN", &|| len >= 4 && i32be(head, 0) == 0x59A6_6A95),
        ("TGA", &|| tga_header(head)),
        ("WEBP", &|| {
            len >= 16
                && starts(b"RIFF")
                && &head[8..12] == b"WEBP"
                && matches!(&head[12..16], b"VP8 " | b"VP8X" | b"VP8L")
        }),
        ("WMF", &|| {
            starts(b"\xd7\xcd\xc6\x9a\0\0")
                || (starts(b"\x01\0\0\0") && len >= 44 && &head[40..44] == b" EMF")
        }),
        ("XBM", &|| {
            (starts(b"#define") || starts(b"\n#define") || starts(b"/*")) && xbm_header(head)
        }),
        ("XPM", &|| starts(b"/* XPM */")),
        ("XVTHUMB", &|| starts(b"P7 332")),
    ];
    checks
        .iter()
        .find(|(_, check)| check())
        .map(|(name, _)| *name)
}

/// A BMP's or DIB's info header at `at`, as Pillow's `_bitmap` reads it before it decodes anything:
/// a size it knows, and a bit depth it reads.
fn bmp_header(head: &[u8], at: usize) -> bool {
    head.len() >= at + 4 && dib_header(head, at)
}

fn dib_header(head: &[u8], at: usize) -> bool {
    let size = i32le(head, at);
    if !matches!(size, 12 | 40 | 52 | 56 | 64 | 108 | 124) {
        return false;
    }
    let bits_at = if size == 12 { at + 10 } else { at + 14 };
    if head.len() < bits_at + 2 {
        return false;
    }
    matches!(i16le(head, bits_at), 1 | 2 | 4 | 8 | 16 | 24 | 32)
}

/// Pillow's `TgaImageFile._open` checks, which are all a TGA has to go by.
fn tga_header(head: &[u8]) -> bool {
    if head.len() < 18 {
        return false;
    }
    let colormap = head[1];
    let image_type = head[2];
    let width = i16le(head, 12);
    let height = i16le(head, 14);
    let depth = head[16];
    if colormap > 1 || width == 0 || height == 0 || !matches!(depth, 1 | 8 | 16 | 24 | 32) {
        return false;
    }
    match image_type {
        3 | 11 => matches!(depth, 1 | 8 | 16),
        1 | 9 => colormap == 1 && matches!(head[7], 15 | 16 | 24 | 32),
        2 | 10 => matches!(depth, 16 | 24 | 32),
        _ => false,
    }
}

/// Pillow's `xbm_head` pattern: two `#define`s of a width and a height.
fn xbm_header(head: &[u8]) -> bool {
    let text = String::from_utf8_lossy(&head[..head.len().min(512)]);
    let mut width = false;
    for line in text.lines() {
        let line = line.trim_start();
        if let Some(rest) = line.strip_prefix("#define") {
            let mut words = rest.split_whitespace();
            let name = words.next().unwrap_or_default();
            let value = words.next().unwrap_or_default();
            let number = !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit());
            if name.ends_with("_width") && number {
                width = true;
            } else if name.ends_with("_height") && number && width {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pillows_order_and_checks_identify_a_file() {
        assert_eq!(identify(b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR"), Some("PNG"));
        assert_eq!(identify(b"\xff\xd8\xff\xe0"), Some("JPEG"));
        assert_eq!(identify(b"GIF89a"), Some("GIF"));
        assert_eq!(identify(b"%PDF-1.7"), None);
        assert_eq!(identify(b"PK\x03\x04"), None);
        // a script's comment isn't an XBM without its defines
        assert_eq!(identify(b"/* a script */ var x = 1;"), None);
        assert_eq!(
            identify(b"#define a_width 8\n#define a_height 8\n"),
            Some("XBM")
        );
        // an OLE file is FlashPix or MIC only when olefile finds their streams
        assert_eq!(identify(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"), None);
        // "PE" isn't a PPM's P with a digit
        assert_eq!(identify(b"MZ\x90\0"), None);
    }
}
