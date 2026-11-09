//! WebPImagePlugin: Pillow opens WebP files with libwebp's `WebPAnimDecoder`, so whether a file
//! opens is whether libwebp 1.6.0's demuxer (`WebPDemux`, demux.c) accepts it; that is ported
//! here. The first frame is decoded by the `image-webp` crate, whose lossy and lossless output
//! matches libwebp's (fancy upsampling) on the cases tested, onto a canvas cleared to
//! transparent black as `WebPAnimDecoderGetNext` does for a key frame.

use crate::Raise;
use crate::image::{Canvas, Mode};
use crate::io::u16le;
use crate::open::{Load, Opened, bomb_check};

const CHUNK_HEADER_SIZE: usize = 8;
const RIFF_HEADER_SIZE: usize = 12;
const MAX_CHUNK_PAYLOAD: u64 = (u32::MAX - 8 - 1) as u64;
const MAX_IMAGE_AREA: u64 = 1 << 32;
const ANIMATION_FLAG: u32 = 0x02;
const XMP_FLAG: u32 = 0x04;
const EXIF_FLAG: u32 = 0x08;
const ALPHA_FLAG: u32 = 0x10;
const ICCP_FLAG: u32 = 0x20;
const ALL_VALID_FLAGS: u32 = 0x3e;

pub(crate) fn accept(prefix: &[u8]) -> Result<bool, Raise> {
    let mode = prefix.get(12..16.min(prefix.len())).unwrap_or(&[]);
    Ok(prefix.starts_with(b"RIFF")
        && prefix.get(8..12.min(prefix.len())) == Some(b"WEBP")
        && matches!(mode, b"VP8 " | b"VP8X" | b"VP8L"))
}

fn le24(b: &[u8], o: usize) -> u32 {
    b[o] as u32 | (b[o + 1] as u32) << 8 | (b[o + 2] as u32) << 16
}

fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Pillow's `_get_size` over the first 30 bytes.
fn get_size(s: &[u8]) -> Option<(i64, i64)> {
    match &s[12..16] {
        b"VP8 " if s.len() >= 30 && &s[23..26] == b"\x9d\x01\x2a" => Some((
            (u16le(s, 26).ok()? & 0x3FFF) as i64,
            (u16le(s, 28).ok()? & 0x3FFF) as i64,
        )),
        b"VP8X" if s.len() >= 30 => Some((le24(s, 24) as i64 + 1, le24(s, 27) as i64 + 1)),
        b"VP8L" if s.len() >= 25 && s[20] == 0x2F => {
            let bits = le32(s, 21);
            Some((
                (bits & 0x3FFF) as i64 + 1,
                ((bits >> 14) & 0x3FFF) as i64 + 1,
            ))
        }
        _ => None,
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
enum Status {
    Ok,
    NeedMore,
    Error,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Vp8 {
    Ok,
    NotEnough,
    Error,
}

#[derive(Default, Clone, Copy)]
struct Features {
    width: i64,
    height: i64,
    has_alpha: bool,
}

/// VP8GetInfo.
fn vp8_get_info(data: &[u8], chunk_size: u64) -> Option<(i64, i64)> {
    if data.len() < 10 || &data[3..6] != b"\x9d\x01\x2a" {
        return None;
    }
    let bits = data[0] as u32 | (data[1] as u32) << 8 | (data[2] as u32) << 16;
    let w = (((data[7] as u32) << 8) | data[6] as u32) & 0x3fff;
    let h = (((data[9] as u32) << 8) | data[8] as u32) & 0x3fff;
    if bits & 1 != 0 || ((bits >> 1) & 7) > 3 || (bits >> 4) & 1 == 0 {
        return None;
    }
    if (bits >> 5) as u64 >= chunk_size || w == 0 || h == 0 {
        return None;
    }
    Some((w as i64, h as i64))
}

/// VP8LGetInfo: (width, height, has_alpha).
fn vp8l_get_info(data: &[u8]) -> Option<(i64, i64, bool)> {
    if data.len() < 5 || data[0] != 0x2f || (data[4] >> 5) != 0 {
        return None;
    }
    let bits = le32(data, 1) as u64 | (data[4] as u64) << 32;
    let w = (bits & 0x3fff) as i64 + 1;
    let h = ((bits >> 14) & 0x3fff) as i64 + 1;
    let a = (bits >> 28) & 1 == 1;
    Some((w, h, a))
}

/// WebPGetFeatures (ParseHeadersInternal without headers, so without all data).
fn get_features(data: &[u8]) -> (Vp8, Features) {
    let mut f = Features::default();
    if data.len() < RIFF_HEADER_SIZE {
        return (Vp8::NotEnough, f);
    }
    let mut d = data;
    let mut riff_size = 0u64;
    if d.starts_with(b"RIFF") {
        if &d[8..12] != b"WEBP" {
            return (Vp8::Error, f);
        }
        let size = le32(d, 4) as u64;
        if size < 12 || size > MAX_CHUNK_PAYLOAD {
            return (Vp8::Error, f);
        }
        riff_size = size;
        d = &d[RIFF_HEADER_SIZE..];
    }
    let found_riff = riff_size > 0;
    // ParseVP8X
    if d.len() < CHUNK_HEADER_SIZE {
        return (Vp8::NotEnough, f);
    }
    let mut found_vp8x = false;
    let (mut cw, mut ch) = (0i64, 0i64);
    let mut flags = 0u32;
    if d.starts_with(b"VP8X") {
        if le32(d, 4) != 10 {
            return (Vp8::Error, f);
        }
        if d.len() < 18 {
            return (Vp8::NotEnough, f);
        }
        flags = le32(d, 8);
        cw = 1 + le24(d, 12) as i64;
        ch = 1 + le24(d, 15) as i64;
        if (cw as u64) * (ch as u64) >= MAX_IMAGE_AREA {
            return (Vp8::Error, f);
        }
        d = &d[18..];
        found_vp8x = true;
    }
    let animation = flags & ANIMATION_FLAG != 0;
    if !found_riff && found_vp8x {
        return (Vp8::Error, f);
    }
    f.has_alpha = flags & ALPHA_FLAG != 0;
    let (mut iw, mut ih) = (cw, ch);
    let mut alpha_data = false;
    let finish =
        |st: Vp8, mut f: Features, iw: i64, ih: i64, alpha_data: bool| -> (Vp8, Features) {
            if st == Vp8::Ok || (st == Vp8::NotEnough && found_vp8x) {
                f.has_alpha |= alpha_data;
                f.width = iw;
                f.height = ih;
                (Vp8::Ok, f)
            } else {
                (st, f)
            }
        };
    if found_vp8x && animation {
        return finish(Vp8::Ok, f, iw, ih, alpha_data);
    }
    if d.len() < 4 {
        return finish(Vp8::NotEnough, f, iw, ih, alpha_data);
    }
    if (found_riff && found_vp8x) || (!found_riff && !found_vp8x && d.starts_with(b"ALPH")) {
        // ParseOptionalChunks
        let mut total: u64 = 4 + 8 + 10;
        loop {
            if d.len() < CHUNK_HEADER_SIZE {
                return finish(Vp8::NotEnough, f, iw, ih, alpha_data);
            }
            let cs = le32(d, 4) as u64;
            if cs > MAX_CHUNK_PAYLOAD {
                return finish(Vp8::Error, f, iw, ih, alpha_data);
            }
            let disk = (8 + cs + 1) & !1;
            total += disk;
            if riff_size > 0 && total > riff_size {
                return finish(Vp8::Error, f, iw, ih, alpha_data);
            }
            if d.starts_with(b"VP8 ") || d.starts_with(b"VP8L") {
                break;
            }
            if (d.len() as u64) < disk {
                return finish(Vp8::NotEnough, f, iw, ih, alpha_data);
            }
            if d.starts_with(b"ALPH") {
                alpha_data = true;
            }
            d = &d[disk as usize..];
        }
    }
    // ParseVP8Header
    if d.len() < CHUNK_HEADER_SIZE {
        return finish(Vp8::NotEnough, f, iw, ih, alpha_data);
    }
    let is_vp8 = d.starts_with(b"VP8 ");
    let is_vp8l = d.starts_with(b"VP8L");
    let compressed;
    let lossless;
    if is_vp8 || is_vp8l {
        let size = le32(d, 4) as u64;
        if riff_size >= 12 && size > riff_size - 12 {
            return finish(Vp8::Error, f, iw, ih, alpha_data);
        }
        compressed = size;
        d = &d[8..];
        lossless = is_vp8l;
    } else {
        lossless = d.len() >= 5 && d[0] == 0x2f && (d[4] >> 5) == 0;
        compressed = d.len() as u64;
    }
    if compressed > MAX_CHUNK_PAYLOAD {
        return (Vp8::Error, f);
    }
    if !lossless {
        if d.len() < 10 {
            return finish(Vp8::NotEnough, f, iw, ih, alpha_data);
        }
        match vp8_get_info(d, compressed) {
            Some((w, h)) => {
                iw = w;
                ih = h;
            }
            None => return (Vp8::Error, f),
        }
    } else {
        if d.len() < 5 {
            return finish(Vp8::NotEnough, f, iw, ih, alpha_data);
        }
        match vp8l_get_info(d) {
            Some((w, h, a)) => {
                iw = w;
                ih = h;
                f.has_alpha = a;
            }
            None => return (Vp8::Error, f),
        }
    }
    if found_vp8x && (cw != iw || ch != ih) {
        return (Vp8::Error, f);
    }
    finish(Vp8::Ok, f, iw, ih, alpha_data)
}

#[derive(Default, Clone, Debug)]
struct Frame {
    x_offset: i64,
    y_offset: i64,
    width: i64,
    height: i64,
    has_alpha: bool,
    frame_num: i64,
    complete: bool,
    /// (offset, size) of the image chunk and the alpha chunk.
    image: (usize, usize),
    alpha: (usize, usize),
}

struct Demux<'a> {
    buf: &'a [u8],
    start: usize,
    end: usize,
    riff_end: usize,
    state_done: bool,
    parsed_header: bool,
    is_ext: bool,
    flags: u32,
    canvas_w: i64,
    canvas_h: i64,
    loop_count: i64,
    frames: Vec<Frame>,
    num_frames: i64,
}

impl Demux<'_> {
    fn data_size(&self) -> usize {
        self.end - self.start
    }
    fn size_invalid(&self, size: u64) -> bool {
        size > (self.riff_end - self.start) as u64
    }
    fn le32(&mut self) -> u32 {
        let v = le32(self.buf, self.start);
        self.start += 4;
        v
    }
    fn le24(&mut self) -> i64 {
        let v = le24(self.buf, self.start) as i64;
        self.start += 3;
        v
    }

    fn add_frame(&mut self, f: Frame) -> bool {
        if let Some(last) = self.frames.last() {
            if !last.complete {
                return false;
            }
        }
        self.frames.push(f);
        true
    }

    fn store_frame(&mut self, frame_num: i64, min_size: u64, frame: &mut Frame) -> Status {
        let mut alpha_chunks = 0;
        let mut image_chunks = 0;
        let mut done = self.data_size() < CHUNK_HEADER_SIZE || (self.data_size() as u64) < min_size;
        let mut status = Status::Ok;
        if done {
            return Status::NeedMore;
        }
        while !done && status == Status::Ok {
            let chunk_start = self.start;
            let fourcc = &self.buf[self.start..self.start + 4];
            let fourcc: [u8; 4] = [fourcc[0], fourcc[1], fourcc[2], fourcc[3]];
            self.start += 4;
            let payload = self.le32() as u64;
            if payload > MAX_CHUNK_PAYLOAD {
                return Status::Error;
            }
            let padded = payload + (payload & 1);
            let available = padded.min(self.data_size() as u64) as usize;
            let chunk_size = CHUNK_HEADER_SIZE + available;
            if self.size_invalid(padded) {
                return Status::Error;
            }
            if padded > self.data_size() as u64 {
                status = Status::NeedMore;
            }
            let mut stop = false;
            match &fourcc {
                b"ALPH" if alpha_chunks == 0 => {
                    alpha_chunks += 1;
                    frame.alpha = (chunk_start, chunk_size);
                    frame.has_alpha = true;
                    frame.frame_num = frame_num;
                    self.start += available;
                }
                b"VP8L" | b"VP8 " if image_chunks == 0 => {
                    if &fourcc == b"VP8L" && alpha_chunks > 0 {
                        return Status::Error;
                    }
                    let (st, feat) = get_features(&self.buf[chunk_start..chunk_start + chunk_size]);
                    if status == Status::NeedMore && st == Vp8::NotEnough {
                        return Status::NeedMore;
                    } else if st != Vp8::Ok {
                        return Status::Error;
                    }
                    image_chunks += 1;
                    frame.image = (chunk_start, chunk_size);
                    frame.width = feat.width;
                    frame.height = feat.height;
                    frame.has_alpha |= feat.has_alpha;
                    frame.frame_num = frame_num;
                    frame.complete = status == Status::Ok;
                    self.start += available;
                }
                b"VP8L" if alpha_chunks > 0 => return Status::Error,
                _ => stop = true,
            }
            if stop {
                self.start -= CHUNK_HEADER_SIZE;
                done = true;
            }
            if self.start == self.riff_end {
                done = true;
            } else if self.data_size() < CHUNK_HEADER_SIZE {
                status = Status::NeedMore;
            }
        }
        status
    }

    fn parse_single_image(&mut self) -> Status {
        if !self.frames.is_empty() {
            return Status::Error;
        }
        if self.size_invalid(CHUNK_HEADER_SIZE as u64) {
            return Status::Error;
        }
        if self.data_size() < CHUNK_HEADER_SIZE {
            return Status::NeedMore;
        }
        let mut frame = Frame::default();
        let status = self.store_frame(1, 0, &mut frame);
        if status != Status::Error {
            let has_alpha = self.flags & ALPHA_FLAG != 0;
            if !has_alpha && frame.alpha.1 > 0 {
                frame.alpha = (0, 0);
                frame.has_alpha = false;
            }
            if !self.is_ext && frame.width > 0 && frame.height > 0 {
                self.parsed_header = true;
                self.canvas_w = frame.width;
                self.canvas_h = frame.height;
                if frame.has_alpha {
                    self.flags |= ALPHA_FLAG;
                }
            }
            if !self.add_frame(frame) {
                return Status::Error;
            }
            self.num_frames = 1;
        }
        status
    }

    fn parse_animation_frame(&mut self, frame_chunk_size: u64) -> Status {
        let is_animation = self.flags & ANIMATION_FLAG != 0;
        let anmf_payload = frame_chunk_size.wrapping_sub(16);
        if self.size_invalid(16) {
            return Status::Error;
        }
        if frame_chunk_size < 16 {
            return Status::Error;
        }
        if self.data_size() < 16 {
            return Status::NeedMore;
        }
        let mut frame = Frame {
            x_offset: 2 * self.le24(),
            y_offset: 2 * self.le24(),
            width: 1 + self.le24(),
            height: 1 + self.le24(),
            ..Default::default()
        };
        let _duration = self.le24();
        self.start += 1;
        if (frame.width as u64) * (frame.height as u64) >= MAX_IMAGE_AREA {
            return Status::Error;
        }
        let start = self.start;
        let mut status = self.store_frame(self.num_frames + 1, anmf_payload, &mut frame);
        if status != Status::Error && (self.start - start) as u64 > anmf_payload {
            status = Status::Error;
        }
        if status != Status::Error && is_animation && frame.frame_num > 0 {
            if self.add_frame(frame) {
                self.num_frames += 1;
            } else {
                status = Status::Error;
            }
        }
        status
    }

    fn parse_vp8x_chunks(&mut self) -> Status {
        let is_animation = self.flags & ANIMATION_FLAG != 0;
        let mut anim_chunks = 0;
        let mut status;
        loop {
            let chunk_start = self.start;
            let fourcc: [u8; 4] = self.buf[self.start..self.start + 4]
                .try_into()
                .expect("4 bytes");
            self.start += 4;
            let chunk_size = self.le32() as u64;
            if chunk_size > MAX_CHUNK_PAYLOAD {
                return Status::Error;
            }
            let padded = chunk_size + (chunk_size & 1);
            if self.size_invalid(padded) {
                return Status::Error;
            }
            status = Status::Ok;
            let mut skip = false;
            match &fourcc {
                b"VP8X" => return Status::Error,
                b"ALPH" | b"VP8 " | b"VP8L" => {
                    if anim_chunks > 0 || is_animation {
                        return Status::Error;
                    }
                    self.start -= CHUNK_HEADER_SIZE;
                    status = self.parse_single_image();
                }
                b"ANIM" => {
                    if padded < 6 {
                        return Status::Error;
                    }
                    if (self.data_size() as u64) < padded {
                        status = Status::NeedMore;
                    } else if anim_chunks == 0 {
                        anim_chunks += 1;
                        let _bg = self.le32();
                        self.loop_count = u16le(self.buf, self.start).unwrap_or(0) as i64;
                        self.start += 2;
                        self.start += (padded - 6) as usize;
                    } else {
                        skip = true;
                    }
                }
                b"ANMF" => {
                    if anim_chunks == 0 {
                        return Status::Error;
                    }
                    status = self.parse_animation_frame(padded);
                }
                _ => skip = true,
            }
            let _ = (chunk_start, ICCP_FLAG, EXIF_FLAG, XMP_FLAG);
            if skip {
                if padded <= self.data_size() as u64 {
                    self.start += padded as usize;
                } else {
                    status = Status::NeedMore;
                }
            }
            if self.start == self.riff_end {
                break;
            } else if self.data_size() < CHUNK_HEADER_SIZE {
                status = Status::NeedMore;
            }
            if status != Status::Ok {
                break;
            }
        }
        status
    }

    fn parse_vp8x(&mut self) -> Status {
        if self.data_size() < CHUNK_HEADER_SIZE {
            return Status::NeedMore;
        }
        self.is_ext = true;
        self.start += 4;
        let mut size = self.le32() as u64;
        if size > MAX_CHUNK_PAYLOAD || size < 10 {
            return Status::Error;
        }
        size += size & 1;
        if self.size_invalid(size) {
            return Status::Error;
        }
        if (self.data_size() as u64) < size {
            return Status::NeedMore;
        }
        self.flags = self.buf[self.start] as u32;
        self.start += 4;
        self.canvas_w = 1 + self.le24();
        self.canvas_h = 1 + self.le24();
        if (self.canvas_w as u64) * (self.canvas_h as u64) >= MAX_IMAGE_AREA {
            return Status::Error;
        }
        self.start += (size - 10) as usize;
        self.parsed_header = true;
        if self.size_invalid(CHUNK_HEADER_SIZE as u64) {
            return Status::Error;
        }
        if self.data_size() < CHUNK_HEADER_SIZE {
            return Status::NeedMore;
        }
        self.parse_vp8x_chunks()
    }

    fn valid_simple(&self) -> bool {
        if !self.parsed_header && !self.state_done {
            return true;
        }
        if self.canvas_w <= 0 || self.canvas_h <= 0 {
            return false;
        }
        let Some(f) = self.frames.first() else {
            return !self.state_done && false;
        };
        f.width > 0 && f.height > 0
    }

    fn valid_extended(&self) -> bool {
        let is_animation = self.flags & ANIMATION_FLAG != 0;
        if !self.parsed_header && !self.state_done {
            return true;
        }
        if self.canvas_w <= 0 || self.canvas_h <= 0 || self.loop_count < 0 {
            return false;
        }
        if self.state_done && self.frames.is_empty() {
            return false;
        }
        if self.flags & !ALL_VALID_FLAGS != 0 {
            return false;
        }
        for (i, f) in self.frames.iter().enumerate() {
            if !is_animation && f.frame_num > 1 {
                return false;
            }
            if f.complete {
                if f.alpha.1 == 0 && f.image.1 == 0 {
                    return false;
                }
                if f.alpha.1 > 0 && f.alpha.0 > f.image.0 {
                    return false;
                }
                if f.width <= 0 || f.height <= 0 {
                    return false;
                }
            } else {
                if self.state_done {
                    return false;
                }
                if f.alpha.1 > 0 && f.image.1 > 0 && f.alpha.0 > f.image.0 {
                    return false;
                }
                if i + 1 < self.frames.len() {
                    return false;
                }
            }
            if f.width > 0 && f.height > 0 {
                let ok = if !is_animation {
                    f.x_offset == 0
                        && f.y_offset == 0
                        && f.width == self.canvas_w
                        && f.height == self.canvas_h
                } else {
                    f.x_offset >= 0
                        && f.y_offset >= 0
                        && f.width + f.x_offset <= self.canvas_w
                        && f.height + f.y_offset <= self.canvas_h
                };
                if !ok {
                    return false;
                }
            }
        }
        true
    }
}

/// WebPDemux(data) (not partial): the demuxer, or None.
fn demux(buf: &[u8]) -> Option<Demux<'_>> {
    if buf.len() < RIFF_HEADER_SIZE + CHUNK_HEADER_SIZE {
        return None;
    }
    if &buf[..4] != b"RIFF" || &buf[8..12] != b"WEBP" {
        return None;
    }
    let riff_size = le32(buf, 4) as u64;
    if riff_size < 8 || riff_size > MAX_CHUNK_PAYLOAD {
        // CreateRawImageDemuxer on data that starts with "RIFF" fails too.
        return None;
    }
    let riff_end = (riff_size + 8) as usize;
    let mut end = buf.len();
    if end > riff_end {
        end = riff_end;
    }
    if end < riff_end {
        return None; // partial
    }
    let mut d = Demux {
        buf,
        start: RIFF_HEADER_SIZE,
        end,
        riff_end,
        state_done: false,
        parsed_header: false,
        is_ext: false,
        flags: 0,
        canvas_w: -1,
        canvas_h: -1,
        loop_count: 1,
        frames: Vec::new(),
        num_frames: 0,
    };
    let id = &buf[12..16];
    let (mut status, ext) = match id {
        b"VP8 " | b"VP8L" => (d.parse_single_image(), false),
        b"VP8X" => (d.parse_vp8x(), true),
        _ => return None,
    };
    if status == Status::Ok {
        d.state_done = true;
    }
    if status == Status::NeedMore {
        status = Status::Error;
    }
    if status != Status::Error {
        let valid = if ext {
            d.valid_extended()
        } else {
            d.valid_simple()
        };
        if !valid {
            status = Status::Error;
        }
    }
    if status == Status::Error {
        return None;
    }
    Some(d)
}

pub(crate) fn open(data: &[u8]) -> Result<Opened<'_>, Raise> {
    let s = &data[..data.len().min(30)];
    if !accept(s)? {
        return Err(Raise::syntax("not a WEBP file"));
    }
    if let Some(size) = get_size(s) {
        bomb_check(size)?;
    }
    let d = demux(data).ok_or_else(|| Raise::os("could not create decoder object"))?;
    let (st, feat) = get_features(data);
    let alpha = !(st == Vp8::Ok && !feat.has_alpha);
    let mode = if alpha { "RGBA" } else { "RGB" };
    let size = (d.canvas_w, d.canvas_h);
    let frame = d.frames.first().cloned();
    Ok(Opened::new(
        "WEBP",
        mode,
        size,
        Box::new(WebpLoad {
            data,
            alpha,
            size,
            frame,
        }),
    ))
}

struct WebpLoad<'a> {
    data: &'a [u8],
    alpha: bool,
    size: (i64, i64),
    frame: Option<Frame>,
}

fn decode_err() -> Raise {
    Raise::os("failed to read next frame")
}

impl Load for WebpLoad<'_> {
    fn load(self: Box<Self>) -> Result<Canvas, Raise> {
        let mode = if self.alpha { Mode::Rgba } else { Mode::Rgb };
        let (cw, ch) = (self.size.0 as usize, self.size.1 as usize);
        let mut c = Canvas::new(mode, cw, ch)?;
        let f = self.frame.ok_or_else(decode_err)?;
        // The frame's chunks as a still WebP file.
        let mut body = Vec::new();
        body.extend_from_slice(b"WEBP");
        if f.alpha.1 > 0 {
            body.extend_from_slice(b"VP8X");
            body.extend_from_slice(&10u32.to_le_bytes());
            body.extend_from_slice(&[ALPHA_FLAG as u8, 0, 0, 0]);
            let w = (f.width - 1) as u32;
            let h = (f.height - 1) as u32;
            body.extend_from_slice(&w.to_le_bytes()[..3]);
            body.extend_from_slice(&h.to_le_bytes()[..3]);
            body.extend_from_slice(&self.data[f.alpha.0..f.alpha.0 + f.alpha.1]);
            if f.alpha.1 % 2 == 1 {
                body.push(0);
            }
        }
        body.extend_from_slice(&self.data[f.image.0..f.image.0 + f.image.1]);
        if f.image.1 % 2 == 1 {
            body.push(0);
        }
        let mut file = Vec::with_capacity(body.len() + 8);
        file.extend_from_slice(b"RIFF");
        file.extend_from_slice(&(body.len() as u32).to_le_bytes());
        file.extend_from_slice(&body);
        let mut dec =
            image_webp::WebPDecoder::new(std::io::Cursor::new(&file)).map_err(|_| decode_err())?;
        let (w, h) = dec.dimensions();
        let (w, h) = (w as usize, h as usize);
        let has_alpha = dec.has_alpha();
        let bpp = if has_alpha { 4 } else { 3 };
        let n = w
            .checked_mul(h)
            .and_then(|n| n.checked_mul(bpp))
            .ok_or_else(Raise::memory)?;
        let mut buf = vec![0u8; n];
        dec.read_image(&mut buf).map_err(|_| decode_err())?;
        let (x0, y0) = (f.x_offset as usize, f.y_offset as usize);
        let mut row = vec![0u8; w * 4];
        for y in 0..h {
            for x in 0..w {
                let p = &buf[(y * w + x) * bpp..];
                row[x * 4..x * 4 + 4].copy_from_slice(&[
                    p[0],
                    p[1],
                    p[2],
                    if has_alpha { p[3] } else { 255 },
                ]);
            }
            c.put_row(x0, y0 + y, &row, w);
        }
        Ok(c)
    }
}
