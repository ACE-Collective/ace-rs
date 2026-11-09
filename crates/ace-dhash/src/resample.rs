//! `Image.resize(size, Image.Resampling.LANCZOS)` for mode "L": Pillow's `Resample.c`.

const PRECISION_BITS: u32 = 32 - 8 - 2;
const LANCZOS_SUPPORT: f64 = 3.0;

fn sinc(x: f64) -> f64 {
    if x == 0.0 {
        return 1.0;
    }
    let x = x * std::f64::consts::PI;
    x.sin() / x
}

fn lanczos(x: f64) -> f64 {
    if (-3.0..3.0).contains(&x) {
        sinc(x) * sinc(x / 3.0)
    } else {
        0.0
    }
}

/// `clip8_lookups[in >> PRECISION_BITS]` over Pillow's table, which covers -640 to 639.
fn clip8(v: i32) -> u8 {
    let i = v >> PRECISION_BITS;
    i.clamp(0, 255) as u8
}

struct Coeffs {
    ksize: usize,
    /// (xmin, xmax) per output pixel, xmax being a count.
    bounds: Vec<(usize, usize)>,
    kk: Vec<i32>,
}

/// `precompute_coeffs` then `normalize_coeffs_8bpc`.
fn precompute(in_size: usize, in0: f32, in1: f32, out_size: usize) -> Coeffs {
    let scale = (in1 - in0) as f64 / out_size as f64;
    let filterscale = if scale < 1.0 { 1.0 } else { scale };
    let support = LANCZOS_SUPPORT * filterscale;
    let ksize = support.ceil() as usize * 2 + 1;
    let mut kk = vec![0f64; out_size * ksize];
    let mut bounds = Vec::with_capacity(out_size);
    let inv_filterscale = 1.0 / filterscale;
    for xx in 0..out_size {
        let center = in0 as f64 + (xx as f64 + 0.5) * scale;
        let mut ww = 0.0;
        // C truncates toward zero; the values here are never below -1.
        let mut xmin = (center - support + 0.5) as i64;
        if xmin < 0 {
            xmin = 0;
        }
        let mut xmax = (center + support + 0.5) as i64;
        if xmax > in_size as i64 {
            xmax = in_size as i64;
        }
        let xmax = (xmax - xmin).max(0) as usize;
        let xmin = xmin as usize;
        let k = &mut kk[xx * ksize..(xx + 1) * ksize];
        for (x, kx) in k.iter_mut().enumerate().take(xmax) {
            let w = lanczos((x as f64 + xmin as f64 - center + 0.5) * inv_filterscale);
            *kx = w;
            ww += w;
        }
        if ww != 0.0 {
            for kx in k.iter_mut().take(xmax) {
                *kx /= ww;
            }
        }
        bounds.push((xmin, xmax));
    }
    let one = (1u32 << PRECISION_BITS) as f64;
    let kk = kk
        .iter()
        .map(|&v| {
            if v < 0.0 {
                (-0.5 + v * one) as i32
            } else {
                (0.5 + v * one) as i32
            }
        })
        .collect();
    Coeffs { ksize, bounds, kk }
}

/// An 8-bit single band image, row major.
pub(crate) struct Gray {
    pub(crate) w: usize,
    pub(crate) h: usize,
    pub(crate) px: Vec<u8>,
}

fn horizontal(input: &Gray, offset: usize, rows: usize, c: &Coeffs) -> Gray {
    let xsize = c.bounds.len();
    let mut out = vec![0u8; xsize * rows];
    for yy in 0..rows {
        let line = &input.px[(yy + offset) * input.w..(yy + offset + 1) * input.w];
        for (xx, &(xmin, xmax)) in c.bounds.iter().enumerate() {
            let k = &c.kk[xx * c.ksize..];
            let mut ss: i32 = 1 << (PRECISION_BITS - 1);
            for x in 0..xmax {
                ss = ss.wrapping_add((line[x + xmin] as i32).wrapping_mul(k[x]));
            }
            out[yy * xsize + xx] = clip8(ss);
        }
    }
    Gray {
        w: xsize,
        h: rows,
        px: out,
    }
}

fn vertical(input: &Gray, c: &Coeffs) -> Gray {
    let ysize = c.bounds.len();
    let xsize = input.w;
    let mut out = vec![0u8; xsize * ysize];
    for (yy, &(ymin, ymax)) in c.bounds.iter().enumerate() {
        let k = &c.kk[yy * c.ksize..];
        for xx in 0..xsize {
            let mut ss: i32 = 1 << (PRECISION_BITS - 1);
            for y in 0..ymax {
                ss = ss.wrapping_add((input.px[(y + ymin) * xsize + xx] as i32).wrapping_mul(k[y]));
            }
            out[yy * xsize + xx] = clip8(ss);
        }
    }
    Gray {
        w: xsize,
        h: ysize,
        px: out,
    }
}

/// `im.resize((xsize, ysize), LANCZOS)` for mode "L" with the default box.
pub(crate) fn resize_lanczos(im: Gray, xsize: usize, ysize: usize) -> Gray {
    // Image.resize: the same size is a copy.
    if im.w == xsize && im.h == ysize {
        return im;
    }
    let box_ = [0f32, 0f32, im.w as f32, im.h as f32];
    let need_horizontal = xsize != im.w || box_[0] != 0.0 || box_[2] != xsize as f32;
    let need_vertical = ysize != im.h || box_[1] != 0.0 || box_[3] != ysize as f32;
    let (in_w, in_h) = (im.w as i64, im.h as i64);
    let horizontal_first =
        !((in_h - ysize as i64) > 0 && (in_h - ysize as i64) > (in_w - xsize as i64) * 2);

    let mut vert = None;
    if (need_horizontal && horizontal_first) || need_vertical {
        vert = Some(precompute(im.h, box_[1], box_[3], ysize));
    }
    let mut ybox_first = 0;
    let mut ybox_last = 0;
    let mut horiz = None;
    if need_horizontal {
        if horizontal_first {
            let v = vert.as_mut().expect("vertical coefficients");
            ybox_first = v.bounds[0].0;
            let last = v.bounds[ysize - 1];
            ybox_last = last.0 + last.1;
            if ybox_first != 0 {
                for b in &mut v.bounds {
                    b.0 -= ybox_first;
                }
            }
        }
        horiz = Some(precompute(im.w, box_[0], box_[2], xsize));
    }
    let mut cur = im;
    if horizontal_first {
        if let Some(h) = &horiz {
            cur = horizontal(&cur, ybox_first, ybox_last - ybox_first, h);
        }
        if need_vertical {
            cur = vertical(&cur, vert.as_ref().expect("vertical coefficients"));
        }
    } else {
        if need_vertical {
            cur = vertical(&cur, vert.as_ref().expect("vertical coefficients"));
        }
        if let Some(h) = &horiz {
            let rows = cur.h;
            cur = horizontal(&cur, 0, rows, h);
        }
    }
    cur
}
