//! `Image.open`: each plugin's accept check and `_open`, in registry order.

use crate::image::Canvas;
use crate::{Kind, Raise};

/// Loads the pixels of an opened image (`im.load()`).
pub(crate) trait Load {
    fn load(self: Box<Self>) -> Result<Canvas, Raise>;
}

/// An image file `Image.open` returned.
pub(crate) struct Opened<'a> {
    pub(crate) format: &'static str,
    /// `im.mode` after `_open` (empty means not identified).
    pub(crate) mode: String,
    pub(crate) size: (i64, i64),
    /// A `StubImageFile` without a handler, for which a zero size is accepted.
    pub(crate) stub: bool,
    pub(crate) loader: Box<dyn Load + 'a>,
}

impl<'a> Opened<'a> {
    pub(crate) fn new(
        format: &'static str,
        mode: impl Into<String>,
        size: (i64, i64),
        loader: Box<dyn Load + 'a>,
    ) -> Self {
        Opened {
            format,
            mode: mode.into(),
            size,
            stub: false,
            loader,
        }
    }
}

/// A loader for an image this crate opens but cannot decode.
pub(crate) struct NoDecoder(pub(crate) &'static str);

impl Load for NoDecoder {
    fn load(self: Box<Self>) -> Result<Canvas, Raise> {
        Err(Raise::unsupported(self.0))
    }
}

/// A loader that raises what Pillow's load raises.
pub(crate) struct Fails(pub(crate) Raise);

impl Load for Fails {
    fn load(self: Box<Self>) -> Result<Canvas, Raise> {
        Err(self.0)
    }
}

type Accept = fn(&[u8]) -> Result<bool, Raise>;
type Factory = for<'a> fn(&'a [u8]) -> Result<Opened<'a>, Raise>;

struct Plugin {
    name: &'static str,
    accept: Option<Accept>,
    open: Factory,
}

use crate::plugins as p;

/// `Image.ID` in a process where `preinit()` and then `init()` have run.
const PLUGINS: &[Plugin] = &[
    Plugin {
        name: "BMP",
        accept: Some(p::bmp::accept),
        open: p::bmp::open_bmp,
    },
    Plugin {
        name: "DIB",
        accept: Some(p::bmp::dib_accept),
        open: p::bmp::open_dib,
    },
    Plugin {
        name: "GIF",
        accept: Some(p::gif::accept),
        open: p::gif::open,
    },
    Plugin {
        name: "JPEG",
        accept: Some(p::jpeg::accept),
        open: p::jpeg::open,
    },
    Plugin {
        name: "PPM",
        accept: Some(p::ppm::accept),
        open: p::ppm::open,
    },
    Plugin {
        name: "PNG",
        accept: Some(p::png::accept),
        open: p::png::open,
    },
    Plugin {
        name: "AVIF",
        accept: Some(p::avif::accept),
        open: p::avif::open,
    },
    Plugin {
        name: "BLP",
        accept: Some(p::misc::blp_accept),
        open: p::misc::blp_open,
    },
    Plugin {
        name: "BUFR",
        accept: Some(p::stub::bufr_accept),
        open: p::stub::bufr_open,
    },
    Plugin {
        name: "CUR",
        accept: Some(p::ico::cur_accept),
        open: p::ico::cur_open,
    },
    Plugin {
        name: "PCX",
        accept: Some(p::pcx::accept),
        open: p::pcx::open,
    },
    Plugin {
        name: "DCX",
        accept: Some(p::pcx::dcx_accept),
        open: p::pcx::dcx_open,
    },
    Plugin {
        name: "DDS",
        accept: Some(p::dds::accept),
        open: p::dds::open,
    },
    Plugin {
        name: "EPS",
        accept: Some(p::eps::accept),
        open: p::eps::open,
    },
    Plugin {
        name: "FITS",
        accept: Some(p::misc::fits_accept),
        open: p::misc::fits_open,
    },
    Plugin {
        name: "FLI",
        accept: Some(p::misc::fli_accept),
        open: p::misc::fli_open,
    },
    Plugin {
        name: "FPX",
        accept: Some(p::ole::accept),
        open: p::ole::fpx_open,
    },
    Plugin {
        name: "FTEX",
        accept: Some(p::misc::ftex_accept),
        open: p::misc::ftex_open,
    },
    Plugin {
        name: "GBR",
        accept: Some(p::misc::gbr_accept),
        open: p::misc::gbr_open,
    },
    Plugin {
        name: "GRIB",
        accept: Some(p::stub::grib_accept),
        open: p::stub::grib_open,
    },
    Plugin {
        name: "HDF5",
        accept: Some(p::stub::hdf5_accept),
        open: p::stub::hdf5_open,
    },
    Plugin {
        name: "JPEG2000",
        accept: Some(p::jpeg2k::accept),
        open: p::jpeg2k::open,
    },
    Plugin {
        name: "ICNS",
        accept: Some(p::icns::accept),
        open: p::icns::open,
    },
    Plugin {
        name: "ICO",
        accept: Some(p::ico::accept),
        open: p::ico::open,
    },
    Plugin {
        name: "IM",
        accept: None,
        open: p::im::open,
    },
    Plugin {
        name: "IMT",
        accept: None,
        open: p::misc::imt_open,
    },
    Plugin {
        name: "IPTC",
        accept: None,
        open: p::misc::iptc_open,
    },
    Plugin {
        name: "MCIDAS",
        accept: Some(p::misc::mcidas_accept),
        open: p::misc::mcidas_open,
    },
    Plugin {
        name: "TIFF",
        accept: Some(p::tiff::accept),
        open: p::tiff::open,
    },
    Plugin {
        name: "MIC",
        accept: Some(p::ole::accept),
        open: p::ole::mic_open,
    },
    Plugin {
        name: "MPEG",
        accept: Some(p::misc::mpeg_accept),
        open: p::misc::mpeg_open,
    },
    Plugin {
        name: "MSP",
        accept: Some(p::misc::msp_accept),
        open: p::misc::msp_open,
    },
    Plugin {
        name: "PCD",
        accept: None,
        open: p::misc::pcd_open,
    },
    Plugin {
        name: "PIXAR",
        accept: Some(p::misc::pixar_accept),
        open: p::misc::pixar_open,
    },
    Plugin {
        name: "PSD",
        accept: Some(p::psd::accept),
        open: p::psd::open,
    },
    Plugin {
        name: "QOI",
        accept: Some(p::misc::qoi_accept),
        open: p::misc::qoi_open,
    },
    Plugin {
        name: "SGI",
        accept: Some(p::misc::sgi_accept),
        open: p::misc::sgi_open,
    },
    Plugin {
        name: "SPIDER",
        accept: None,
        open: p::misc::spider_open,
    },
    Plugin {
        name: "SUN",
        accept: Some(p::misc::sun_accept),
        open: p::misc::sun_open,
    },
    Plugin {
        name: "TGA",
        accept: None,
        open: p::tga::open,
    },
    Plugin {
        name: "WEBP",
        accept: Some(p::webp::accept),
        open: p::webp::open,
    },
    Plugin {
        name: "WMF",
        accept: Some(p::stub::wmf_accept),
        open: p::stub::wmf_open,
    },
    Plugin {
        name: "XBM",
        accept: Some(p::misc::xbm_accept),
        open: p::misc::xbm_open,
    },
    Plugin {
        name: "XPM",
        accept: Some(p::misc::xpm_accept),
        open: p::misc::xpm_open,
    },
    Plugin {
        name: "XVTHUMB",
        accept: Some(p::misc::xvthumb_accept),
        open: p::misc::xvthumb_open,
    },
];

/// Exceptions `_open_core` catches around an accept check and a factory.
fn caught_by_open_core(k: Kind) -> bool {
    matches!(
        k,
        Kind::SyntaxError | Kind::IndexError | Kind::TypeError | Kind::StructError
    )
}

/// Exceptions `ImageFile.__init__` turns into SyntaxError.
fn caught_by_init(k: Kind) -> bool {
    caught_by_open_core(k) || matches!(k, Kind::KeyError | Kind::EOFError)
}

/// `Image._decompression_bomb_check`: only the error matters (the warning is a warning).
pub(crate) fn bomb_check(size: (i64, i64)) -> Result<(), Raise> {
    let pixels = (size.0.max(1) as i128) * (size.1.max(1) as i128);
    if pixels > 2 * crate::MAX_IMAGE_PIXELS as i128 {
        return Err(Raise::new(
            Kind::DecompressionBombError,
            format!(
                "Image size ({pixels} pixels) exceeds limit of {} pixels, could be decompression bomb DOS attack.",
                2 * crate::MAX_IMAGE_PIXELS
            ),
        ));
    }
    Ok(())
}

/// The checks `ImageFile.__init__` makes after `_open`.
pub(crate) fn check_identified(im: &Opened) -> Result<(), Raise> {
    let bad_size = if im.stub {
        im.size.0.min(im.size.1) < 0
    } else {
        im.size.0.min(im.size.1) <= 0
    };
    if im.mode.is_empty() || bad_size {
        return Err(Raise::syntax("not identified by this driver"));
    }
    Ok(())
}

/// `Image.open(fp)` over every registered format.
pub(crate) fn open(data: &[u8]) -> Result<Opened<'_>, Raise> {
    let prefix = &data[..data.len().min(16)];
    for plugin in PLUGINS {
        match plugin.accept.map_or(Ok(true), |a| a(prefix)) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(e) if caught_by_open_core(e.kind) => continue,
            Err(e) => return Err(e),
        }
        let r = (plugin.open)(data).and_then(|im| check_identified(&im).map(|()| im));
        match r {
            Ok(im) => {
                bomb_check(im.size)?;
                return Ok(im);
            }
            Err(e) if caught_by_init(e.kind) => {
                let _ = plugin.name;
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(Raise::new(
        Kind::UnidentifiedImageError,
        "cannot identify image file",
    ))
}
