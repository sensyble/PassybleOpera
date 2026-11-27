//! QR codes in PNG/JPEG images (a screenshot or photo of Google Authenticator's export screen, or
//! of a Passyble Server pairing QR code), and in raw RGBA pixels (a clipboard image on the desktop).

use std::io::Cursor;

use image::{GrayImage, ImageReader, Limits};

use super::invalid;
use crate::i18n::tr;
use crate::Result;

const MAX_SIDE: u32 = 8000;
/// Larger images are scaled down before QR detection; export QR codes are big and sharp.
const DETECT_SIDE: u32 = 2000;

/// The text of every QR code found in a PNG/JPEG image. `InvalidInput` if the image can't be read
/// or holds no QR code.
pub fn qr_decode_image(data: &[u8]) -> Result<Vec<String>> {
    let mut reader = ImageReader::new(Cursor::new(data))
        .with_guessed_format()
        .map_err(|_| invalid(tr!("import.image_unreadable")))?;
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_SIDE);
    limits.max_image_height = Some(MAX_SIDE);
    limits.max_alloc = Some(512 * 1024 * 1024);
    reader.limits(limits);
    let image = reader
        .decode()
        .map_err(|_| invalid(tr!("import.image_unreadable")))?;
    decode_gray(image.to_luma8())
}

/// [`qr_decode_image`] for raw 8-bit RGBA pixels, row by row (`width * height * 4` bytes).
pub fn qr_decode_rgba(width: u32, height: u32, rgba: &[u8]) -> Result<Vec<String>> {
    if width == 0 || height == 0 || width > MAX_SIDE || height > MAX_SIDE {
        return Err(invalid(tr!("import.image_size")));
    }
    let pixels = (width as usize) * (height as usize);
    if rgba.len() != pixels * 4 {
        return Err(invalid(tr!("import.image_data_size")));
    }
    let gray = GrayImage::from_fn(width, height, |x, y| {
        let i = ((y as usize) * (width as usize) + x as usize) * 4;
        let (r, g, b) = (
            u32::from(rgba[i]),
            u32::from(rgba[i + 1]),
            u32::from(rgba[i + 2]),
        );
        // Rec. 601 luma; transparent pixels count as white (screenshots of light pages).
        let a = u32::from(rgba[i + 3]);
        let luma = (299 * r + 587 * g + 114 * b) / 1000;
        image::Luma([((luma * a + 255 * (255 - a)) / 255) as u8])
    });
    decode_gray(gray)
}

fn decode_gray(mut gray: GrayImage) -> Result<Vec<String>> {
    if gray.width().max(gray.height()) > DETECT_SIDE {
        let scale = f64::from(DETECT_SIDE) / f64::from(gray.width().max(gray.height()));
        let w = ((f64::from(gray.width()) * scale) as u32).max(1);
        let h = ((f64::from(gray.height()) * scale) as u32).max(1);
        gray = image::imageops::resize(&gray, w, h, image::imageops::FilterType::Triangle);
    }
    let mut found = detect(&gray);
    if found.is_empty() {
        // Dark-mode screenshots: light modules on a dark background.
        image::imageops::invert(&mut gray);
        found = detect(&gray);
    }
    if found.is_empty() {
        return Err(invalid(tr!("import.no_qr_code")));
    }
    Ok(found)
}

fn detect(gray: &GrayImage) -> Vec<String> {
    // The decoder is third-party code fed untrusted pixels: contain any panic.
    std::panic::catch_unwind(|| {
        let (w, h) = (gray.width() as usize, gray.height() as usize);
        let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| {
            gray.get_pixel(x as u32, y as u32)[0]
        });
        prepared
            .detect_grids()
            .into_iter()
            .filter_map(|grid| grid.decode().ok().map(|(_, text)| text))
            .collect::<Vec<_>>()
    })
    .unwrap_or_default()
}
