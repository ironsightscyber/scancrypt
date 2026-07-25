"""
Generate the ScanCrypt application icon from the brand mark: the scan reticle corners
(signal green) over the entropy bar (a red encrypted block, a green intact block) on the
site's near-black background.

The mark is drawn in code so the icon is reproducible and stays in sync with the palette,
rather than living as an opaque binary nobody can regenerate. Geometry mirrors the
`#sc-mark` SVG symbol on the website (a 32x32 viewBox).

Requires Pillow (in the dev extras). Run from the repo root:
    python build_scripts/make_icon.py

Outputs:
    assets/scancrypt.ico   multi-resolution Windows icon (16..256 px), used by PyInstaller
    assets/scancrypt.png   256 px preview of the same rendering
    docs/favicon.png       48 px favicon for the website
"""
from PIL import Image, ImageDraw

BG = "#0A0C11"       # site background
SIG = "#37E28C"      # signal green: recovered / alive
ENC = "#FF5A5A"      # encrypted red

# Render supersampled on a 32-unit grid (the SVG viewBox), then downsample per size.
GRID = 32
SS = 32              # 32x supersampling -> master is 1024 px


def _capsule(d, x0, y0, x1, y1, color, s):
    """A stroke segment drawn as a rounded rect (capsule), like an SVG round line cap."""
    d.rounded_rectangle([x0 * s, y0 * s, x1 * s, y1 * s],
                        radius=min(x1 - x0, y1 - y0) * s / 2, fill=color)


def render_master() -> Image.Image:
    s = SS
    img = Image.new("RGBA", (GRID * s, GRID * s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # Badge background: the near-black site panel with a rounded corner.
    d.rounded_rectangle([0, 0, GRID * s, GRID * s], radius=6 * s, fill=BG)

    # Reticle corners (stroke width 2 on the 32 grid, centered on the SVG path lines).
    # Each corner is a vertical and a horizontal capsule meeting at the bend.
    for fx in (False, True):        # flip horizontally for right-hand corners
        for fy in (False, True):    # flip vertically for bottom corners
            def X(v):
                return GRID - v if fx else v
            def Y(v):
                return GRID - v if fy else v
            xs = sorted([X(3), X(5)]); xl = sorted([X(3), X(10)])
            yv = sorted([Y(3), Y(10)]); yh = sorted([Y(3), Y(5)])
            _capsule(d, xs[0], yv[0], xs[1], yv[1], SIG, s)   # vertical arm
            _capsule(d, xl[0], yh[0], xl[1], yh[1], SIG, s)   # horizontal arm

    # Entropy bar: encrypted red block, then the larger intact green block.
    d.rounded_rectangle([10 * s, 14 * s, 14 * s, 18 * s], radius=1 * s, fill=ENC)
    d.rounded_rectangle([15 * s, 14 * s, 23 * s, 18 * s], radius=1 * s, fill=SIG)
    return img


def main():
    master = render_master()
    sizes = [16, 24, 32, 48, 64, 128, 256]
    frames = [master.resize((n, n), Image.LANCZOS) for n in sizes]

    frames[-1].save("assets/scancrypt.ico", format="ICO",
                    append_images=frames[:-1], sizes=[(n, n) for n in sizes])
    frames[-1].save("assets/scancrypt.png")
    master.resize((48, 48), Image.LANCZOS).save("docs/favicon.png")
    # macOS app icon (PyInstaller --icon on macOS wants a .icns).
    master.resize((1024, 1024), Image.LANCZOS).save("assets/scancrypt.icns")
    print("wrote assets/scancrypt.ico, assets/scancrypt.icns, assets/scancrypt.png, docs/favicon.png")


if __name__ == "__main__":
    main()
