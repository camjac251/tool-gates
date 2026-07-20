# tool-gates brand mark

The gate mark is a compact torii silhouette: a bowed top rail, a straight decision rail, and two vertical posts. It represents a tool call crossing a policy boundary before execution.

## Canonical assets

- `favicon.svg` is the source of truth for the mark geometry.
- `favicon.png` is a 64 x 64 raster fallback generated from the SVG.
- The documentation wordmark renders the SVG as a CSS mask so the mark inherits the current theme accent.

Regenerate the raster fallback from the repository root with the same headless Chrome renderer used to verify the checked-in asset:

```bash
google-chrome-stable --headless --disable-gpu --hide-scrollbars --default-background-color=00000000 --force-device-scale-factor=1 --window-size=64,64 --screenshot="$PWD/docs/theme/favicon.png" "file://$PWD/docs/theme/favicon.svg"
```

## Geometry

- View box: `0 0 24 24`.
- Stroke width: `1.8` with round line caps.
- Clear space: keep at least one post width around the mark.
- Minimum UI size: 18 CSS pixels. Preferred navigation size: 22 CSS pixels.

## Color

- Interactive documentation: use `currentColor`, normally `--accent`.
- Standalone favicon: use `#59cbe8` on transparency.
- Do not introduce gradients, shadows, fills, or independent colors inside the mark.

## Usage

- Keep the proportions and path coordinates unchanged.
- Do not rotate, skew, crop, outline twice, or place the mark inside another container shape.
- Pair with the exact lowercase wordmark `tool-gates` when text is present.
