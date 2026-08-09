# Keynoxis branding

The visual system is built from one canonical source:
[`keynoxis-avatar-dark.svg`](keynoxis-avatar-dark.svg).

## Assets

| File | Use |
| --- | --- |
| `keynoxis-avatar-dark.svg` | Master artwork and application icon source |
| `keynoxis-avatar-dark.png` | Raster preview for services that do not accept SVG |
| `keynoxis-mark.svg` | Standalone mark on transparent backgrounds |
| `keynoxis-wordmark.svg` | Horizontal lockup for light backgrounds |
| `keynoxis-wordmark-dark.svg` | Horizontal lockup for dark backgrounds |

The compact lock-and-K artwork in `src-tauri/icons/tray-icon-template.svg` is a
macOS template icon derived from the same monogram. Its raster export must stay
monochrome with a transparent background so the menu bar can tint it correctly.

The files under `src-tauri/icons/` are generated application assets. Do not edit
them individually; regenerate the complete platform set from the master artwork:

```sh
npm ci
npx tauri icon branding/keynoxis-avatar-dark.svg
```

## Palette

| Role | Color |
| --- | --- |
| Carbon | `#090B0D` |
| Core | `#151A1F` |
| Steel highlight | `#F2F5F7` |
| Steel | `#B9C3CC` |
| Steel shadow | `#7D8994` |
| Trust/status | `#90C99B` |

Keep the mark unmodified, preserve its square proportions, and do not recolor it
with the retired lime-and-forest palette.
