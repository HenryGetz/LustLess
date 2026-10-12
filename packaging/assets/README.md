# CE branding assets (extracted, authorized)

**Authorization:** `AUTHORIZATION.md` at the repo root records written
authorization from the Covenant Eyes head of software engineering (2026-10-11)
granting this project use of CE's logos/branding assets in the Linux build.
These files are CE's production artwork, extracted verbatim from the shipped
Windows binaries — not redraws.

## Provenance

Source binaries (all in `re/samples/`, hashes in `re/samples/MANIFEST.sha256`):

* **`VictoryShield.exe`** — CE Victory Shield 10.1.44 (version resource:
  `ProductName "Covenant Eyes"`, `FileDescription "Victory Shield"`,
  `FileVersion 10.1.44`, `Copyright 2026 Covenant Eyes`).
  Resource inventory (language 1033):
  * `RT_GROUP_ICON` **128** and **165** — identical 8-size color icon groups
    referencing `RT_ICON` ids **1–8** (16/24/32/48/64/96/128/256 px, 32-bit
    RGBA, PNG-compressed).
  * `RT_GROUP_ICON` **166** — monochrome (grayscale) variant referencing
    `RT_ICON` ids **17–24** (same size ladder). Not used.
  * `RT_ICON` ids **9–16** — byte-identical duplicates of 1–8.
  * `RT_ICON` 192 / 226 are `RT_BITMAP`s; ids 30994/30996 are tiny toolbar
    bitmaps — not branding.
  * `PNG` resources **228 / 229** (501×92) — full "Covenant Eyes" wordmark
    lockups, dark- and light-text variants. **230** (88×94) — the shield
    mark alone (blue shield + white glyph). **231 / 232** (250×186) —
    horizontal lockups (mark + wordmark), dark/light variants. Not used
    beyond the mark.
* **`UWPApp.dll`** — icon resources are **byte-identical** to
  `VictoryShield.exe` `RT_ICON` 1–8 (verified with `cmp`); no distinct
  assets. Not used as a source.
* **`vs-config.exe`** — same again (`cmp`-identical 256 px icon). Not used.

## Files

| file | source | notes |
|---|---|---|
| `lustless.ico` | `VictoryShield.exe` `RT_GROUP_ICON` 128 (icons 1–8) | multi-size Windows icon, 16–256 px, PNG-compressed entries — the extracted group reassembled as an `.ico` |
| `lustless-16.png` | `RT_ICON` 1 (16×16) | exported tray/messaging sizes |
| `lustless-24.png` | `RT_ICON` 2 (24×24) | |
| `lustless-32.png` | `RT_ICON` 3 (32×32) | embedded in the agent tray (`indicator.rs`, `include_bytes!`) |
| `lustless-48.png` | `RT_ICON` 4 (48×48) | |
| `lustless-256.png` | `RT_ICON` 8 (256×256) | staged as `/usr/share/pixmaps/lustless.png` by `build-deb.sh` |
| `lustless-mark.png` | `PNG` resource 230 (88×94) | shield mark; embedded as a data URI in the dashboard header (`dashboard.rs`) |

## Extraction

Re-extract with `wrestool` (from `icoutils`):

```sh
wrestool -x --raw --type=icon --name=<1..8> --language=1033 \
    -o lustless-<N>.png re/samples/VictoryShield.exe
wrestool -x --type=14 --name=128 --language=1033 \
    -o lustless.ico re/samples/VictoryShield.exe   # group → assembled .ico
wrestool -x --raw --type=PNG --name=230 --language=1033 \
    -o lustless-mark.png re/samples/VictoryShield.exe
```

The PNG sizes above are the native resource bytes (the CE icon set stores
PNG-compressed icon entries), so no re-encoding/scaling was performed.
