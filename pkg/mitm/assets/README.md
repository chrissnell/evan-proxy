# `pancho.jpg`

The image embedded in the block page (`blockpage.go`).

The committed file is a **placeholder** — a paw print in the page's palette, not
a photo. Replace it with the real head-tilt photo of Pancho: ~800px wide, JPEG
quality 75 (keeps it in the 60–80KB range). It is inlined into the page as a
`data:` URI, so the block page is a single response with no subresource
requests; anything much larger makes that response needlessly fat.

No code change is needed after swapping the file — `go:embed` picks it up at
build time.
