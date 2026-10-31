# `pancho.jpg`

The photo embedded in the block page (`blockpage.go`).

800×800, JPEG quality 72, ~79KB. It is inlined into the page as a `data:` URI so
the block page is a single response with no subresource requests — a subresource
would leave the tunnel and need its own interception — which is why the size
matters more here than for an ordinary web image.

To replace it: crop square, scale to 800px, and keep the encode in the 60–80KB
range. No code change is needed — `go:embed` picks the file up at build time.
