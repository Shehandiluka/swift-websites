# swiftlk.com + shehanx.com

Two static sites sharing one theme (`assets/theme.css`, `assets/site.js`). No build step.

## Edit
- `*/public/assets/site-config.js` — WealthFlow URL, SwiftClean download link, name, social links
- `shehanx.com/public/assets/me.jpg` — add a square photo (shows "S" until then)
- Text: `*/public/index.html`

## Deploy (Cloudflare Workers – static assets)
Both domains must be added to your Cloudflare account first.
```
cd swiftlk.com && npx wrangler login && npx wrangler deploy
cd ../shehanx.com && npx wrangler deploy
```
`wrangler.jsonc` attaches the apex + www custom domains automatically.

## Email
Cloudflare dashboard → each domain → Email → Email Routing:
`hello@swiftlk.com` and `hello@shehanx.com` → forward to your Gmail.

## SwiftClean download
Cloudflare static files max 25 MB, the installer is ~75 MB. Upload it to a GitHub Release
(or R2) and paste the link into `swiftcleanDownload` in both site-config.js files.

## Scroll animations
`assets/site.js` drives scroll-scrubbed scenes (plays forward/backward with the scroll):
- `data-pin="230" data-scene="hero"` — pinned hero, window rises and flattens (portfolio: 3 cards fan out)
- `data-pin="420" data-scene="story"` — product "chapters" with crossfading screenshots and bullet reveals
- `data-scrub` on any element — fades/slides with scroll (`left`, `right`, `zoom` variants)
- `data-count="55" data-suffix="+"` — number counts up
Visitors with "reduce motion" turned on get a normal static page.
