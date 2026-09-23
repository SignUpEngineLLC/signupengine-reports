# SignUpEngine Reports

Client reports published with GitHub Pages at https://signupenginellc.github.io/signupengine-reports/

## ⚠ Everything here is public

This repo is public, and so is its Pages site. Only publish reports that are fine for anyone to read.
Never include personal data (names, emails, addresses, individual orders). `robots.txt` and the
`noindex` meta tags keep pages out of search engines, but anyone with a link can still open them.

## Layout

```
<client>/index.html               the client's report list (update it when you add a report)
<client>/<yyyy-mm>-<slug>/index.html   one report
```

To add a report: create `<client>/<yyyy-mm>-<slug>/index.html`, put
`<meta name="robots" content="noindex, nofollow">` in its `<head>`, add a link to it in
`<client>/index.html`, then push to `main`. Pages redeploys within a minute or two.

## Clients

- `nyjtl/`: NYJTL
