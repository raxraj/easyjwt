# easyjwt

Static, browser-only JWT decoder, linter, verifier, and local test-token signer.

## Deploying

1. Push `main` to GitHub and set **Settings → Pages → Source** to **GitHub Actions**.
2. Add `easyjwt.sourcastic.dev` as the repository custom domain; the included `CNAME` is published with the site.
3. Point the domain DNS at GitHub Pages and wait for GitHub to provision HTTPS before relying on the service worker.

Run `npm test` to exercise the parser, linter, and timestamp helpers. The production site has no build step and no runtime dependencies.
