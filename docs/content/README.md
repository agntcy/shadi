# Documentation

[![Docs](https://github.com/agntcy/shadi/actions/workflows/docs-pages.yml/badge.svg?branch=main)](https://github.com/agntcy/shadi/actions/workflows/docs-pages.yml)
[![Docs Site](https://img.shields.io/badge/docs-agntcy.github.io%2Fshadi-blue)](https://agntcy.github.io/shadi)
[![codecov](https://codecov.io/gh/agntcy/shadi/branch/main/graph/badge.svg)](https://codecov.io/gh/agntcy/shadi)
[![CI](https://github.com/agntcy/shadi/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/agntcy/shadi/actions/workflows/ci.yml)

This folder holds the content for the SHADI documentation site built with
MkDocs; the site config lives in [`docs/mkdocs/`](../mkdocs/mkdocs.yml).

Run locally, from the repo root:

```bash
just docs-serve
```

Or directly with MkDocs:

```bash
cd docs/mkdocs && mkdocs serve --livereload --dirty
```

The dev server rebuilds changed pages automatically and refreshes the browser.
Keep it running while you edit files under `docs/content/`; you do not need
`just docs-build` for day-to-day writing.
