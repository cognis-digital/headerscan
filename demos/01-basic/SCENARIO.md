# Demo 01 — basic header grading

## Scenario

You captured the HTTP response from a web app you are **authorized to test**
(your own staging environment). You saved the raw response — status line,
headers, and body — to `response.txt`. You want a quick A-F report card on the
security-header posture before writing it up, the way securityheaders.com
would score it.

This response is realistic but imperfect:

- `server` and `x-powered-by` leak the stack (nginx + Express).
- `strict-transport-security` has a tiny `max-age=86400` (1 day) and no
  `includeSubDomains`.
- The CSP allows `'unsafe-inline'` for scripts (defeats most XSS protection).
- There is **no** `X-Content-Type-Options` or `Permissions-Policy`.
- `X-Frame-Options: SAMEORIGIN` is good.

## Input

[`response.txt`](./response.txt) — a raw HTTP/2 200 response with headers
and a short body.

## Run it

```sh
python -m headerscan grade demos/01-basic/response.txt
```

Machine-readable output for piping into other tooling:

```sh
python -m headerscan grade demos/01-basic/response.txt --format json
```

From stdin:

```sh
cat demos/01-basic/response.txt | python -m headerscan grade -
```

## What to notice

- The grade lands in the **C/D** range (not A): HSTS is weak, CSP is weak,
  two headers are missing, and two info-leak headers are present.
- The body after the blank line is ignored — only the header section is parsed.
- The process exits **1** because findings exist, so you can gate CI on header
  posture. A clean A/A+ response exits **0**; a read/usage error exits **2**.
