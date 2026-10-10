<div align="center">
  <img src="./banner.svg" alt="ssti-hunter" width="800">
</div>

# ssti-hunter

> Bounded, heuristic template-injection checks for systems you are authorized to test.

## Usage

Requires Python 3.9 or later; there are no third-party dependencies.

```bash
python ssti_hunter.py "https://example.test/render?name=value" --params name
python ssti_hunter.py "https://example.test/render" --method POST --params name --header "Authorization: Bearer TOKEN" --out report.json
```

The checker sends five small arithmetic probes per parameter, using syntaxes associated with Jinja2/Twig, Freemarker, Thymeleaf, ERB/JSP, and Smarty. It tests at most eight unique parameters (40 requests total), accepts only HTTP(S) URLs, uses a maximum 30-second socket-operation timeout, stores at most 16 KiB of each response (reading one extra byte to detect truncation), and does not follow redirects. Extra headers may be repeated with `--header`.

## Interpreting results and limitations

A matching arithmetic result is **heuristic evidence**, not confirmation of SSTI or identification of a specific template engine. Ordinary response content can coincidentally contain `49`; verify findings manually and only within the authorized scope. Failed HTTP requests, blocked redirects, and truncated responses are reported as failed or inconclusive probes rather than clean results. The command exits with status 2 if any probe fails or is inconclusive.

Only simple arithmetic expressions are sent. The checker does not attempt code execution, introspection, file or process access, evasion, or state-changing actions. A lack of evidence does not rule out SSTI: this small probe set supports only the listed syntaxes and may miss other engines, contexts, encodings, and application behaviors. The timeout applies to individual socket operations, not a strict end-to-end deadline.

Run the offline test suite with:

```bash
python -m unittest -v
```

## Disclaimer

> **Authorized security testing only.**

## Author

**Omar Khalid** — [omareldemery.com](https://omareldemery.com) | [@amooryx](https://github.com/amooryx)
