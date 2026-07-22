# embedded-js-dom-xss

## Description

Add production Sighthound checks for DOM XSS in JavaScript embedded inside HTML templates. Cover at least untrusted browser-controlled or remote values reaching `document.write` and `innerHTML`, including the two held-out benchmark patterns missed by Sighthound simple analysis. Preserve existing scanner architecture, output provenance, performance expectations, and safe-case behavior. Add focused fixtures and regression tests, then validate and commit the implementation.
