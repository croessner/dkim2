# DKIM2 Rspamd Policy End-to-End Harness

This fixture exercises the real generic Policy boundary without adding a DKIM2
handler to Nauthilus. It runs the current Nauthilus checkout with the native
`dkim2_reputation` decision fact provider, Rspamd 4.1.5 in Milter mode, Redis,
a deterministic `/v1/process` stub, and the local `miltertest-go` checkout.

Run it through `../run-policy-e2e.sh`. The runner creates all credentials and
certificates in a private temporary directory, uses an isolated Compose project,
and removes the stack and runtime material on exit.

By default, the runner discovers `nauthilus` and `miltertest-go` as sibling
checkouts next to the DKIM2 checkout:

```text
workspace/
  dkim2/
  nauthilus/
  miltertest-go/
```

For another neutral workspace layout, set `NAUTHILUS_REPO` and
`MILTERTEST_REPO` to the respective checkout paths. The runner validates both
locations before creating credentials or starting containers. Set
`POLICY_E2E_PREFLIGHT_ONLY=1` to validate checkout discovery without building
images or starting the stack.

The proof sequence is deliberately small:

1. The first scan calls the DKIM2 stub and Nauthilus, then Rspamd greylisting
   produces a temporary result and arms the retry cache.
2. The identical retry calls Nauthilus again but reuses the armed DKIM2 result,
   so the stub call count stays unchanged. The matured greylist permits the
   message and the late finalizer consumes the retry result.
3. A third identical scan reaches the DKIM2 stub again, proving that the
   terminal outcome consumed the cached authority-bearing result.

The SMTP peer is `203.0.113.25`. The native plugin permits only the configured
`203.0.113.0/24` contract for the target hop, so both successful generic Policy
decisions also prove that the exact CONNECT address reached the provider.
