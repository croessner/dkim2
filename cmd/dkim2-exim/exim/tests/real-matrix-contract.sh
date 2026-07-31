#!/usr/bin/env bash
# Defines the exact real-Exim qualification rows, cases, and proof classes.

# real_matrix_rows emits the only supported qualification row names.
real_matrix_rows() {
  printf '%s\n' \
    upstream-4.99.5 \
    debian-4.98.2-1+deb13u3 \
    debian-4.98.2-1+deb13u4 \
    ubuntu-4.99.1-1ubuntu1.3 \
    ubuntu-4.99.1-1ubuntu1.4
}

# real_matrix_cases emits the exact logical cases for one closed category.
real_matrix_cases() {
  case "${1:-}" in
    smtp)
      printf '%s\n' \
        build-mismatch exact-build interactive-smtp local-submission \
        smtp-timeout smtp-crash local-timeout local-crash c-to-go-unavailable \
        daemon-unavailable-closed daemon-unavailable-reached-fail-open \
        lf crlf duplicate-folded binary-body smtputf8-rfc6532 \
        forged-authentication-results incoming-outgoing-envelope \
        missing-evidence expired-evidence tampered-evidence
      ;;
    local-submission)
      printf '%s\n' non-smtp-drop nonzero-exit
      ;;
    transport-filter)
      printf '%s\n' \
        sign revise return-path empty-bounce divergent-sender \
        empty-smtp-return-path sender-address-rejected max-rcpt-one bcc-safe \
        pipe-addresses negative-size-addition zero-size-rejected \
        positive-size-rejected daemon-unavailable daemon-timeout \
        daemon-malformed daemon-overflow nonascii-envelope nonzero-deferral \
        partial-output
      ;;
    *)
      return 1
      ;;
  esac
}

# real_matrix_components emits the exact per-case live artifact components.
real_matrix_components() {
  printf '%s\n' exim adapter dkim2d fault readback
}

# real_matrix_expected_contract returns proof and mandatory component assertions.
real_matrix_expected_contract() {
  case "${1:-}:${2:-}" in
    smtp:build-mismatch)
      printf '%s\n' \
        'real-exim-local-scan passed passed not-reached injected passed'
      ;;
    smtp:exact-build)
      printf '%s\n' \
        'real-exim-dkim2d-local-scan passed passed passed not-applicable passed'
      ;;
    smtp:interactive-smtp | smtp:local-submission | smtp:lf | smtp:crlf | \
      smtp:duplicate-folded | smtp:binary-body | smtp:smtputf8-rfc6532 | \
      smtp:forged-authentication-results)
      printf '%s\n' \
        'real-exim-dkim2d-local-scan passed passed passed not-applicable passed'
      ;;
    smtp:incoming-outgoing-envelope)
      printf '%s\n' \
        'real-exim-dkim2d-roundtrip passed passed passed not-applicable passed'
      ;;
      smtp:smtp-timeout | smtp:smtp-crash | smtp:local-timeout | \
      smtp:local-crash | smtp:c-to-go-unavailable | \
      smtp:daemon-unavailable-closed)
      printf '%s\n' \
        'real-exim-fault-injection passed passed not-reached injected passed'
      ;;
    smtp:missing-evidence | smtp:expired-evidence | smtp:tampered-evidence)
      printf '%s\n' \
        'real-exim-fault-injection passed passed not-reached injected passed'
      ;;
    smtp:daemon-unavailable-reached-fail-open)
      printf '%s\n' \
        'real-exim-fault-injection passed passed reached injected passed'
      ;;
    local-submission:non-smtp-drop | local-submission:nonzero-exit)
      printf '%s\n' \
        'real-exim-local-scan passed passed not-reached injected passed'
      ;;
    transport-filter:sign | transport-filter:revise | \
      transport-filter:return-path | \
      transport-filter:empty-bounce | transport-filter:divergent-sender | \
      transport-filter:bcc-safe)
      printf '%s\n' \
        'real-exim-dkim2d-transport passed passed passed not-applicable passed'
      ;;
    transport-filter:nonascii-envelope)
      printf '%s\n' \
        'real-exim-transport passed passed not-reached not-applicable passed'
      ;;
    transport-filter:empty-smtp-return-path | \
      transport-filter:sender-address-rejected | \
      transport-filter:max-rcpt-one | transport-filter:pipe-addresses | \
      transport-filter:negative-size-addition | \
      transport-filter:zero-size-rejected | \
      transport-filter:positive-size-rejected)
      printf '%s\n' \
        'deployment-readback passed passed not-applicable not-applicable passed'
      ;;
    transport-filter:daemon-unavailable | transport-filter:daemon-timeout | \
      transport-filter:daemon-malformed | transport-filter:daemon-overflow)
      printf '%s\n' \
        'real-exim-fault-injection passed passed reached injected passed'
      ;;
    transport-filter:nonzero-deferral | transport-filter:partial-output)
      printf '%s\n' \
        'real-exim-fault-injection passed passed passed injected passed'
      ;;
    *)
      return 1
      ;;
  esac
}

# real_matrix_expected_proof returns the sole proof class allowed for one case.
real_matrix_expected_proof() {
  local contract
  contract=$(real_matrix_expected_contract "$@") || return 1
  printf '%s\n' "${contract%% *}"
}

# real_matrix_expected_observation returns one exact sanitized live outcome.
real_matrix_expected_observation() {
  local category=${1:-} logical_case=${2:-} component=${3:-}
  local contract dkim2d_state fault_state readback_state
  contract=$(real_matrix_expected_contract "$category" "$logical_case") ||
    return 1
  read -r _ _ _ dkim2d_state fault_state \
    readback_state <<<"$contract"
  case "$component" in
    exim)
      case "$category:$logical_case" in
        smtp:smtp-timeout | smtp:smtp-crash)
          printf '%s\n' 'smtp-final-421,deliveries-0'
          ;;
        smtp:build-mismatch | smtp:local-timeout | smtp:local-crash | \
          smtp:c-to-go-unavailable | smtp:daemon-unavailable-closed)
          printf '%s\n' 'smtp-final-451,deliveries-0'
          ;;
        smtp:exact-build)
          printf '%s\n' 'smtp-final-250,deliveries-1,authentication-results-1'
          ;;
        smtp:local-submission)
          printf '%s\n' 'submission-exit-0,deliveries-1'
          ;;
        smtp:daemon-unavailable-reached-fail-open)
          printf '%s\n' 'smtp-final-250,deliveries-1,fail-open-1'
          ;;
        smtp:lf)
          return 1
          ;;
        smtp:crlf)
          return 1
          ;;
        smtp:duplicate-folded)
          return 1
          ;;
        smtp:binary-body)
          return 1
          ;;
        smtp:smtputf8-rfc6532)
          return 1
          ;;
        smtp:missing-evidence | smtp:expired-evidence | smtp:tampered-evidence)
          printf '%s\n' 'smtp-final-250,transport-exit-75,deliveries-0'
          ;;
        smtp:*)
          printf '%s\n' 'smtp-final-250,deliveries-1'
          ;;
        local-submission:non-smtp-drop)
          printf '%s\n' 'submission-complete,message-dropped-1,deliveries-0'
          ;;
        local-submission:nonzero-exit)
          printf '%s\n' 'submission-exit-nonzero,deliveries-0'
          ;;
        transport-filter:sign | transport-filter:revise | \
          transport-filter:bcc-safe)
          return 1
          ;;
        transport-filter:return-path | transport-filter:empty-bounce | \
          transport-filter:divergent-sender)
          printf '%s\n' 'transport-exit-0,deliveries-1'
          ;;
        transport-filter:nonascii-envelope | \
          transport-filter:daemon-unavailable | \
          transport-filter:daemon-timeout | \
          transport-filter:daemon-malformed | \
          transport-filter:daemon-overflow | \
          transport-filter:nonzero-deferral | \
          transport-filter:partial-output)
          printf '%s\n' 'transport-exit-75,deliveries-0'
          ;;
        transport-filter:*)
          printf '%s\n' 'deployment-readback-complete,runtime-not-run'
          ;;
        *)
          return 1
          ;;
      esac
      ;;
    adapter)
      case "$category:$logical_case" in
        smtp:build-mismatch)
          printf '%s\n' 'operation-process,contract-rejected,daemon-calls-0'
          ;;
        smtp:exact-build)
          printf '%s\n' 'operation-process,result-pass,actions-1'
          ;;
        smtp:daemon-unavailable-reached-fail-open)
          printf '%s\n' 'operation-process,result-pass,fail-open-warning-1'
          ;;
        smtp:smtp-timeout | smtp:smtp-crash | smtp:local-timeout | \
          smtp:local-crash | smtp:c-to-go-unavailable | \
          smtp:daemon-unavailable-closed)
          printf '%s\n' 'operation-process,result-tempfail,mail-output-0'
          ;;
        smtp:missing-evidence | smtp:expired-evidence | smtp:tampered-evidence)
          printf '%s\n' 'operation-revise,result-defer,mail-output-0'
          ;;
        smtp:incoming-outgoing-envelope)
          return 1
          ;;
        smtp:forged-authentication-results)
          return 1
          ;;
        smtp:*)
          printf '%s\n' 'operation-process,result-pass,actions-admitted'
          ;;
        local-submission:*)
          printf '%s\n' 'operation-process,result-drop,mail-output-0'
          ;;
        transport-filter:sign)
          return 1
          ;;
        transport-filter:revise)
          return 1
          ;;
        transport-filter:bcc-safe)
          return 1
          ;;
        transport-filter:return-path | \
          transport-filter:empty-bounce | transport-filter:divergent-sender)
          printf '%s\n' 'operation-sign,result-pass,generated-fields-2'
          ;;
        transport-filter:nonascii-envelope)
          printf '%s\n' 'operation-rejected-before-authority,mail-output-0'
          ;;
        transport-filter:daemon-unavailable | \
          transport-filter:daemon-timeout | \
          transport-filter:daemon-malformed | \
          transport-filter:daemon-overflow | \
          transport-filter:nonzero-deferral | \
          transport-filter:partial-output)
          printf '%s\n' 'operation-filter,result-defer,mail-output-not-accepted'
          ;;
        transport-filter:*)
          printf '%s\n' 'deployment-validator-pass,runtime-not-run'
          ;;
        *)
          return 1
          ;;
      esac
      ;;
    dkim2d)
      case "$dkim2d_state:$category:$logical_case" in
        passed:smtp:incoming-outgoing-envelope)
          return 1
          ;;
        passed:smtp:*)
          printf '%s\n' 'route-process,http-2xx-1,result-pass'
          ;;
        passed:transport-filter:sign)
          return 1
          ;;
        passed:transport-filter:revise)
          return 1
          ;;
        passed:transport-filter:bcc-safe)
          return 1
          ;;
        passed:transport-filter:*)
          case "$logical_case" in
            return-path | empty-bounce | divergent-sender | \
              nonzero-deferral | partial-output)
              printf '%s\n' 'route-sign,http-2xx-1,result-pass,fields-2'
              ;;
            *)
              printf '%s\n' 'route-revise,http-2xx-1,result-pass,fields-2'
              ;;
          esac
          ;;
        reached:smtp:*)
          printf '%s\n' 'route-process,calls-1,fault-observed'
          ;;
        reached:transport-filter:*)
          printf '%s\n' 'route-filter,calls-1,fault-observed'
          ;;
        not-reached:*)
          printf '%s\n' 'authority-calls-0'
          ;;
        not-applicable:*)
          printf '%s\n' 'authority-not-applicable'
          ;;
        *)
          return 1
          ;;
      esac
      ;;
    fault)
      case "$fault_state:$category:$logical_case" in
        not-applicable:*)
          printf '%s\n' 'fault-mode-none,outcome-not-applicable'
          ;;
        injected:smtp:build-mismatch)
          printf '%s\n' 'fault-build-id-mismatch,outcome-smtp-451'
          ;;
        injected:smtp:daemon-unavailable-reached-fail-open)
          printf '%s\n' 'fault-daemon-unavailable,outcome-fail-open-accepted'
          ;;
        injected:smtp:missing-evidence | injected:smtp:expired-evidence | \
          injected:smtp:tampered-evidence)
          printf '%s\n' "fault-$logical_case,outcome-transport-deferred"
          ;;
        injected:smtp:smtp-timeout | injected:smtp:smtp-crash)
          printf '%s\n' "fault-$logical_case,outcome-smtp-421"
          ;;
        injected:smtp:*)
          printf '%s\n' "fault-$logical_case,outcome-smtp-451"
          ;;
        injected:local-submission:*)
          printf '%s\n' "fault-$logical_case,outcome-local-drop"
          ;;
        injected:transport-filter:partial-output)
          printf '%s\n' 'fault-partial-output,outcome-transport-deferred'
          ;;
        injected:transport-filter:*)
          printf '%s\n' "fault-$logical_case,outcome-transport-deferred"
          ;;
        *)
          return 1
          ;;
      esac
      ;;
    readback)
      case "$readback_state:$category:$logical_case" in
        passed:smtp:build-mismatch)
          printf '%s\n' 'version-match,build-id-mismatch,validator-pass'
          ;;
        passed:transport-filter:empty-smtp-return-path)
          printf '%s\n' 'smtp-return-path-unset,validator-pass'
          ;;
        passed:transport-filter:sender-address-rejected)
          printf '%s\n' 'sender-address-substitution-rejected,validator-pass'
          ;;
        passed:transport-filter:max-rcpt-one)
          printf '%s\n' 'max-rcpt-1,validator-pass'
          ;;
        passed:transport-filter:pipe-addresses)
          printf '%s\n' 'pipe-addresses-separate-argv,validator-pass'
          ;;
        passed:transport-filter:negative-size-addition)
          printf '%s\n' 'size-addition-negative,validator-pass'
          ;;
        passed:transport-filter:zero-size-rejected)
          printf '%s\n' 'size-addition-zero,rejected'
          ;;
        passed:transport-filter:positive-size-rejected)
          printf '%s\n' 'size-addition-positive,rejected'
          ;;
        passed:*)
          printf '%s\n' 'version-match,build-id-match,validator-pass'
          ;;
        *)
          return 1
          ;;
      esac
      ;;
    *)
      return 1
      ;;
  esac
}

# real_matrix_observation_has_live_values identifies digest-bearing observations.
real_matrix_observation_has_live_values() {
  case "${1:-}:${2:-}:${3:-}" in
    smtp:lf:exim | smtp:crlf:exim | smtp:duplicate-folded:exim | \
      smtp:binary-body:exim | smtp:smtputf8-rfc6532:exim | \
      smtp:forged-authentication-results:adapter | \
      smtp:incoming-outgoing-envelope:adapter | \
      smtp:incoming-outgoing-envelope:dkim2d | \
      transport-filter:sign:exim | transport-filter:revise:exim | \
      transport-filter:sign:adapter | transport-filter:sign:dkim2d | \
      transport-filter:revise:adapter | transport-filter:revise:dkim2d | \
      transport-filter:bcc-safe:exim | transport-filter:bcc-safe:adapter | \
      transport-filter:bcc-safe:dkim2d)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}
