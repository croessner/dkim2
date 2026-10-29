package redisstore

import (
	"context"
	"errors"
	"strconv"
	"strings"

	dkim2 "github.com/croessner/dkim2"
	"github.com/redis/go-redis/v9"
)

const (
	maximumInfoBytes      = 64 * 1024
	minimumServerMajor    = 7
	noEvictionPolicyValue = "noeviction"
)

// StartupReason identifies one closed startup-check failure class.
type StartupReason uint8

const (
	// StartupUnavailable means a primary could not be reached or answered.
	StartupUnavailable StartupReason = iota + 1
	// StartupAuthentication means the server rejected the configured credentials.
	StartupAuthentication
	// StartupPermission means the ACL denies a command the provider requires.
	StartupPermission
	// StartupUnsupportedVersion means a primary reports a version below 7.0.0.
	StartupUnsupportedVersion
	// StartupEvictionPolicy means a primary does not use maxmemory-policy noeviction.
	StartupEvictionPolicy
	// StartupMalformedReply means a primary returned an INFO reply outside the bounded grammar.
	StartupMalformedReply
)

// StartupError is one content-free startup-check failure. Its text names
// the violated requirement and, for permission failures, the required ACL;
// it never contains addresses, usernames, or server-provided text.
type StartupError struct {
	reason     StartupReason
	violations int
}

// Reason returns the closed failure class.
func (e *StartupError) Reason() StartupReason {
	if e == nil {
		return 0
	}
	return e.reason
}

// Violations returns how many primaries violated the requirement.
func (e *StartupError) Violations() int {
	if e == nil {
		return 0
	}
	return e.violations
}

// Error returns one constant operator-facing explanation.
func (e *StartupError) Error() string {
	if e == nil {
		return "replay store startup check failed"
	}
	switch e.reason {
	case StartupUnavailable:
		return "replay store startup check failed: a primary is unreachable"
	case StartupAuthentication:
		return "replay store startup check failed: authentication rejected"
	case StartupPermission:
		return "replay store startup check failed: ACL denies a required command; " +
			"grant +hello +auth +ping +info +set +get +eval +evalsha (+select for database_number > 0, " +
			"+cluster|slots in cluster mode) on ~<key_prefix>dkim2:replay:*"
	case StartupUnsupportedVersion:
		return "replay store startup check failed: " + strconv.Itoa(e.violations) +
			" primary(s) report redis_version below 7.0.0"
	case StartupEvictionPolicy:
		return "replay store startup check failed: " + strconv.Itoa(e.violations) +
			" primary(s) do not use maxmemory-policy noeviction"
	case StartupMalformedReply:
		return "replay store startup check failed: malformed INFO reply"
	default:
		return "replay store startup check failed"
	}
}

// Unwrap exposes the stable replay taxonomy code for the failure class.
func (e *StartupError) Unwrap() error {
	if e != nil && e.reason == StartupUnavailable {
		return dkim2.NewReplayError(dkim2.ReplayErrorUnavailable)
	}
	return dkim2.NewReplayError(dkim2.ReplayErrorMisconfigured)
}

// startupFailure constructs one startup error.
func startupFailure(reason StartupReason, violations int) error {
	return &StartupError{reason: reason, violations: violations}
}

// classifyStartupError maps one raw check error into the closed startup classes.
func classifyStartupError(err error) error {
	var startup *StartupError
	if errors.As(err, &startup) {
		return err
	}
	var serverError redis.Error
	if errors.As(err, &serverError) && serverError != nil {
		kind, _ := leadingErrorKind(serverError.Error())
		switch kind {
		case "NOPERM":
			return startupFailure(StartupPermission, 0)
		case "NOAUTH", "WRONGPASS":
			return startupFailure(StartupAuthentication, 0)
		}
	}
	return startupFailure(StartupUnavailable, 0)
}

// runStartupChecks proves reachability on every primary, the version floor
// required by SET NX GET, and the noeviction policy unless disabled. Primaries
// are inspected sequentially and all violations of one requirement are
// counted before the check fails.
func runStartupChecks(ctx context.Context, client backend, requireNoEviction bool) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
	}()
	if err := preflightContext(ctx); err != nil {
		return err
	}
	if err := client.pingPrimaries(ctx); err != nil {
		if callerErr := preflightContext(ctx); callerErr != nil {
			return callerErr
		}
		return classifyStartupError(err)
	}
	versionViolations, policyViolations := 0, 0
	err := client.eachPrimary(ctx, func(ctx context.Context, primary infoClient) error {
		server, err := boundedInfo(ctx, primary, "server")
		if err != nil {
			return err
		}
		supported, ok := supportedServerVersion(server)
		if !ok {
			return startupFailure(StartupMalformedReply, 0)
		}
		if !supported {
			versionViolations++
		}
		if !requireNoEviction {
			return nil
		}
		memory, err := boundedInfo(ctx, primary, "memory")
		if err != nil {
			return err
		}
		policy, ok := infoField(memory, "maxmemory_policy")
		if !ok {
			return startupFailure(StartupMalformedReply, 0)
		}
		if policy != noEvictionPolicyValue {
			policyViolations++
		}
		return nil
	})
	if err != nil {
		if callerErr := preflightContext(ctx); callerErr != nil {
			return callerErr
		}
		return classifyStartupError(err)
	}
	if versionViolations != 0 {
		return startupFailure(StartupUnsupportedVersion, versionViolations)
	}
	if policyViolations != 0 {
		return startupFailure(StartupEvictionPolicy, policyViolations)
	}
	return nil
}

// boundedInfo reads one INFO section and rejects oversized replies.
func boundedInfo(ctx context.Context, primary infoClient, section string) (string, error) {
	reply, err := primary.Info(ctx, section).Result()
	if err != nil {
		return "", err
	}
	if len(reply) > maximumInfoBytes {
		return "", startupFailure(StartupMalformedReply, 0)
	}
	return reply, nil
}

// infoField returns the value of one exact "name:value" INFO line.
func infoField(info, name string) (string, bool) {
	for line := range strings.Lines(info) {
		line = strings.TrimRight(line, "\r\n")
		field, value, found := strings.Cut(line, ":")
		if found && field == name {
			return value, value != ""
		}
	}
	return "", false
}

// supportedServerVersion parses redis_version as major.minor.patch and
// reports whether it is at least 7.0.0. Valkey reports a compatible
// redis_version value.
func supportedServerVersion(info string) (supported bool, ok bool) {
	version, found := infoField(info, "redis_version")
	if !found {
		return false, false
	}
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false, false
	}
	numbers := [3]int{}
	for index, part := range parts {
		if part == "" || len(part) > 6 {
			return false, false
		}
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 || strconv.Itoa(number) != part {
			return false, false
		}
		numbers[index] = number
	}
	return numbers[0] >= minimumServerMajor, true
}

// Probe performs one bounded health probe: PING on every primary within the
// configured health timeout. A success clears the transient recovery fact
// and resets the failure count; failure_threshold consecutive failures set
// the transient fact, so readiness follows backend reachability without a
// restart. A contained backend panic or missing client is an internal
// invariant that publishes the sticky restart fact, matching write dispatch.
// Sticky restart facts are never cleared. Probe never performs a replay
// write.
func (s *Store) Probe(ctx context.Context) error {
	if err := preflightContext(ctx); err != nil {
		return err
	}
	if s == nil || s.storeCore == nil || s.gate == nil {
		return misconfigured()
	}
	finish, err := s.gate.admitLifecycle(ctx)
	if err != nil {
		return err
	}
	defer finish()
	probeContext, cancel := context.WithTimeout(ctx, s.healthTimeout)
	defer cancel()
	if invariant, err := s.ping(probeContext); err != nil {
		if invariant {
			s.publishFailure(recoveryRestart)
			return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
		if callerErr := preflightContext(ctx); callerErr != nil {
			return callerErr
		}
		if s.probeFailures.Add(1) >= s.healthThreshold {
			s.publishFailure(recoveryTransient)
		}
		return dkim2.NewReplayError(dkim2.ReplayErrorUnavailable)
	}
	s.probeFailures.Store(0)
	s.publishSuccess()
	return nil
}

// ping contains backend panics during one probe and reports them, like a
// missing client, as an internal invariant. Every other error stays raw so
// Probe can classify it as a reachability failure.
func (s *Store) ping(ctx context.Context) (invariant bool, resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
			invariant = true
		}
	}()
	if nilInterface(s.client) {
		return true, dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}
	return false, s.client.pingPrimaries(ctx)
}
