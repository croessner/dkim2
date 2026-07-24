package valkey

import (
	"bytes"
	"context"
	"sort"
	"time"

	dkim2 "github.com/croessner/dkim2"
)

const (
	auditCommandTimeout = 2 * time.Second
	auditGlobalTimeout  = 30 * time.Second
	auditCommandCount   = 11
	auditUnknownToken   = "unknown"

	auditPersistenceRDB    = "rdb"
	auditPersistenceAOF    = "aof"
	auditPersistenceRDBAOF = "rdb_aof"

	auditAppendFsyncInactive = "inactive"
	auditAppendFsyncAlways   = "always"
	auditAppendFsyncEverySec = "everysec"

	serverKindNOAUTH      = "NOAUTH"
	serverKindWRONGPASS   = "WRONGPASS"
	serverKindNOPERM      = "NOPERM"
	serverKindERR         = "ERR"
	serverKindREADONLY    = "READONLY"
	serverKindMASTERDOWN  = "MASTERDOWN"
	serverKindCLUSTERDOWN = "CLUSTERDOWN"
	serverKindLOADING     = "LOADING"
	serverKindMISCONF     = "MISCONF"
	serverKindNOREPLICAS  = "NOREPLICAS"
)

// auditCommand identifies one command in the closed privileged inventory.
type auditCommand uint8

const (
	auditCommandAuth auditCommand = iota + 1
	auditCommandRole
	auditCommandConfigGet
	auditCommandInfoMemory
	auditCommandInfoPersistence
	auditCommandInfoReplication
	auditCommandInfoCluster
	auditCommandACLGetUser
	auditCommandACLDryRunPing
	auditCommandACLDryRunInNamespaceSet
	auditCommandACLDryRunOutOfNamespaceSet
)

// String returns one bounded command identifier without arguments.
func (c auditCommand) String() string {
	switch c {
	case auditCommandAuth:
		return "auth"
	case auditCommandRole:
		return "role"
	case auditCommandConfigGet:
		return "config_get"
	case auditCommandInfoMemory:
		return "info_memory"
	case auditCommandInfoPersistence:
		return "info_persistence"
	case auditCommandInfoReplication:
		return "info_replication"
	case auditCommandInfoCluster:
		return "info_cluster"
	case auditCommandACLGetUser:
		return "acl_getuser"
	case auditCommandACLDryRunPing:
		return "acl_dryrun_ping"
	case auditCommandACLDryRunInNamespaceSet:
		return "acl_dryrun_namespace_set"
	case auditCommandACLDryRunOutOfNamespaceSet:
		return "acl_dryrun_outside_set"
	default:
		return auditUnknownToken
	}
}

// auditRequest carries one closed command plus its command-specific protected arguments.
type auditRequest struct {
	command   auditCommand
	arguments [][]byte
}

// auditWire performs one sequential bounded exchange and owns its cleanup.
type auditWire interface {
	roundTrip(context.Context, auditRequest) (resp2Value, error)
	Close() error
}

// auditCredentials owns one ephemeral credential projection.
type auditCredentials struct {
	username string
	password []byte
}

// clear erases the auditor password clone after its one audit.
func (c *auditCredentials) clear() {
	if c == nil {
		return
	}
	clear(c.password)
	c.password = nil
}

// auditPhase selects the closed mismatch mapping for construction or revalidation.
type auditPhase uint8

const (
	auditPhaseConstruction auditPhase = iota + 1
	auditPhaseRuntime
)

// securityAuditPolicy contains only immutable already-validated policy expectations.
type securityAuditPolicy struct {
	applicationUsername      string
	persistenceMode          string
	appendFsyncPolicy        string
	saveSchedule             string
	minReplicasToWrite       uint64
	minReplicasMaxLagSeconds uint64
}

// auditSnapshot retains only bounded non-secret facts needed across sequential probes.
type auditSnapshot struct {
	roleReplicas      uint64
	maxMemory         uint64
	appendOnly        bool
	connectedReplicas uint64
}

// auditValidation identifies accepted, policy-mismatch, and malformed reply state.
type auditValidation uint8

const (
	auditAccepted auditValidation = iota + 1
	auditPolicyMismatch
	auditMalformed
)

// runSecurityAudit executes and closes the exact sequential privileged proof.
func runSecurityAudit(
	ctx context.Context,
	wire auditWire,
	credentials auditCredentials,
	policy securityAuditPolicy,
	phase auditPhase,
) error {
	globalContext, cancelGlobal, err := newGlobalAuditContext(ctx)
	if err != nil {
		if !nilInterface(wire) {
			if closeErr := closeAuditWire(wire); closeErr != nil &&
				dkim2.ReplayErrorCodeOf(closeErr) ==
					dkim2.ReplayErrorInternalInvariant {
				return closeErr
			}
		}
		return err
	}
	defer cancelGlobal()
	return runSecurityAuditWithinDeadline(
		ctx,
		globalContext,
		wire,
		credentials,
		policy,
		phase,
		nil,
	)
}

// runSecurityAuditWithinDeadline executes under an already-started global budget.
func runSecurityAuditWithinDeadline(
	callerContext context.Context,
	globalContext context.Context,
	wire auditWire,
	credentials auditCredentials,
	policy securityAuditPolicy,
	phase auditPhase,
	onComplete func() error,
) (resultErr error) {
	ownedCredentials := auditCredentials{
		username: credentials.username,
		password: append([]byte(nil), credentials.password...),
	}
	defer ownedCredentials.clear()

	wirePresent := !nilInterface(wire)
	defer func() {
		panicked := recover() != nil
		closePanicked := false
		var closeErr error
		if wirePresent {
			func() {
				defer func() {
					if recover() != nil {
						closePanicked = true
					}
				}()
				closeErr = wire.Close()
			}()
		}
		switch {
		case closePanicked || panicked:
			resultErr = dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		case closeErr != nil && resultErr == nil:
			resultErr = dkim2.NewReplayError(dkim2.ReplayErrorUnavailable)
		}
	}()

	if err := preflightContext(callerContext); err != nil {
		return err
	}
	if err := preflightContext(globalContext); err != nil {
		if callerErr := preflightContext(callerContext); callerErr != nil {
			return callerErr
		}
		return dkim2.NewReplayError(dkim2.ReplayErrorUnavailable)
	}
	if !wirePresent || !validAuditInputs(ownedCredentials, policy, phase) {
		return dkim2.NewReplayError(dkim2.ReplayErrorMisconfigured)
	}

	snapshot := auditSnapshot{}
	requests := buildAuditRequests(ownedCredentials, policy.applicationUsername)
	defer clearAuditRequests(requests)
	if len(requests) != auditCommandCount {
		return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
	}

	for index := range requests {
		if index >= auditCommandCount {
			return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
		if err := preflightContext(callerContext); err != nil {
			return err
		}
		if globalContext.Err() != nil {
			return dkim2.NewReplayError(dkim2.ReplayErrorUnavailable)
		}
		commandContext, cancelCommand := context.WithTimeout(globalContext, auditCommandTimeout)
		value, err := wire.roundTrip(commandContext, requests[index])
		commandState := commandContext.Err()
		cancelCommand()
		callerErr := preflightContext(callerContext)
		validate := callerErr == nil && err == nil && commandState == nil && globalContext.Err() == nil
		validation := validateAndClearAuditReply(
			&value,
			validate,
			requests[index].command,
			policy,
			&snapshot,
		)
		if callerErr != nil {
			return callerErr
		}
		if err != nil || commandState != nil || globalContext.Err() != nil {
			return dkim2.NewReplayError(dkim2.ReplayErrorUnavailable)
		}
		switch validation {
		case auditAccepted:
		case auditPolicyMismatch:
			return auditMismatchError(phase)
		case auditMalformed:
			return dkim2.NewReplayError(dkim2.ReplayErrorInconsistent)
		default:
			return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
	}
	if snapshot.roleReplicas != snapshot.connectedReplicas {
		return auditMismatchError(phase)
	}
	if onComplete != nil {
		if err := onComplete(); err != nil {
			return err
		}
	}
	return nil
}

// validateAndClearAuditReply guarantees cleanup even when validation panics.
func validateAndClearAuditReply(
	value *resp2Value,
	validate bool,
	command auditCommand,
	policy securityAuditPolicy,
	snapshot *auditSnapshot,
) auditValidation {
	defer value.clear()
	if !validate {
		return auditAccepted
	}
	return validateAuditReply(command, *value, policy, snapshot)
}

// clearAuditRequests erases every ephemeral command argument clone.
func clearAuditRequests(requests []auditRequest) {
	for requestIndex := range requests {
		for argumentIndex := range requests[requestIndex].arguments {
			clear(requests[requestIndex].arguments[argumentIndex])
			requests[requestIndex].arguments[argumentIndex] = nil
		}
		requests[requestIndex].arguments = nil
	}
}

// validAuditInputs proves that only validated projections reach the runner.
func validAuditInputs(credentials auditCredentials, policy securityAuditPolicy, phase auditPhase) bool {
	if !validUsername(credentials.username) ||
		len(credentials.password) < 1 || len(credentials.password) > 1024 ||
		!validUsername(policy.applicationUsername) ||
		policy.minReplicasToWrite > 3 ||
		policy.minReplicasMaxLagSeconds < 1 || policy.minReplicasMaxLagSeconds > 3600 ||
		phase != auditPhaseConstruction && phase != auditPhaseRuntime {
		return false
	}
	switch policy.persistenceMode {
	case auditPersistenceRDB:
		return policy.appendFsyncPolicy == auditAppendFsyncInactive && validSaveSchedule(policy.saveSchedule)
	case auditPersistenceAOF:
		return (policy.appendFsyncPolicy == auditAppendFsyncAlways || policy.appendFsyncPolicy == auditAppendFsyncEverySec) &&
			policy.saveSchedule == ""
	case auditPersistenceRDBAOF:
		return (policy.appendFsyncPolicy == auditAppendFsyncAlways || policy.appendFsyncPolicy == auditAppendFsyncEverySec) &&
			validSaveSchedule(policy.saveSchedule)
	default:
		return false
	}
}

// buildAuditRequests constructs the only permitted command plan.
func buildAuditRequests(credentials auditCredentials, applicationUsername string) []auditRequest {
	return []auditRequest{
		{command: auditCommandAuth, arguments: [][]byte{[]byte(credentials.username), append([]byte(nil), credentials.password...)}},
		{command: auditCommandRole},
		{command: auditCommandConfigGet},
		{command: auditCommandInfoMemory},
		{command: auditCommandInfoPersistence},
		{command: auditCommandInfoReplication},
		{command: auditCommandInfoCluster},
		{command: auditCommandACLGetUser, arguments: [][]byte{[]byte(applicationUsername)}},
		{command: auditCommandACLDryRunPing, arguments: [][]byte{[]byte(applicationUsername)}},
		{command: auditCommandACLDryRunInNamespaceSet, arguments: [][]byte{[]byte(applicationUsername)}},
		{command: auditCommandACLDryRunOutOfNamespaceSet, arguments: [][]byte{[]byte(applicationUsername)}},
	}
}

// validateAuditReply validates one command-specific reply without formatting it.
func validateAuditReply(
	command auditCommand,
	value resp2Value,
	policy securityAuditPolicy,
	snapshot *auditSnapshot,
) auditValidation {
	if value.kind == resp2Error {
		return validateAuditError(command, value.bytes)
	}
	switch command {
	case auditCommandAuth:
		return validateExactOK(value)
	case auditCommandRole:
		return validateRole(value, snapshot)
	case auditCommandConfigGet:
		return validateConfig(value, policy, snapshot)
	case auditCommandInfoMemory:
		return validateMemoryInfo(value, snapshot)
	case auditCommandInfoPersistence:
		return validatePersistenceInfo(value, policy, snapshot)
	case auditCommandInfoReplication:
		return validateReplicationInfo(value, policy, snapshot)
	case auditCommandInfoCluster:
		return validateClusterInfo(value)
	case auditCommandACLGetUser:
		return validateACLGetUser(value)
	case auditCommandACLDryRunPing, auditCommandACLDryRunInNamespaceSet:
		return validateAllowedDryRun(value)
	case auditCommandACLDryRunOutOfNamespaceSet:
		return validateDeniedDryRun(value)
	default:
		return auditMalformed
	}
}

// validateAuditError maps one exact stable wire error token to a policy mismatch.
func validateAuditError(command auditCommand, value []byte) auditValidation {
	kind, valid := leadingAuditErrorKind(value)
	if !valid {
		return auditMalformed
	}
	switch kind {
	case auditErrorMapped:
		return auditPolicyMismatch
	case auditErrorBusy:
		if command != auditCommandAuth {
			return auditPolicyMismatch
		}
		return auditMalformed
	default:
		return auditMalformed
	}
}

// auditErrorKind identifies one closed classification without retaining reply bytes.
type auditErrorKind uint8

const (
	auditErrorUnknown auditErrorKind = iota
	auditErrorMapped
	auditErrorBusy
)

// leadingAuditErrorKind classifies only the bounded token without copying it.
func leadingAuditErrorKind(value []byte) (auditErrorKind, bool) {
	if len(value) == 0 {
		return auditErrorUnknown, false
	}
	end := bytes.IndexByte(value, ' ')
	if end < 0 {
		end = len(value)
	}
	if end < 1 || end > maximumKindBytes {
		return auditErrorUnknown, false
	}
	for index := range end {
		character := value[index]
		if index == 0 {
			if character < 'A' || character > 'Z' {
				return auditErrorUnknown, false
			}
			continue
		}
		if (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') &&
			character != '_' {
			return auditErrorUnknown, false
		}
	}
	token := value[:end]
	if bytes.Equal(token, []byte(serverKindBUSY)) {
		return auditErrorBusy, true
	}
	if oneOfBytes(
		token,
		serverKindNOAUTH, serverKindWRONGPASS, serverKindNOPERM, serverKindERR,
		serverKindREADONLY, serverKindMASTERDOWN, serverKindCLUSTERDOWN,
		serverKindLOADING, serverKindMISCONF, serverKindNOREPLICAS,
		serverKindMOVED, serverKindASK, serverKindTRYAGAIN, serverKindOOM,
	) {
		return auditErrorMapped, true
	}
	return auditErrorUnknown, true
}

// validateExactOK requires one exact simple-string success.
func validateExactOK(value resp2Value) auditValidation {
	if value.kind == resp2SimpleString && bytes.Equal(value.bytes, []byte("OK")) {
		return auditAccepted
	}
	return auditMalformed
}

// validateRole proves one official master shape or classifies supported drift shapes.
func validateRole(value resp2Value, snapshot *auditSnapshot) auditValidation {
	if value.kind != resp2Array || len(value.values) == 0 ||
		value.values[0].kind != resp2BulkString {
		return auditMalformed
	}
	switch {
	case bytes.Equal(value.values[0].bytes, []byte("master")):
		if len(value.values) != 3 || value.values[1].kind != resp2Integer ||
			value.values[1].integer < 0 || value.values[2].kind != resp2Array {
			return auditMalformed
		}
		healthMismatch := false
		for _, replica := range value.values[2].values {
			switch validateRoleReplica(replica) {
			case auditAccepted:
			case auditPolicyMismatch:
				healthMismatch = true
			default:
				return auditMalformed
			}
		}
		snapshot.roleReplicas = uint64(len(value.values[2].values))
		if snapshot.roleReplicas > 3 {
			healthMismatch = true
		}
		if healthMismatch {
			return auditPolicyMismatch
		}
		return auditAccepted
	case bytes.Equal(value.values[0].bytes, []byte("slave")):
		if len(value.values) != 5 ||
			value.values[1].kind != resp2BulkString ||
			value.values[2].kind != resp2Integer ||
			value.values[2].integer < 0 || value.values[2].integer > 65535 ||
			value.values[3].kind != resp2BulkString ||
			!oneOfBytes(
				value.values[3].bytes,
				"handshake", "none", "connect", "connecting", "sync", "connected", auditUnknownToken,
			) ||
			value.values[4].kind != resp2Integer || value.values[4].integer < -1 {
			return auditMalformed
		}
		return auditPolicyMismatch
	case bytes.Equal(value.values[0].bytes, []byte("sentinel")):
		if len(value.values) != 2 || value.values[1].kind != resp2Array {
			return auditMalformed
		}
		for _, name := range value.values[1].values {
			if name.kind != resp2BulkString {
				return auditMalformed
			}
		}
		return auditPolicyMismatch
	default:
		return auditMalformed
	}
}

// validateRoleReplica distinguishes tagged structure from strict health.
func validateRoleReplica(value resp2Value) auditValidation {
	if value.kind != resp2Array ||
		len(value.values) != 3 ||
		value.values[0].kind != resp2BulkString ||
		len(value.values[0].bytes) > 255 ||
		value.values[1].kind != resp2BulkString ||
		!canonicalSigned(value.values[1].bytes, 32) ||
		value.values[2].kind != resp2BulkString ||
		!canonicalSigned(value.values[2].bytes, 64) {
		return auditMalformed
	}
	port, _ := parseCanonicalSigned(value.values[1].bytes, 32)
	offset, _ := parseCanonicalSigned(value.values[2].bytes, 64)
	if !canonicalIP(value.values[0].bytes) || port < 1 || port > 65535 || offset < 0 {
		return auditPolicyMismatch
	}
	return auditAccepted
}

// validateConfig proves the exact ordered fourteen-scalar CONFIG reply.
func validateConfig(
	value resp2Value,
	policy securityAuditPolicy,
	snapshot *auditSnapshot,
) auditValidation {
	names := [...][]byte{
		[]byte("appendfsync"),
		[]byte("appendonly"),
		[]byte("maxmemory"),
		[]byte("maxmemory-policy"),
		[]byte("min-replicas-max-lag"),
		[]byte("min-replicas-to-write"),
		[]byte("save"),
	}
	if value.kind != resp2Array || len(value.values) != len(names)*2 {
		return auditMalformed
	}
	values := make([][]byte, len(names))
	for index, name := range names {
		key := value.values[index*2]
		candidate := value.values[index*2+1]
		if key.kind != resp2BulkString || !bytes.Equal(key.bytes, name) ||
			candidate.kind != resp2BulkString {
			return auditMalformed
		}
		values[index] = candidate.bytes
	}
	if !oneOfBytes(values[0], "always", "everysec", "no") ||
		!oneOfBytes(values[1], "yes", "no") ||
		!canonicalUint(values[2], 64) ||
		!validPolicyToken(values[3]) ||
		!canonicalUintBounded(values[4], 2_147_483_647) ||
		!canonicalUintBounded(values[5], 2_147_483_647) ||
		!validLiveConfigSave(values[6]) {
		return auditMalformed
	}
	maxMemory, _ := parseCanonicalUint(values[2], 64)
	maxLag, _ := parseCanonicalUint(values[4], 64)
	minReplicas, _ := parseCanonicalUint(values[5], 64)
	snapshot.maxMemory = maxMemory
	snapshot.appendOnly = bytes.Equal(values[1], []byte("yes"))
	if !bytes.Equal(values[3], []byte("noeviction")) ||
		maxMemory < 16*1024*1024 || maxMemory > 1024*1024*1024*1024 ||
		maxLag != policy.minReplicasMaxLagSeconds ||
		minReplicas != policy.minReplicasToWrite ||
		!bytes.Equal(values[6], []byte(policy.saveSchedule)) {
		return auditPolicyMismatch
	}
	expectedAppendOnly := policy.persistenceMode == auditPersistenceAOF ||
		policy.persistenceMode == auditPersistenceRDBAOF
	if snapshot.appendOnly != expectedAppendOnly {
		return auditPolicyMismatch
	}
	if expectedAppendOnly && !bytes.Equal(values[0], []byte(policy.appendFsyncPolicy)) {
		return auditPolicyMismatch
	}
	return auditAccepted
}

// validPolicyToken validates one bounded lowercase CONFIG policy token.
func validPolicyToken(value []byte) bool {
	if len(value) < 1 || len(value) > 32 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			character == '-' {
			continue
		}
		return false
	}
	return true
}

// validLiveConfigSave validates the tagged signed live CONFIG save grammar.
func validLiveConfigSave(value []byte) bool {
	if len(value) == 0 {
		return true
	}
	if len(value) > 512 || value[0] == ' ' || value[len(value)-1] == ' ' {
		return false
	}
	fields := bytes.Split(value, []byte{' '})
	if len(fields)%2 != 0 {
		return false
	}
	for index := 0; index < len(fields); index += 2 {
		if !canonicalUintBounded(fields[index], ^uint64(0)>>1) ||
			bytes.Equal(fields[index], []byte("0")) ||
			!canonicalSigned(fields[index+1], 32) {
			return false
		}
	}
	return true
}

// validateMemoryInfo proves finite noeviction headroom.
func validateMemoryInfo(value resp2Value, snapshot *auditSnapshot) auditValidation {
	fields, validation := parseInfo(value, "Memory", []string{"used_memory"})
	if validation != auditAccepted {
		return validation
	}
	usedBytes, _ := fields.get("used_memory")
	if !canonicalUint(usedBytes, 64) {
		return auditMalformed
	}
	used, _ := parseCanonicalUint(usedBytes, 64)
	if snapshot.maxMemory == 0 {
		return auditMalformed
	}
	if used > snapshot.maxMemory {
		return auditPolicyMismatch
	}
	required := snapshot.maxMemory / 10
	if snapshot.maxMemory%10 != 0 {
		required++
	}
	if required < 16*1024*1024 {
		required = 16 * 1024 * 1024
	}
	if snapshot.maxMemory-used < required {
		return auditPolicyMismatch
	}
	return auditAccepted
}

// validatePersistenceInfo proves current configured persistence health.
func validatePersistenceInfo(
	value resp2Value,
	policy securityAuditPolicy,
	snapshot *auditSnapshot,
) auditValidation {
	required := []string{
		"rdb_last_bgsave_status",
		"aof_enabled",
		"aof_last_write_status",
		"aof_last_bgrewrite_status",
	}
	fields, validation := parseInfo(value, "Persistence", required)
	if validation != auditAccepted {
		return validation
	}
	rdbStatus, _ := fields.get("rdb_last_bgsave_status")
	aofEnabled, _ := fields.get("aof_enabled")
	aofWriteStatus, _ := fields.get("aof_last_write_status")
	aofRewriteStatus, _ := fields.get("aof_last_bgrewrite_status")
	if !oneOfBytes(rdbStatus, "ok", "err") ||
		!oneOfBytes(aofEnabled, "0", "1") ||
		!oneOfBytes(aofWriteStatus, "ok", "err") ||
		!oneOfBytes(aofRewriteStatus, "ok", "err") {
		return auditMalformed
	}
	if bytes.Equal(aofEnabled, []byte("1")) != snapshot.appendOnly {
		return auditPolicyMismatch
	}
	if policy.persistenceMode == auditPersistenceRDB ||
		policy.persistenceMode == auditPersistenceRDBAOF {
		if !bytes.Equal(rdbStatus, []byte("ok")) {
			return auditPolicyMismatch
		}
	}
	if policy.persistenceMode == auditPersistenceAOF ||
		policy.persistenceMode == auditPersistenceRDBAOF {
		if !bytes.Equal(aofWriteStatus, []byte("ok")) ||
			!bytes.Equal(aofRewriteStatus, []byte("ok")) {
			return auditPolicyMismatch
		}
	}
	return auditAccepted
}

// validateReplicationInfo proves exact primary replica topology and current lag health.
func validateReplicationInfo(
	value resp2Value,
	policy securityAuditPolicy,
	snapshot *auditSnapshot,
) auditValidation {
	fields, validation := parseInfo(value, "Replication", []string{"role", "connected_slaves"})
	if validation != auditAccepted {
		return validation
	}
	role, _ := fields.get("role")
	connectedBytes, _ := fields.get("connected_slaves")
	if !canonicalUint(connectedBytes, 64) {
		return auditMalformed
	}
	connected, _ := parseCanonicalUint(connectedBytes, 64)
	if !bytes.Equal(role, []byte("master")) {
		if bytes.Equal(role, []byte("slave")) {
			return auditPolicyMismatch
		}
		return auditMalformed
	}
	type observedReplica struct {
		index uint64
		value []byte
	}
	observed := make([]observedReplica, 0, 4)
	for _, field := range fields {
		if isIndexedSlaveField(field.name) {
			index, valid := parseSlaveFieldIndex(field.name)
			if !valid {
				return auditMalformed
			}
			observed = append(observed, observedReplica{index: index, value: field.value})
		}
	}
	if uint64(len(observed)) != connected {
		return auditMalformed
	}
	sort.Slice(observed, func(left, right int) bool {
		return observed[left].index < observed[right].index
	})
	healthy := uint64(0)
	metadataMismatch := false
	for position, replica := range observed {
		if replica.index != uint64(position) {
			return auditMalformed
		}
		online, mismatch, valid := parseReplicaInfo(
			replica.value,
			policy.minReplicasMaxLagSeconds,
		)
		if !valid {
			return auditMalformed
		}
		if mismatch {
			metadataMismatch = true
		}
		if online {
			healthy++
		}
	}
	snapshot.connectedReplicas = connected
	if connected > 3 || metadataMismatch || healthy < policy.minReplicasToWrite {
		return auditPolicyMismatch
	}
	return auditAccepted
}

// validateClusterInfo proves one exact standalone topology field.
func validateClusterInfo(value resp2Value) auditValidation {
	fields, validation := parseInfo(value, "Cluster", []string{"cluster_enabled"})
	if validation != auditAccepted {
		return validation
	}
	clusterEnabled, _ := fields.get("cluster_enabled")
	switch {
	case bytes.Equal(clusterEnabled, []byte("0")):
		return auditAccepted
	case bytes.Equal(clusterEnabled, []byte("1")):
		return auditPolicyMismatch
	default:
		return auditMalformed
	}
}

// infoField aliases one bounded field inside the decoder-owned INFO payload.
type infoField struct {
	name  []byte
	value []byte
}

// infoFields is one duplicate-preserving in-place INFO projection.
type infoFields []infoField

// get returns one exact aliased field without copying payload data.
func (f infoFields) get(name string) ([]byte, bool) {
	for _, field := range f {
		if bytes.Equal(field.name, []byte(name)) {
			return field.value, true
		}
	}
	return nil, false
}

// parseInfo parses a duplicate-preserving INFO payload entirely in place.
func parseInfo(
	value resp2Value,
	requestedSection string,
	required []string,
) (infoFields, auditValidation) {
	if value.kind != resp2BulkString || validateRESP2InfoLineLengths(value.bytes) != nil {
		return nil, auditMalformed
	}
	fields := make(infoFields, 0, 16)
	payload := value.bytes
	var currentSection []byte
	requestedSections := 0
	for start := 0; start < len(payload); {
		relativeEnd := bytes.Index(payload[start:], []byte{'\r', '\n'})
		if relativeEnd < 0 {
			return nil, auditMalformed
		}
		end := start + relativeEnd
		line := payload[start:end]
		start = end + 2
		if len(line) == 0 {
			continue
		}
		if line[0] == '#' {
			if len(line) < 3 || line[1] != ' ' || !validInfoSectionName(line[2:]) {
				return nil, auditMalformed
			}
			currentSection = line[2:]
			if bytes.Equal(currentSection, []byte(requestedSection)) {
				requestedSections++
				if requestedSections > 1 {
					return nil, auditMalformed
				}
			}
			continue
		}
		if currentSection == nil {
			return nil, auditMalformed
		}
		colon := bytes.IndexByte(line, ':')
		if colon < 1 || !validInfoFieldName(line[:colon]) {
			return nil, auditMalformed
		}
		if !bytes.Equal(currentSection, []byte(requestedSection)) {
			continue
		}
		name := line[:colon]
		duplicate := false
		for _, field := range fields {
			if bytes.Equal(field.name, name) {
				duplicate = true
				break
			}
		}
		if duplicate {
			if requiredInfoField(name, required) || isIndexedSlaveField(name) {
				return nil, auditMalformed
			}
			continue
		}
		fields = append(fields, infoField{name: name, value: line[colon+1:]})
	}
	if requestedSections != 1 {
		return nil, auditMalformed
	}
	for index := range required {
		if _, present := fields.get(required[index]); !present {
			return nil, auditMalformed
		}
	}
	return fields, auditAccepted
}

// validInfoSectionName validates one exact bounded INFO section name.
func validInfoSectionName(value []byte) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

// requiredInfoField reports exact membership in one command-specific field set.
func requiredInfoField(name []byte, required []string) bool {
	for _, candidate := range required {
		if bytes.Equal(name, []byte(candidate)) {
			return true
		}
	}
	return false
}

// validInfoFieldName validates one bounded official INFO field name.
func validInfoFieldName(value []byte) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			character == '_' || character == '.' || character == '-' {
			continue
		}
		return false
	}
	return true
}

// parseReplicaInfo distinguishes tagged structure from strict healthy metadata.
func parseReplicaInfo(value []byte, maximumLag uint64) (bool, bool, bool) {
	var parts [6][]byte
	remaining := value
	for index := range parts {
		if index == len(parts)-1 {
			if bytes.IndexByte(remaining, ',') >= 0 {
				return false, false, false
			}
			parts[index] = remaining
			break
		}
		comma := bytes.IndexByte(remaining, ',')
		if comma < 0 {
			return false, false, false
		}
		parts[index] = remaining[:comma]
		remaining = remaining[comma+1:]
	}
	prefixes := [...][]byte{
		[]byte("ip="),
		[]byte("port="),
		[]byte("state="),
		[]byte("offset="),
		[]byte("lag="),
		[]byte("type="),
	}
	for index, prefix := range prefixes {
		if len(parts[index]) < len(prefix) || !bytes.Equal(parts[index][:len(prefix)], prefix) {
			return false, false, false
		}
		parts[index] = parts[index][len(prefix):]
	}
	if len(parts[0]) > 255 ||
		bytes.ContainsAny(parts[0], ",\r\n") ||
		!canonicalSigned(parts[1], 32) ||
		!validReplicaState(parts[2]) ||
		!canonicalSigned(parts[3], 64) ||
		!canonicalSigned(parts[4], 64) ||
		!oneOfBytes(parts[5], "rdb-channel", "main-channel", "replica") {
		return false, false, false
	}
	port, _ := parseCanonicalSigned(parts[1], 32)
	offset, _ := parseCanonicalSigned(parts[3], 64)
	lag, _ := parseCanonicalSigned(parts[4], 64)
	metadataHealthy := canonicalIP(parts[0]) &&
		port >= 1 && port <= 65535 &&
		offset >= 0 && lag >= 0
	online := metadataHealthy &&
		bytes.Equal(parts[2], []byte("online")) &&
		bytes.Equal(parts[5], []byte("replica")) &&
		uint64(lag) <= maximumLag
	return online, !metadataHealthy, true
}

// validReplicaState proves one bounded official-style replication state token.
func validReplicaState(value []byte) bool {
	return oneOfBytes(
		value,
		"wait_bgsave",
		"bg_transfer",
		"send_bulk",
		"online",
		"rdb_transmitted",
	)
}

// isIndexedSlaveField distinguishes exact slaveN records from unknown INFO fields.
func isIndexedSlaveField(value []byte) bool {
	prefix := []byte("slave")
	if len(value) <= len(prefix) || !bytes.Equal(value[:len(prefix)], prefix) {
		return false
	}
	for index := len(prefix); index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

// parseSlaveFieldIndex parses one exact contiguous INFO slave field suffix.
func parseSlaveFieldIndex(value []byte) (uint64, bool) {
	prefix := []byte("slave")
	if len(value) < len(prefix) || !bytes.Equal(value[:len(prefix)], prefix) {
		return 0, false
	}
	suffix := value[len(prefix):]
	if len(suffix) == 0 || !canonicalUint(suffix, 64) {
		return 0, false
	}
	index, _ := parseCanonicalUint(suffix, 64)
	return index, true
}

// validateACLGetUser proves the exact duplicate-preserving least-privilege shape.
func validateACLGetUser(value resp2Value) auditValidation {
	if value.kind == resp2NullBulk {
		return auditPolicyMismatch
	}
	if value.kind != resp2Array || len(value.values) != 14 {
		return auditMalformed
	}
	fields := aclUserFields{}
	for index := 0; index < len(value.values); index += 2 {
		name := value.values[index]
		field := value.values[index+1]
		if name.kind != resp2BulkString {
			return auditMalformed
		}
		slot := fields.slot(name.bytes)
		if slot == nil || slot.seen {
			return auditMalformed
		}
		slot.seen = true
		slot.value = field
	}
	if !fields.complete() ||
		fields.flags.value.kind != resp2Array ||
		fields.passwords.value.kind != resp2Array ||
		fields.commands.value.kind != resp2BulkString ||
		fields.keys.value.kind != resp2BulkString ||
		fields.channels.value.kind != resp2BulkString ||
		fields.databases.value.kind != resp2BulkString ||
		fields.selectors.value.kind != resp2Array {
		return auditMalformed
	}
	if !validACLFlags(fields.flags.value.values) ||
		!validPasswordHashes(fields.passwords.value.values) ||
		!validCommandDescriptor(fields.commands.value.bytes) ||
		!validKeyRules(fields.keys.value.bytes) ||
		!validChannelRules(fields.channels.value.bytes) ||
		!validDatabaseRule(fields.databases.value.bytes) ||
		!validSelectors(fields.selectors.value.values) {
		return auditMalformed
	}
	if !exactFlags(fields.flags.value.values) ||
		len(fields.passwords.value.values) != 1 ||
		!bytes.Equal(fields.commands.value.bytes, []byte("-@all +ping +set")) ||
		!bytes.Equal(fields.keys.value.bytes, []byte("~dkim2:replay:v1:*")) ||
		len(fields.channels.value.bytes) != 0 ||
		!bytes.Equal(fields.databases.value.bytes, []byte("db=0")) ||
		len(fields.selectors.value.values) != 0 {
		return auditPolicyMismatch
	}
	return auditAccepted
}

// aclFieldSlot retains one reply alias plus duplicate state without copying its name.
type aclFieldSlot struct {
	seen  bool
	value resp2Value
}

// aclUserFields owns the exact seven closed ACL GETUSER fields.
type aclUserFields struct {
	flags     aclFieldSlot
	passwords aclFieldSlot
	commands  aclFieldSlot
	keys      aclFieldSlot
	channels  aclFieldSlot
	databases aclFieldSlot
	selectors aclFieldSlot
}

// slot returns the exact field destination without retaining the reply name.
func (f *aclUserFields) slot(name []byte) *aclFieldSlot {
	switch {
	case bytes.Equal(name, []byte("flags")):
		return &f.flags
	case bytes.Equal(name, []byte("passwords")):
		return &f.passwords
	case bytes.Equal(name, []byte("commands")):
		return &f.commands
	case bytes.Equal(name, []byte("keys")):
		return &f.keys
	case bytes.Equal(name, []byte("channels")):
		return &f.channels
	case bytes.Equal(name, []byte("databases")):
		return &f.databases
	case bytes.Equal(name, []byte("selectors")):
		return &f.selectors
	default:
		return nil
	}
}

// complete reports whether every closed ACL field occurred exactly once.
func (f aclUserFields) complete() bool {
	return f.flags.seen && f.passwords.seen && f.commands.seen &&
		f.keys.seen && f.channels.seen && f.databases.seen && f.selectors.seen
}

// validACLFlags validates bounded official-style scalar flag tokens.
func validACLFlags(values []resp2Value) bool {
	if len(values) < 2 || len(values) > 3 {
		return false
	}
	stateCount := 0
	sanitizeCount := 0
	nopassCount := 0
	for _, value := range values {
		if value.kind != resp2BulkString {
			return false
		}
		switch {
		case oneOfBytes(value.bytes, "on", "off"):
			stateCount++
		case oneOfBytes(value.bytes, "sanitize-payload", "skip-sanitize-payload"):
			sanitizeCount++
		case bytes.Equal(value.bytes, []byte("nopass")):
			nopassCount++
		default:
			return false
		}
	}
	return stateCount == 1 && sanitizeCount == 1 && nopassCount <= 1
}

// exactFlags reports the exact canonical two-flag set.
func exactFlags(values []resp2Value) bool {
	if len(values) != 2 {
		return false
	}
	seenOn := false
	seenSanitize := false
	for _, value := range values {
		switch {
		case bytes.Equal(value.bytes, []byte("on")):
			if seenOn {
				return false
			}
			seenOn = true
		case bytes.Equal(value.bytes, []byte("sanitize-payload")):
			if seenSanitize {
				return false
			}
			seenSanitize = true
		default:
			return false
		}
	}
	return seenOn && seenSanitize
}

// validPasswordHashes validates all protected official SHA-256 hash scalars.
func validPasswordHashes(values []resp2Value) bool {
	for _, value := range values {
		if value.kind != resp2BulkString || len(value.bytes) != 64 {
			return false
		}
		for _, character := range value.bytes {
			if character < '0' || character > '9' && character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}

// validCommandDescriptor proves the tagged closed-prefix byte envelope.
func validCommandDescriptor(value []byte) bool {
	if len(value) < len("-@all") || len(value) > maximumAuditReplyBytes {
		return false
	}
	prefix := value[:len("-@all")]
	if !bytes.Equal(prefix, []byte("-@all")) && !bytes.Equal(prefix, []byte("+@all")) {
		return false
	}
	if len(value) > len(prefix) &&
		(value[len(prefix)] != ' ' || len(value) == len(prefix)+1) {
		return false
	}
	for _, character := range value {
		if character == 0 || character >= 'A' && character <= 'Z' {
			return false
		}
	}
	return true
}

// validKeyRules validates exact prefixes, C-whitespace exclusion, and unique suffixes.
func validKeyRules(value []byte) bool {
	return validGlobRules(value, true)
}

// validChannelRules validates exact channel tokens and the sole all-channel token.
func validChannelRules(value []byte) bool {
	return validGlobRules(value, false)
}

// validGlobRules validates one source-reachable root key or channel sequence.
func validGlobRules(value []byte, keyRules bool) bool {
	if len(value) == 0 {
		return true
	}
	tokens := bytes.Split(value, []byte{' '})
	seen := make([][]byte, 0, len(tokens))
	allChannels := false
	for _, token := range tokens {
		var suffix []byte
		if keyRules {
			switch {
			case len(token) >= 3 &&
				(bytes.Equal(token[:3], []byte("%R~")) || bytes.Equal(token[:3], []byte("%W~"))):
				suffix = token[3:]
			case len(token) >= 1 && token[0] == '~':
				suffix = token[1:]
			default:
				return false
			}
		} else {
			if len(token) < 1 || token[0] != '&' {
				return false
			}
			suffix = token[1:]
			if bytes.Equal(suffix, []byte("*")) {
				allChannels = true
			}
		}
		for _, character := range suffix {
			if character == 0 || isCWhitespace(character) {
				return false
			}
		}
		for _, prior := range seen {
			if bytes.Equal(prior, suffix) {
				return false
			}
		}
		seen = append(seen, suffix)
	}
	return keyRules || !allChannels || len(tokens) == 1
}

// isCWhitespace reports the exact locale-independent ACL exclusion set.
func isCWhitespace(value byte) bool {
	switch value {
	case '\t', '\n', '\v', '\f', '\r', ' ':
		return true
	default:
		return false
	}
}

// validDatabaseRule validates exact official canonical root database forms.
func validDatabaseRule(value []byte) bool {
	if len(value) == 0 || bytes.Equal(value, []byte("alldbs")) {
		return true
	}
	prefix := []byte("db=")
	if len(value) < len(prefix) || !bytes.Equal(value[:len(prefix)], prefix) {
		return false
	}
	identifiers := bytes.Split(value[len(prefix):], []byte{','})
	if len(identifiers) == 0 {
		return false
	}
	var previous uint64
	for index, identifier := range identifiers {
		if !canonicalUint(identifier, 64) {
			return false
		}
		number, _ := parseCanonicalUint(identifier, 64)
		if number > 2_147_483_647 {
			return false
		}
		if index > 0 && number <= previous {
			return false
		}
		previous = number
	}
	return true
}

// validSelectors accepts only exact official selector field/value arrays.
func validSelectors(values []resp2Value) bool {
	names := [...][]byte{
		[]byte("commands"),
		[]byte("keys"),
		[]byte("channels"),
		[]byte("databases"),
	}
	for _, selector := range values {
		if selector.kind != resp2Array || len(selector.values) != len(names)*2 {
			return false
		}
		for index, name := range names {
			key := selector.values[index*2]
			value := selector.values[index*2+1]
			if key.kind != resp2BulkString || !bytes.Equal(key.bytes, name) ||
				value.kind != resp2BulkString {
				return false
			}
		}
		if !validCommandDescriptor(selector.values[1].bytes) ||
			!validKeyRules(selector.values[3].bytes) ||
			!validChannelRules(selector.values[5].bytes) ||
			!validDatabaseRule(selector.values[7].bytes) {
			return false
		}
	}
	return true
}

// validateAllowedDryRun accepts exact OK or a nonempty official denial.
func validateAllowedDryRun(value resp2Value) auditValidation {
	switch value.kind {
	case resp2SimpleString:
		if bytes.Equal(value.bytes, []byte("OK")) {
			return auditAccepted
		}
		return auditMalformed
	case resp2BulkString:
		if len(value.bytes) > 0 {
			return auditPolicyMismatch
		}
		return auditMalformed
	default:
		return auditMalformed
	}
}

// validateDeniedDryRun requires one nonempty denial and rejects permission.
func validateDeniedDryRun(value resp2Value) auditValidation {
	switch value.kind {
	case resp2BulkString:
		if len(value.bytes) > 0 {
			return auditAccepted
		}
		return auditMalformed
	case resp2SimpleString:
		if bytes.Equal(value.bytes, []byte("OK")) {
			return auditPolicyMismatch
		}
		return auditMalformed
	default:
		return auditMalformed
	}
}

// auditMismatchError maps one authoritative policy mismatch by invocation phase.
func auditMismatchError(phase auditPhase) error {
	if phase == auditPhaseConstruction {
		return dkim2.NewReplayError(dkim2.ReplayErrorMisconfigured)
	}
	if phase == auditPhaseRuntime {
		return dkim2.NewReplayError(dkim2.ReplayErrorUnavailable)
	}
	return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
}

// canonicalUint validates one bounded canonical unsigned decimal.
func canonicalUint(value []byte, bits int) bool {
	_, valid := parseCanonicalUint(value, bits)
	return valid
}

// canonicalUintBounded validates canonical unsigned decimal under one exact maximum.
func canonicalUintBounded(value []byte, maximum uint64) bool {
	if !canonicalUint(value, 64) {
		return false
	}
	parsed, _ := parseCanonicalUint(value, 64)
	return parsed <= maximum
}

// canonicalSigned validates canonical signed decimal in one signed bit width.
func canonicalSigned(value []byte, bits int) bool {
	_, valid := parseCanonicalSigned(value, bits)
	return valid
}

// parseCanonicalUint parses canonical decimal without copying protected bytes.
func parseCanonicalUint(value []byte, bits int) (uint64, bool) {
	if len(value) == 0 || len(value) > 1 && value[0] == '0' ||
		bits < 1 || bits > 64 {
		return 0, false
	}
	maximum := ^uint64(0)
	if bits < 64 {
		maximum = 1<<bits - 1
	}
	parsed := uint64(0)
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, false
		}
		digit := uint64(character - '0')
		if parsed > (maximum-digit)/10 {
			return 0, false
		}
		parsed = parsed*10 + digit
	}
	return parsed, true
}

// parseCanonicalSigned parses canonical signed decimal without copying protected bytes.
func parseCanonicalSigned(value []byte, bits int) (int64, bool) {
	if len(value) == 0 || value[0] == '+' {
		return 0, false
	}
	if bits < 2 || bits > 64 {
		return 0, false
	}
	negative := value[0] == '-'
	digits := value
	if negative {
		if len(value) == 1 || value[1] == '0' {
			return 0, false
		}
		digits = value[1:]
	}
	if len(digits) > 1 && digits[0] == '0' {
		return 0, false
	}
	positiveMaximum := uint64(1)<<(bits-1) - 1
	magnitudeMaximum := positiveMaximum
	if negative {
		magnitudeMaximum++
	}
	magnitude := uint64(0)
	for _, character := range digits {
		if character < '0' || character > '9' {
			return 0, false
		}
		digit := uint64(character - '0')
		if magnitude > (magnitudeMaximum-digit)/10 {
			return 0, false
		}
		magnitude = magnitude*10 + digit
	}
	if !negative {
		return int64(magnitude), true
	}
	if magnitude == uint64(1)<<63 {
		return -int64(magnitude-1) - 1, true
	}
	return -int64(magnitude), true
}

// canonicalIP validates one exact canonical IP literal.
func canonicalIP(value []byte) bool {
	if bytes.IndexByte(value, ':') < 0 {
		_, valid := parseCanonicalIPv4(value)
		return valid
	}
	groups, valid := parseIPv6Groups(value)
	if !valid {
		return false
	}
	var renderBuffer [39]byte
	rendered := renderCanonicalIPv6(renderBuffer[:0], groups)
	equal := bytes.Equal(value, rendered)
	clear(renderBuffer[:])
	return equal
}

// oneOfBytes reports exact membership without exposing the compared value.
func oneOfBytes(value []byte, candidates ...string) bool {
	for _, candidate := range candidates {
		if bytes.Equal(value, []byte(candidate)) {
			return true
		}
	}
	return false
}

// parseCanonicalIPv4 parses one exact dotted-decimal address.
func parseCanonicalIPv4(value []byte) ([4]byte, bool) {
	var address [4]byte
	remaining := value
	for index := range address {
		var part []byte
		if index == len(address)-1 {
			if bytes.IndexByte(remaining, '.') >= 0 {
				return [4]byte{}, false
			}
			part = remaining
		} else {
			dot := bytes.IndexByte(remaining, '.')
			if dot < 0 {
				return [4]byte{}, false
			}
			part = remaining[:dot]
			remaining = remaining[dot+1:]
		}
		parsed, valid := parseCanonicalUint(part, 8)
		if !valid {
			return [4]byte{}, false
		}
		address[index] = byte(parsed)
	}
	return address, true
}

// parseIPv6Groups parses textual IPv6 into eight numeric groups without retaining text.
func parseIPv6Groups(value []byte) ([8]uint16, bool) {
	var compact [8]uint16
	count := 0
	compression := -1
	index := 0
	if len(value) < 2 {
		return [8]uint16{}, false
	}
	if value[0] == ':' {
		if value[1] != ':' {
			return [8]uint16{}, false
		}
		compression = 0
		index = 2
	}
	for index < len(value) {
		if count >= len(compact) {
			return [8]uint16{}, false
		}
		start := index
		for index < len(value) && value[index] != ':' {
			index++
		}
		segment := value[start:index]
		if len(segment) == 0 {
			return [8]uint16{}, false
		}
		if bytes.IndexByte(segment, '.') >= 0 {
			if index != len(value) || count > 6 {
				return [8]uint16{}, false
			}
			ipv4, valid := parseCanonicalIPv4(segment)
			if !valid {
				return [8]uint16{}, false
			}
			compact[count] = uint16(ipv4[0])<<8 | uint16(ipv4[1])
			compact[count+1] = uint16(ipv4[2])<<8 | uint16(ipv4[3])
			count += 2
			break
		}
		group, valid := parseHexGroup(segment)
		if !valid {
			return [8]uint16{}, false
		}
		compact[count] = group
		count++
		if index == len(value) {
			break
		}
		index++
		if index < len(value) && value[index] == ':' {
			if compression >= 0 {
				return [8]uint16{}, false
			}
			compression = count
			index++
		}
	}
	if compression < 0 {
		if count != len(compact) {
			return [8]uint16{}, false
		}
		return compact, true
	}
	missing := len(compact) - count
	if missing < 1 {
		return [8]uint16{}, false
	}
	var expanded [8]uint16
	copy(expanded[:compression], compact[:compression])
	copy(expanded[compression+missing:], compact[compression:count])
	return expanded, true
}

// parseHexGroup parses one bounded hexadecimal IPv6 group.
func parseHexGroup(value []byte) (uint16, bool) {
	if len(value) < 1 || len(value) > 4 {
		return 0, false
	}
	parsed := uint16(0)
	for _, character := range value {
		var digit byte
		switch {
		case character >= '0' && character <= '9':
			digit = character - '0'
		case character >= 'a' && character <= 'f':
			digit = character - 'a' + 10
		case character >= 'A' && character <= 'F':
			digit = character - 'A' + 10
		default:
			return 0, false
		}
		parsed = parsed<<4 | uint16(digit)
	}
	return parsed, true
}

// renderCanonicalIPv6 renders the exact lower-case first-longest-zero form into caller-owned memory.
func renderCanonicalIPv6(output []byte, groups [8]uint16) []byte {
	if groups[0] == 0 && groups[1] == 0 && groups[2] == 0 &&
		groups[3] == 0 && groups[4] == 0 && groups[5] == 0xffff {
		output = append(output, []byte("::ffff:")...)
		output = appendDecimal(output, uint64(groups[6]>>8))
		output = append(output, '.')
		output = appendDecimal(output, uint64(byte(groups[6])))
		output = append(output, '.')
		output = appendDecimal(output, uint64(groups[7]>>8))
		output = append(output, '.')
		return appendDecimal(output, uint64(byte(groups[7])))
	}
	bestStart := -1
	bestLength := 0
	for start := 0; start < len(groups); {
		if groups[start] != 0 {
			start++
			continue
		}
		end := start
		for end < len(groups) && groups[end] == 0 {
			end++
		}
		if end-start > bestLength && end-start >= 2 {
			bestStart = start
			bestLength = end - start
		}
		start = end
	}
	for index := 0; index < len(groups); {
		if index == bestStart {
			output = append(output, ':', ':')
			index += bestLength
			continue
		}
		if len(output) > 0 && output[len(output)-1] != ':' {
			output = append(output, ':')
		}
		output = appendHex(output, groups[index])
		index++
	}
	return output
}

// appendHex appends one lowercase hexadecimal group without leading zeroes.
func appendHex(output []byte, value uint16) []byte {
	const alphabet = "0123456789abcdef"
	started := false
	for shift := 12; shift >= 0; shift -= 4 {
		digit := byte(value >> shift & 0x0f)
		if digit != 0 || started || shift == 0 {
			output = append(output, alphabet[digit])
			started = true
		}
	}
	return output
}

// appendDecimal appends one bounded unsigned decimal without temporary strings.
func appendDecimal(output []byte, value uint64) []byte {
	var digits [20]byte
	index := len(digits)
	for {
		index--
		digits[index] = byte(value%10) + '0'
		value /= 10
		if value == 0 {
			break
		}
	}
	return append(output, digits[index:]...)
}
