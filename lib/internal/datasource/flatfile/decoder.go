package flatfile

import (
	"bytes"
	"encoding/base64"
	"io"
	"time"
	"unicode/utf8"

	"github.com/croessner/dkim2/internal/datasource"
	"github.com/croessner/dkim2/internal/datasource/memory"
	"github.com/croessner/dkim2/internal/niliface"
)

const formatVersion = "dkim2-datasource-v1"

const maxConsecutiveEmptyReads = 100

// documentDTO retains only private schema values pending transactional validation.
type documentDTO struct {
	handles  []handleDTO
	profiles []profileDTO
	policies []policyDTO
}

// handleDTO retains one declared opaque handle identifier.
type handleDTO struct {
	id string
}

// profileDTO retains one untrusted profile record.
type profileDTO struct {
	id, domain, status  string
	credentials         []credentialDTO
	notBefore, notAfter string
	notBeforeSet        bool
	notAfterSet         bool
}

// credentialDTO retains one untrusted public credential binding.
type credentialDTO struct {
	algorithm, selector, publicKeySPKI, handleID string
}

// policyDTO retains one untrusted administrative binding.
type policyDTO struct {
	tenantID, domain, use, profileID string
	status, rollout, compatibility   string
	feedbackRouteID                  string
	feedbackRouteIDSet               bool
}

// decoder applies the closed schema after strict structural scanning.
type decoder struct {
	scanner
	records int
}

// Decode validates one complete byte document into an immutable snapshot.
func Decode(
	generation uint64,
	document []byte,
	limits datasource.Limits,
) (*Snapshot, error) {
	if generation == 0 || limits.Validate() != nil {
		return nil, datasource.NewError(datasource.ErrorCodeInvalidRequest)
	}
	if len(document) > limits.MaxJSONFileBytes {
		return nil, limitExceeded()
	}
	if len(document) == 0 || !utf8.Valid(document) {
		return nil, malformed()
	}
	stringBytes, err := scanDocument(document, limits)
	if err != nil {
		return nil, err
	}
	target := decoder{scanner: scanner{data: document, limits: limits}}
	decoded, err := target.decodeDocument()
	if err != nil {
		return nil, err
	}
	provider, err := decoded.buildProvider(generation, limits)
	if err != nil {
		return nil, err
	}
	return newSnapshot(provider, generation, stringBytes, limits)
}

// DecodeReader reads at most one byte beyond the file cap before decoding.
func DecodeReader(
	generation uint64,
	reader io.Reader,
	limits datasource.Limits,
) (snapshot *Snapshot, resultErr error) {
	defer func() {
		if recover() != nil {
			snapshot = nil
			resultErr = datasource.NewError(datasource.ErrorCodeInternalInvariant)
		}
	}()
	if generation == 0 || limits.Validate() != nil || niliface.IsNil(reader) {
		return nil, datasource.NewError(datasource.ErrorCodeInvalidRequest)
	}
	return decodeBoundedReader(generation, reader, limits)
}

// decodeBoundedReader terminates hostile no-progress readers under a fixed buffer.
func decodeBoundedReader(
	generation uint64,
	reader io.Reader,
	limits datasource.Limits,
) (*Snapshot, error) {
	document := make([]byte, limits.MaxJSONFileBytes+1)
	total := 0
	noProgress := 0
	for total < len(document) {
		count, err := reader.Read(document[total:])
		if count < 0 || count > len(document)-total {
			return nil, datasource.NewError(datasource.ErrorCodeInternalInvariant)
		}
		total += count
		switch {
		case err != nil && err != io.EOF:
			return nil, datasource.NewError(datasource.ErrorCodeUnavailable)
		case err == io.EOF:
			if total > limits.MaxJSONFileBytes {
				return nil, limitExceeded()
			}
			return Decode(generation, document[:total], limits)
		case count == 0:
			noProgress++
			if noProgress >= maxConsecutiveEmptyReads {
				return nil, datasource.NewError(datasource.ErrorCodeUnavailable)
			}
		default:
			noProgress = 0
		}
	}
	return nil, limitExceeded()
}

// decodeDocument applies the exact four-member root schema.
func (d *decoder) decodeDocument() (documentDTO, error) {
	var output documentDTO
	var version string
	var versionSet, handlesSet, profilesSet, policiesSet bool
	err := d.readObject(func(name string) error {
		switch name {
		case "version":
			versionSet = true
			return d.readStringValue(&version)
		case "handles":
			handlesSet = true
			return d.readHandles(&output.handles)
		case "profiles":
			profilesSet = true
			return d.readProfiles(&output.profiles)
		case "policies":
			policiesSet = true
			return d.readPolicies(&output.policies)
		default:
			return malformed()
		}
	})
	if err != nil {
		return documentDTO{}, err
	}
	d.skipWhitespace()
	if d.position != len(d.data) || !versionSet || !handlesSet ||
		!profilesSet || !policiesSet || version != formatVersion {
		return documentDTO{}, malformed()
	}
	return output, nil
}

// readHandles decodes the bounded declared-handle array.
func (d *decoder) readHandles(output *[]handleDTO) error {
	return d.readArray(func() error {
		if err := d.takeRecord(len(*output), d.limits.MaxHandles); err != nil {
			return err
		}
		var item handleDTO
		var idSet bool
		if err := d.readObject(func(name string) error {
			if name != "id" {
				return malformed()
			}
			idSet = true
			return d.readStringValue(&item.id)
		}); err != nil {
			return err
		}
		if !idSet {
			return malformed()
		}
		*output = append(*output, item)
		return nil
	})
}

// readProfiles decodes the bounded profile array.
func (d *decoder) readProfiles(output *[]profileDTO) error {
	return d.readArray(func() error {
		if err := d.takeRecord(len(*output), d.limits.MaxProfiles); err != nil {
			return err
		}
		item, err := d.readProfile()
		if err != nil {
			return err
		}
		*output = append(*output, item)
		return nil
	})
}

// readProfile decodes one closed profile object.
func (d *decoder) readProfile() (profileDTO, error) {
	var item profileDTO
	var idSet, domainSet, statusSet, credentialsSet bool
	err := d.readObject(func(name string) error {
		switch name {
		case "id":
			idSet = true
			return d.readStringValue(&item.id)
		case "domain":
			domainSet = true
			return d.readStringValue(&item.domain)
		case "status":
			statusSet = true
			return d.readStringValue(&item.status)
		case "credentials":
			credentialsSet = true
			return d.readCredentials(&item.credentials)
		case "not_before":
			item.notBeforeSet = true
			return d.readStringValue(&item.notBefore)
		case "not_after":
			item.notAfterSet = true
			return d.readStringValue(&item.notAfter)
		default:
			return malformed()
		}
	})
	if err != nil {
		return profileDTO{}, err
	}
	if !idSet || !domainSet || !statusSet || !credentialsSet ||
		item.notBeforeSet != item.notAfterSet {
		return profileDTO{}, malformed()
	}
	return item, nil
}

// readCredentials decodes one profile's bounded credential array.
func (d *decoder) readCredentials(output *[]credentialDTO) error {
	return d.readArray(func() error {
		if err := d.takeRecord(len(*output), d.limits.MaxCredentialsPerProfile); err != nil {
			return err
		}
		var item credentialDTO
		var algorithmSet, selectorSet, publicKeySet, handleSet bool
		err := d.readObject(func(name string) error {
			switch name {
			case "algorithm":
				algorithmSet = true
				return d.readStringValue(&item.algorithm)
			case "selector":
				selectorSet = true
				return d.readStringValue(&item.selector)
			case "public_key_spki":
				publicKeySet = true
				return d.readStringValue(&item.publicKeySPKI)
			case "handle_id":
				handleSet = true
				return d.readStringValue(&item.handleID)
			default:
				return malformed()
			}
		})
		if err != nil {
			return err
		}
		if !algorithmSet || !selectorSet || !publicKeySet || !handleSet {
			return malformed()
		}
		*output = append(*output, item)
		return nil
	})
}

// readPolicies decodes the bounded administrative-policy array.
func (d *decoder) readPolicies(output *[]policyDTO) error {
	return d.readArray(func() error {
		if err := d.takeRecord(len(*output), d.limits.MaxPolicies); err != nil {
			return err
		}
		item, err := d.readPolicy()
		if err != nil {
			return err
		}
		*output = append(*output, item)
		return nil
	})
}

// readPolicy decodes one closed administrative-policy object.
func (d *decoder) readPolicy() (policyDTO, error) {
	var item policyDTO
	var tenantSet, domainSet, useSet, profileSet bool
	var statusSet, rolloutSet, compatibilitySet bool
	err := d.readObject(func(name string) error {
		switch name {
		case "tenant_id":
			tenantSet = true
			return d.readStringValue(&item.tenantID)
		case "domain":
			domainSet = true
			return d.readStringValue(&item.domain)
		case "use":
			useSet = true
			return d.readStringValue(&item.use)
		case "profile_id":
			profileSet = true
			return d.readStringValue(&item.profileID)
		case "status":
			statusSet = true
			return d.readStringValue(&item.status)
		case "rollout":
			rolloutSet = true
			return d.readStringValue(&item.rollout)
		case "compatibility":
			compatibilitySet = true
			return d.readStringValue(&item.compatibility)
		case "feedback_route_id":
			item.feedbackRouteIDSet = true
			return d.readStringValue(&item.feedbackRouteID)
		default:
			return malformed()
		}
	})
	if err != nil {
		return policyDTO{}, err
	}
	if !tenantSet || !domainSet || !useSet || !profileSet ||
		!statusSet || !rolloutSet || !compatibilitySet {
		return policyDTO{}, malformed()
	}
	return item, nil
}

// readObject applies one schema callback to each already duplicate-free member.
func (d *decoder) readObject(consumeMember func(string) error) error {
	d.skipWhitespace()
	if !d.consume('{') {
		return malformed()
	}
	d.skipWhitespace()
	if d.consume('}') {
		return nil
	}
	for {
		name, err := d.readString()
		if err != nil {
			return err
		}
		d.skipWhitespace()
		if !d.consume(':') {
			return malformed()
		}
		if err := consumeMember(name); err != nil {
			return err
		}
		d.skipWhitespace()
		if d.consume('}') {
			return nil
		}
		if !d.consume(',') {
			return malformed()
		}
		d.skipWhitespace()
	}
}

// readArray applies one item callback to every array element.
func (d *decoder) readArray(consumeItem func() error) error {
	d.skipWhitespace()
	if !d.consume('[') {
		return malformed()
	}
	d.skipWhitespace()
	if d.consume(']') {
		return nil
	}
	for {
		if err := consumeItem(); err != nil {
			return err
		}
		d.skipWhitespace()
		if d.consume(']') {
			return nil
		}
		if !d.consume(',') {
			return malformed()
		}
		d.skipWhitespace()
	}
}

// readStringValue consumes one schema value that must be a JSON string.
func (d *decoder) readStringValue(output *string) error {
	d.skipWhitespace()
	value, err := d.readString()
	if err != nil {
		return err
	}
	*output = value
	return nil
}

// takeRecord enforces both one collection cap and aggregate work cap.
func (d *decoder) takeRecord(current, maximum int) error {
	if current >= maximum || d.records >= d.limits.MaxRecords {
		return limitExceeded()
	}
	d.records++
	return nil
}

// buildProvider validates all DTOs through datasource owners before publication.
func (d documentDTO) buildProvider(
	generation uint64,
	limits datasource.Limits,
) (*memory.Provider, error) {
	handles := make([]datasource.KeyHandleID, 0, len(d.handles))
	for _, input := range d.handles {
		handleID, err := buildHandleID(input.id, limits)
		if err != nil {
			return nil, err
		}
		handles = append(handles, handleID)
	}
	profiles := make([]datasource.Profile, 0, len(d.profiles))
	for _, input := range d.profiles {
		profile, err := input.build(limits)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, profile)
	}
	policies := make([]datasource.Policy, 0, len(d.policies))
	for _, input := range d.policies {
		policy, err := input.build(limits)
		if err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}
	provider, err := memory.New(generation, handles, profiles, policies, limits)
	if err != nil {
		return nil, providerDataError(err)
	}
	return provider, nil
}

// build converts one profile DTO through domain-owned validators.
func (d profileDTO) build(limits datasource.Limits) (datasource.Profile, error) {
	id, err := buildProfileID(d.id, limits)
	if err != nil {
		return datasource.Profile{}, err
	}
	status, err := datasource.ParseRecordStatus(d.status)
	if err != nil {
		return datasource.Profile{}, malformed()
	}
	if len(d.credentials) == 2 &&
		(d.credentials[0].algorithm != string(datasource.AlgorithmRSASHA256) ||
			d.credentials[1].algorithm != string(datasource.AlgorithmEd25519SHA256)) {
		return datasource.Profile{}, malformed()
	}
	credentials := make([]datasource.Credential, 0, len(d.credentials))
	for _, input := range d.credentials {
		credential, credentialErr := input.build(limits)
		if credentialErr != nil {
			return datasource.Profile{}, credentialErr
		}
		credentials = append(credentials, credential)
	}
	var notBefore, notAfter time.Time
	if d.notBeforeSet {
		notBefore, err = parseTimestamp(d.notBefore)
		if err != nil {
			return datasource.Profile{}, err
		}
		notAfter, err = parseTimestamp(d.notAfter)
		if err != nil {
			return datasource.Profile{}, err
		}
	}
	profile, err := datasource.NewProfile(
		id, d.domain, status, credentials, notBefore, notAfter, limits,
	)
	if err != nil {
		return datasource.Profile{}, providerDataError(err)
	}
	if profile.SigningDomain() != d.domain {
		return datasource.Profile{}, malformed()
	}
	return profile, nil
}

// build converts one credential DTO through public-key and datasource owners.
func (d credentialDTO) build(limits datasource.Limits) (datasource.Credential, error) {
	var algorithm datasource.Algorithm
	switch d.algorithm {
	case string(datasource.AlgorithmRSASHA256):
		algorithm = datasource.AlgorithmRSASHA256
	case string(datasource.AlgorithmEd25519SHA256):
		algorithm = datasource.AlgorithmEd25519SHA256
	default:
		return datasource.Credential{}, malformed()
	}
	handleID, err := buildHandleID(d.handleID, limits)
	if err != nil {
		return datasource.Credential{}, err
	}
	publicKey, err := decodePublicKey(d.publicKeySPKI, limits)
	if err != nil {
		return datasource.Credential{}, err
	}
	credential, err := datasource.NewCredential(
		d.selector, algorithm, publicKey, handleID, limits,
	)
	if err != nil {
		return datasource.Credential{}, providerDataError(err)
	}
	if credential.Selector() != d.selector ||
		!bytes.Equal(credential.PublicKeySPKIDER(), publicKey) {
		return datasource.Credential{}, malformed()
	}
	return credential, nil
}

// build converts one policy DTO through datasource-owned validators.
func (d policyDTO) build(limits datasource.Limits) (datasource.Policy, error) {
	tenantID, err := buildTenantID(d.tenantID, limits)
	if err != nil {
		return datasource.Policy{}, err
	}
	profileID, err := buildProfileID(d.profileID, limits)
	if err != nil {
		return datasource.Policy{}, err
	}
	use, err := datasource.ParseProfileUse(d.use)
	if err != nil {
		return datasource.Policy{}, malformed()
	}
	status, err := datasource.ParseRecordStatus(d.status)
	if err != nil {
		return datasource.Policy{}, malformed()
	}
	rollout, err := datasource.ParseRollout(d.rollout)
	if err != nil {
		return datasource.Policy{}, malformed()
	}
	compatibility, err := datasource.ParseCompatibility(d.compatibility)
	if err != nil {
		return datasource.Policy{}, malformed()
	}
	var feedback datasource.FeedbackRouteID
	if d.feedbackRouteIDSet {
		feedback, err = buildFeedbackRouteID(d.feedbackRouteID, limits)
		if err != nil {
			return datasource.Policy{}, err
		}
	}
	policy, err := datasource.NewPolicy(
		tenantID, d.domain, use, profileID, status, rollout,
		compatibility, feedback, limits,
	)
	if err != nil {
		return datasource.Policy{}, providerDataError(err)
	}
	if policy.SigningDomain() != d.domain {
		return datasource.Policy{}, malformed()
	}
	return policy, nil
}

// buildHandleID validates one exact non-normalized opaque handle identifier.
func buildHandleID(value string, limits datasource.Limits) (datasource.KeyHandleID, error) {
	if len(value) > limits.MaxIdentifierBytes {
		return datasource.KeyHandleID{}, limitExceeded()
	}
	result, err := datasource.NewKeyHandleID(value)
	if err != nil {
		return datasource.KeyHandleID{}, malformed()
	}
	return result, nil
}

// buildProfileID validates one exact non-normalized profile identifier.
func buildProfileID(value string, limits datasource.Limits) (datasource.ProfileID, error) {
	if len(value) > limits.MaxIdentifierBytes {
		return datasource.ProfileID{}, limitExceeded()
	}
	result, err := datasource.NewProfileID(value)
	if err != nil {
		return datasource.ProfileID{}, malformed()
	}
	return result, nil
}

// buildTenantID validates one exact non-normalized tenant identifier.
func buildTenantID(value string, limits datasource.Limits) (datasource.TenantID, error) {
	if len(value) > limits.MaxIdentifierBytes {
		return datasource.TenantID{}, limitExceeded()
	}
	result, err := datasource.NewTenantID(value)
	if err != nil {
		return datasource.TenantID{}, malformed()
	}
	return result, nil
}

// buildFeedbackRouteID validates one exact non-normalized feedback identifier.
func buildFeedbackRouteID(
	value string,
	limits datasource.Limits,
) (datasource.FeedbackRouteID, error) {
	if len(value) > limits.MaxIdentifierBytes {
		return datasource.FeedbackRouteID{}, limitExceeded()
	}
	result, err := datasource.NewFeedbackRouteID(value)
	if err != nil {
		return datasource.FeedbackRouteID{}, malformed()
	}
	return result, nil
}

// decodePublicKey enforces strict padded canonical standard base64 before DER work.
func decodePublicKey(value string, limits datasource.Limits) ([]byte, error) {
	if len(value) == 0 || len(value)%4 != 0 {
		return nil, malformed()
	}
	padding := 0
	if value[len(value)-1] == '=' {
		padding++
	}
	if len(value) > 1 && value[len(value)-2] == '=' {
		padding++
	}
	decodedLength := len(value)/4*3 - padding
	if decodedLength <= 0 {
		return nil, malformed()
	}
	if decodedLength > limits.MaxDecodedPublicKeyBytes {
		return nil, limitExceeded()
	}
	decoded := make([]byte, decodedLength)
	count, err := base64.StdEncoding.Strict().Decode(decoded, []byte(value))
	if err != nil || count != decodedLength ||
		base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, malformed()
	}
	return decoded, nil
}

// parseTimestamp requires exact canonical UTC RFC3339Nano with terminal Z.
func parseTimestamp(value string) (time.Time, error) {
	if len(value) == 0 || value[len(value)-1] != 'Z' {
		return time.Time{}, malformed()
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC ||
		parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, malformed()
	}
	return parsed, nil
}

// providerDataError maps caller-valid provider input into closed file-data errors.
func providerDataError(err error) error {
	switch datasource.ErrorCodeOf(err) {
	case datasource.ErrorCodeLimitExceeded:
		return limitExceeded()
	case datasource.ErrorCodeAmbiguous:
		return datasource.NewError(datasource.ErrorCodeAmbiguous)
	case datasource.ErrorCodeMalformedData:
		return malformed()
	case datasource.ErrorCodeInternalInvariant:
		return datasource.NewError(datasource.ErrorCodeInternalInvariant)
	default:
		return malformed()
	}
}

// malformed returns the opaque provider-data parse failure.
func malformed() error { return datasource.NewError(datasource.ErrorCodeMalformedData) }

// limitExceeded returns the opaque configured resource failure.
func limitExceeded() error { return datasource.NewError(datasource.ErrorCodeLimitExceeded) }
