package milter

import (
	"strings"
	"unicode/utf8"
)

const (
	maxActionAggregateBytes = 3 * maxMilterFrameLength

	modeInbound       = "inbound"
	modeOriginator    = "originator"
	modeTransit       = "ordinary_transit"
	modePostfixDSN    = "postfix_dsn"
	operationProcess  = "process"
	operationSign     = "sign"
	operationRevise   = "revise"
	operationDSNSign  = "delivery_status"
	resultPass        = "pass"
	resultFail        = "fail"
	resultPermerror   = "permerror"
	resultTemperror   = "temperror"
	resultNone        = "none"
	headerAuthResults = "Authentication-Results"
	headerMessage     = "Message-Instance"
	headerDKIM2       = "DKIM2-Signature"
)

// validResult proves the complete operation/action matrix without side effects.
func validResult(result Result, mode, authservID string) bool {
	wantOperation, ok := operationForMode(mode)
	if !ok || result.Operation != wantOperation ||
		!validDisposition(result.Outcome) ||
		!validActions(result) {
		return false
	}
	switch mode {
	case modeInbound:
		return (validResultStatus(result.Result) || result.Result == resultNone) &&
			validInboundResult(result, authservID)
	case modeOriginator, modePostfixDSN:
		return (validResultStatus(result.Result) || result.Result == resultNone) &&
			validOriginatorResult(result)
	case modeTransit:
		return validResultStatus(result.Result) && validResultOutcome(result.Result, result.Outcome) &&
			validTransitResult(result)
	}
	return false
}

// validResultOutcome enforces the exact daemon result/disposition matrix.
func validResultOutcome(result string, disposition Disposition) bool {
	switch result {
	case resultPass:
		return disposition == DispositionAccept ||
			disposition == DispositionContinue
	case resultFail, resultPermerror:
		return disposition == DispositionReject
	case resultTemperror:
		return disposition == DispositionTempfail
	default:
		return false
	}
}

// operationForMode returns the sole daemon operation authorized for a mode.
func operationForMode(mode string) (string, bool) {
	switch mode {
	case modeInbound:
		return operationProcess, true
	case modeOriginator:
		return operationSign, true
	case modeTransit:
		return operationRevise, true
	case modePostfixDSN:
		return operationDSNSign, true
	default:
		return "", false
	}
}

// validResultStatus admits only the closed daemon result vocabulary.
func validResultStatus(status string) bool {
	return status == resultPass || status == resultFail ||
		status == resultPermerror || status == resultTemperror
}

// validDisposition admits only terminal dispositions understood by this adapter.
func validDisposition(disposition Disposition) bool {
	return disposition == DispositionAccept || disposition == DispositionContinue ||
		disposition == DispositionReject || disposition == DispositionTempfail
}

// validActions validates the transport-safe shape and aggregate size of all actions.
func validActions(result Result) bool {
	if len(result.Actions) > 3 ||
		(result.Outcome != DispositionAccept &&
			result.Outcome != DispositionContinue && len(result.Actions) != 0) {
		return false
	}
	total := 0
	for _, action := range result.Actions {
		if action.Kind != ActionAddHeader || !validActionName(action.Name) ||
			action.Value == "" ||
			len(action.Name)+len(action.Value)+3 > maxMilterFrameLength ||
			strings.ContainsAny(action.Value, "\r\n\x00") {
			return false
		}
		total += len(action.Name) + len(action.Value) + 3
		if total > maxActionAggregateBytes {
			return false
		}
	}
	return true
}

// validInboundResult enforces the optional single authoritative report action.
func validInboundResult(result Result, authservID string) bool {
	if result.Result == resultNone {
		return result.Outcome == DispositionContinue && len(result.Actions) == 0
	}
	if authservID == "" ||
		(result.Outcome != DispositionAccept &&
			result.Outcome != DispositionContinue) {
		return len(result.Actions) == 0
	}
	return len(result.Actions) == 1 &&
		result.Actions[0].Name == headerAuthResults &&
		authservID != "" &&
		result.Actions[0].Value == authservID+"; dkim2="+result.Result
}

// validOriginatorResult enforces the exact ordered signing mutation.
func validOriginatorResult(result Result) bool {
	if result.Result == resultNone {
		return result.Outcome == DispositionContinue && len(result.Actions) == 0
	}
	if !validResultOutcome(result.Result, result.Outcome) {
		return false
	}
	if result.Outcome != DispositionAccept {
		return len(result.Actions) == 0
	}
	return result.Result == resultPass &&
		len(result.Actions) == 2 &&
		result.Actions[0].Name == headerMessage &&
		result.Actions[1].Name == headerDKIM2
}

// validTransitResult enforces the exact append-only revision alternatives.
func validTransitResult(result Result) bool {
	if result.Outcome != DispositionAccept {
		return len(result.Actions) == 0
	}
	if result.Result != resultPass {
		return false
	}
	if len(result.Actions) == 1 {
		return result.Actions[0].Name == headerDKIM2
	}
	return len(result.Actions) == 2 &&
		result.Actions[0].Name == headerMessage &&
		result.Actions[1].Name == headerDKIM2
}

// validActionName accepts only the exact append-only field matrix.
func validActionName(value string) bool {
	return value == headerMessage || value == headerDKIM2 ||
		value == headerAuthResults
}

// authenticationConflict detects exact local authserv-id authority.
func authenticationConflict(headers []headerField, authservID string) bool {
	return len(localAuthenticationResultOccurrences(headers, authservID)) != 0
}

// localAuthenticationResultOccurrences returns one-based field-name indexes
// for untrusted fields that claim this adapter's local authority.
func localAuthenticationResultOccurrences(
	headers []headerField,
	authservID string,
) []uint32 {
	if authservID == "" {
		return nil
	}
	occurrence := uint32(0)
	var matches []uint32
	for _, field := range headers {
		if !strings.EqualFold(string(field.name), headerAuthResults) {
			continue
		}
		occurrence++
		value := unfoldHeaderValue(field.value)
		claimed, ok := leadingAuthservID(value)
		if ok && equivalentAuthservID(claimed, authservID) {
			matches = append(matches, occurrence)
		}
	}
	return matches
}

// equivalentAuthservID compares validated canonical U-label forms as required
// at an RFC 8601 trust boundary with EAI-capable identifiers.
func equivalentAuthservID(claimed, local string) bool {
	if !utf8.ValidString(claimed) || !utf8.ValidString(local) {
		return false
	}
	profile := smtpIDNAProfile()
	claimedASCII, claimedErr := profile.ToASCII(claimed)
	localASCII, localErr := profile.ToASCII(local)
	if claimedErr != nil || localErr != nil {
		return false
	}
	claimedUnicode, claimedErr := profile.ToUnicode(claimedASCII)
	localUnicode, localErr := profile.ToUnicode(localASCII)
	return claimedErr == nil && localErr == nil &&
		strings.EqualFold(claimedUnicode, localUnicode)
}

// leadingAuthservID extracts the RFC 8601 value after bounded leading CFWS.
func leadingAuthservID(value string) (string, bool) {
	index, ok := skipCFWS(value, 0)
	if !ok || index >= len(value) {
		return "", false
	}
	if value[index] == '"' {
		var output strings.Builder
		for index++; index < len(value); index++ {
			switch value[index] {
			case '\\':
				index++
				if index >= len(value) {
					return "", false
				}
				output.WriteByte(value[index])
			case '"':
				return output.String(), output.Len() > 0
			case '\r', '\n':
				return "", false
			default:
				output.WriteByte(value[index])
			}
		}
		return "", false
	}
	start := index
	for index < len(value) {
		current := value[index]
		if current == ' ' || current == '\t' || current == '(' || current == ';' {
			break
		}
		if current < 33 || current == 127 {
			return "", false
		}
		index++
	}
	claimed := value[start:index]
	return claimed, claimed != "" && utf8.ValidString(claimed)
}

// skipCFWS skips RFC 5322 whitespace and nested comments without retaining content.
func skipCFWS(value string, index int) (int, bool) {
	for index < len(value) {
		switch value[index] {
		case ' ', '\t':
			index++
		case '(':
			depth := 1
			index++
			for index < len(value) && depth > 0 {
				switch value[index] {
				case '\\':
					index += 2
				case '(':
					depth++
					index++
				case ')':
					depth--
					index++
				case '\r', '\n':
					return 0, false
				default:
					index++
				}
			}
			if depth != 0 {
				return 0, false
			}
		default:
			return index, true
		}
	}
	return index, true
}

// unfoldHeaderValue removes only legal CRLF while retaining following WSP.
func unfoldHeaderValue(value []byte) string {
	output := make([]byte, 0, len(value))
	for index := 0; index < len(value); index++ {
		if value[index] == '\r' && index+2 < len(value) &&
			value[index+1] == '\n' && (value[index+2] == ' ' || value[index+2] == '\t') {
			index++
			continue
		}
		output = append(output, value[index])
	}
	return string(output)
}

// FormatAuthenticationResults constructs the exact RFC 8601 local projection.
func FormatAuthenticationResults(authservID, result string) (string, error) {
	if !validAuthservToken(authservID) ||
		!validResultStatus(result) {
		return "", &Error{Class: FailureContract}
	}
	return authservID + "; dkim2=" + result, nil
}

// validAuthservToken accepts canonical lower-case dot-atom host tokens.
func validAuthservToken(value string) bool {
	if value == "" || value != strings.ToLower(value) || len(value) > 253 {
		return false
	}
	for part := range strings.SplitSeq(value, ".") {
		if part == "" || len(part) > 63 || strings.HasPrefix(part, "-") ||
			strings.HasSuffix(part, "-") {
			return false
		}
		for _, char := range part {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}
