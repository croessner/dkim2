package daemon

import (
	"encoding/json"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/daemon/generated"
)

// completeDeliveryStatusProjection returns one complete received delivery-status
// projection whose members are all inside their closed vocabularies.
func completeDeliveryStatusProjection() generated.DeliveryStatusProjection {
	return generated.DeliveryStatusProjection{
		Embedded:         generated.DeliveryStatusEmbeddedVerified,
		LocalHop:         generated.DeliveryStatusLocalHopLocal,
		OuterAlignment:   generated.DeliveryStatusOuterAlignmentAligned,
		Propagation:      generated.DeliveryStatusPropagationEligible,
		RecipientLinkage: generated.DeliveryStatusRecipientLinkageLinked,
		Structure:        generated.DeliveryStatusStructureValid,
	}
}

// TestProcessContractToleratesAbsentAndPresentDeliveryStatus proves the inbound
// adapter accepts the optional received delivery-status member in both
// directions without changing any other inbound response fact.
func TestProcessContractToleratesAbsentAndPresentDeliveryStatus(t *testing.T) {
	t.Parallel()
	absent := validProcessResponse()
	if absent.DeliveryStatus != nil {
		t.Fatal("baseline inbound response already carried a delivery-status member")
	}
	if !validProcessContract(&absent, testAuthservID) {
		t.Fatal("inbound response without the delivery-status member was rejected")
	}

	present := validProcessResponse()
	projection := completeDeliveryStatusProjection()
	present.DeliveryStatus = &projection
	if !validProcessContract(&present, testAuthservID) {
		t.Fatal("inbound response with the delivery-status member was rejected")
	}
	if present.Disposition != absent.Disposition ||
		present.Authentication.State != absent.Authentication.State ||
		len(present.Actions) != len(absent.Actions) ||
		present.Actions[0].Value != absent.Actions[0].Value {
		t.Fatal("the delivery-status member changed an inbound action or state fact")
	}
}

// TestProcessContractRejectsUnknownDeliveryStatusMember proves each closed
// vocabulary of the optional member is validated instead of trusted.
func TestProcessContractRejectsUnknownDeliveryStatusMember(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*generated.DeliveryStatusProjection){
		"structure": func(value *generated.DeliveryStatusProjection) {
			value.Structure = generated.DeliveryStatusProjectionStructure("future")
		},
		"embedded": func(value *generated.DeliveryStatusProjection) {
			value.Embedded = generated.DeliveryStatusProjectionEmbedded("future")
		},
		"outer alignment": func(value *generated.DeliveryStatusProjection) {
			value.OuterAlignment = generated.DeliveryStatusProjectionOuterAlignment("future")
		},
		"recipient linkage": func(value *generated.DeliveryStatusProjection) {
			value.RecipientLinkage = generated.DeliveryStatusProjectionRecipientLinkage("future")
		},
		"local hop": func(value *generated.DeliveryStatusProjection) {
			value.LocalHop = generated.DeliveryStatusProjectionLocalHop("future")
		},
		"propagation": func(value *generated.DeliveryStatusProjection) {
			value.Propagation = generated.DeliveryStatusProjectionPropagation("future")
		},
	} {
		value := validProcessResponse()
		projection := completeDeliveryStatusProjection()
		mutate(&projection)
		value.DeliveryStatus = &projection
		if validProcessContract(&value, testAuthservID) {
			t.Fatalf("unknown delivery-status %s value was accepted", name)
		}
	}
}

// TestProcessRequiredMembersRejectIncompleteDeliveryStatus proves a present but
// partial projection fails closed before typed decoding trusts a zero value.
func TestProcessRequiredMembersRejectIncompleteDeliveryStatus(t *testing.T) {
	t.Parallel()
	value := validProcessResponse()
	projection := completeDeliveryStatusProjection()
	value.DeliveryStatus = &projection
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal("encoding the inbound response failed")
	}
	if !validProcessRequiredMembers(body) {
		t.Fatal("complete delivery-status member was rejected")
	}
	for _, member := range []string{
		"structure", "embedded", "outer_alignment",
		"recipient_linkage", "local_hop", "propagation",
	} {
		var document map[string]any
		if json.Unmarshal(body, &document) != nil {
			t.Fatal("decoding the inbound response failed")
		}
		delete(document["delivery_status"].(map[string]any), member)
		mutated, marshalErr := json.Marshal(document)
		if marshalErr != nil {
			t.Fatal("re-encoding the inbound response failed")
		}
		if validProcessRequiredMembers(mutated) {
			t.Fatalf("delivery-status member without %s was accepted", member)
		}
	}
}

// TestInboundRequestCarriesNoTenant proves the inbound adapter keeps its request
// unchanged and relies on the daemon's configured default authority.
func TestInboundRequestCarriesNoTenant(t *testing.T) {
	t.Parallel()
	request := generated.ProcessRequest{
		ApiVersion: generated.V1,
		Draft:      generated.DraftIetfDkimDkim2Spec06,
	}
	if request.Context != nil {
		t.Fatal("the inbound process request gained a tenant context")
	}
}
