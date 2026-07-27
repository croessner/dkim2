package resource

import "testing"

// TestMaximumEOMWorkingSetBytes freezes exact configured-message boundaries
// and proves invalid or overflowing inputs fail closed.
func TestMaximumEOMWorkingSetBytes(t *testing.T) {
	tests := []struct {
		name       string
		message    int64
		recipients int
		want       int64
		wantOK     bool
	}{
		{
			name: "four_mib_one_recipient", message: 4 << 20, recipients: 1,
			want: 58_919_936, wantOK: true,
		},
		{
			name: "default_maxima", message: 32 << 20, recipients: 2000,
			want: 267_511_296, wantOK: true,
		},
		{name: "zero_message", recipients: 1},
		{name: "zero_recipients", message: 1},
		{name: "overflow", message: int64(^uint64(0) >> 1), recipients: 1},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			got, ok := MaximumEOMWorkingSetBytes(
				testCase.message,
				testCase.recipients,
			)
			if got != testCase.want || ok != testCase.wantOK {
				t.Fatalf(
					"MaximumEOMWorkingSetBytes() = (%d,%t), want (%d,%t)",
					got,
					ok,
					testCase.want,
					testCase.wantOK,
				)
			}
		})
	}
}
