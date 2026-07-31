package evidence

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"time"
)

const (
	readinessBytes           = 112
	readinessPayloadBytes    = readinessBytes - sha256.Size
	readinessVersion         = byte(1)
	readinessClean           = byte(1)
	readinessDirty           = byte(2)
	readinessClosed          = byte(3)
	readinessTemporaryPrefix = ".ready-"
	readinessMACDomain       = "DKIM2-EXIM-READINESS-V1\x00"
)

// rootFingerprint binds readiness to one exact evidence-root generation.
type rootFingerprint struct {
	device    uint64
	inode     uint64
	mtimeSec  int64
	mtimeNsec int64
	ctimeSec  int64
	ctimeNsec int64
}

// readinessSnapshot is one authenticated cross-process store state.
type readinessSnapshot struct {
	state      byte
	generation uint64
	root       rootFingerprint
	stats      Stats
}

// encodeReadiness authenticates one fixed-width store snapshot.
func encodeReadiness(snapshot readinessSnapshot, key []byte) ([]byte, error) {
	if len(key) != KeyBytes || snapshot.generation == 0 ||
		snapshot.state < readinessClean || snapshot.state > readinessClosed ||
		!snapshot.stats.Valid() {
		return nil, ErrEvidence
	}
	output := make([]byte, readinessBytes)
	copy(output[:4], "DXR1")
	output[4] = readinessVersion
	output[5] = snapshot.state
	binary.BigEndian.PutUint64(output[8:16], snapshot.generation)
	binary.BigEndian.PutUint64(output[16:24], snapshot.root.device)
	binary.BigEndian.PutUint64(output[24:32], snapshot.root.inode)
	binary.BigEndian.PutUint64(output[32:40], uint64(snapshot.root.mtimeSec))
	binary.BigEndian.PutUint64(output[40:48], uint64(snapshot.root.mtimeNsec))
	binary.BigEndian.PutUint64(output[48:56], uint64(snapshot.root.ctimeSec))
	binary.BigEndian.PutUint64(output[56:64], uint64(snapshot.root.ctimeNsec))
	binary.BigEndian.PutUint64(output[64:72], uint64(snapshot.stats.Records))
	binary.BigEndian.PutUint64(output[72:80], uint64(snapshot.stats.Bytes))
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(readinessMACDomain))
	_, _ = mac.Write(output[:readinessPayloadBytes])
	sum := mac.Sum(nil)
	copy(output[readinessPayloadBytes:], sum)
	clear(sum)
	return output, nil
}

// decodeReadiness verifies one exact clean/dirty generation snapshot.
func decodeReadiness(encoded, key []byte) (readinessSnapshot, error) {
	if len(encoded) != readinessBytes || len(key) != KeyBytes ||
		string(encoded[:4]) != "DXR1" || encoded[4] != readinessVersion ||
		encoded[5] < readinessClean || encoded[5] > readinessClosed ||
		encoded[6] != 0 || encoded[7] != 0 {
		return readinessSnapshot{}, ErrEvidence
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(readinessMACDomain))
	_, _ = mac.Write(encoded[:readinessPayloadBytes])
	expected := mac.Sum(nil)
	valid := hmac.Equal(encoded[readinessPayloadBytes:], expected)
	clear(expected)
	if !valid {
		return readinessSnapshot{}, ErrEvidence
	}
	recordCount := binary.BigEndian.Uint64(encoded[64:72])
	byteCount := binary.BigEndian.Uint64(encoded[72:80])
	generation := binary.BigEndian.Uint64(encoded[8:16])
	device := binary.BigEndian.Uint64(encoded[16:24])
	inode := binary.BigEndian.Uint64(encoded[24:32])
	mtimeSec := int64(binary.BigEndian.Uint64(encoded[32:40]))
	mtimeNsec := int64(binary.BigEndian.Uint64(encoded[40:48]))
	ctimeSec := int64(binary.BigEndian.Uint64(encoded[48:56]))
	ctimeNsec := int64(binary.BigEndian.Uint64(encoded[56:64]))
	if generation == 0 || recordCount > uint64(MaximumMaxRecords) ||
		byteCount > uint64(MaximumMaxBytes) || device == 0 || inode == 0 ||
		mtimeSec <= 0 || ctimeSec <= 0 ||
		mtimeNsec < 0 || mtimeNsec >= int64(time.Second) ||
		ctimeNsec < 0 || ctimeNsec >= int64(time.Second) ||
		recordCount == 0 && byteCount != 0 ||
		recordCount != 0 && byteCount == 0 {
		return readinessSnapshot{}, ErrEvidence
	}
	return readinessSnapshot{
		state: encoded[5], generation: generation,
		root: rootFingerprint{
			device: device, inode: inode,
			mtimeSec: mtimeSec, mtimeNsec: mtimeNsec,
			ctimeSec: ctimeSec, ctimeNsec: ctimeNsec,
		},
		stats: Stats{
			Records: int(recordCount),
			Bytes:   int64(byteCount),
		},
	}, nil
}
