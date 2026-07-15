package nativemsg

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
)

// frame encodes a request the way the browser would, for feeding readMessage.
func frame(t *testing.T, v any) []byte {
	t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(len(body)))
	return append(hdr[:], body...)
}

func TestReadMessage(t *testing.T) {
	in := bytes.NewReader(frame(t, Request{Target: "example.com"}))
	req, err := readMessage(in)
	if err != nil {
		t.Fatal(err)
	}
	if req.Target != "example.com" {
		t.Errorf("Target = %q, want example.com", req.Target)
	}
}

func TestWriteMessageRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	writeMessage(&buf, &Response{Error: "boom"})

	// The frame we wrote must be readable back with the same length prefix.
	n := binary.LittleEndian.Uint32(buf.Bytes()[:4])
	if int(n) != buf.Len()-4 {
		t.Fatalf("length prefix %d != body %d", n, buf.Len()-4)
	}
	var resp Response
	if err := json.Unmarshal(buf.Bytes()[4:], &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error != "boom" {
		t.Errorf("Error = %q, want boom", resp.Error)
	}
}

func TestReadMessageRejectsOversize(t *testing.T) {
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], maxMessage+1)
	if _, err := readMessage(bytes.NewReader(hdr[:])); err == nil {
		t.Error("expected oversize message to be rejected")
	}
}

func TestHandleMissingTarget(t *testing.T) {
	if resp := handle(&Request{}); resp.Error == "" {
		t.Error("expected error for missing target")
	}
}
