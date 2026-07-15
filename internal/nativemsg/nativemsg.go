// Package nativemsg implements the browser Native Messaging protocol so the
// Lumra extension can hand a target to the local engine and render its full
// verdict (including raw-socket attribution the browser cannot measure itself).
//
// Wire format (Chrome/Firefox): each message is UTF-8 JSON preceded by a 4-byte
// native-endian length prefix. We use little-endian, which is correct on the
// platforms Lumra ships to (amd64/arm64).
package nativemsg

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/croc100/lumra/internal/engine"
	"github.com/croc100/lumra/internal/verdict"
)

// maxMessage bounds an incoming message. Chrome caps requests at 1 MiB.
const maxMessage = 1 << 20

// Request is what the extension sends.
type Request struct {
	Target string `json:"target"`
}

// Response wraps a verdict or an error back to the extension.
type Response struct {
	Verdict *verdict.Verdict `json:"verdict,omitempty"`
	Error   string           `json:"error,omitempty"`
}

// Serve reads native-messaging requests from r and writes responses to w until
// EOF. Each request runs a diagnosis.
func Serve(r io.Reader, w io.Writer) error {
	for {
		req, err := readMessage(r)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		writeMessage(w, handle(req))
	}
}

// handle runs one diagnosis, translating panics-in-input into an error response.
func handle(req *Request) *Response {
	if req.Target == "" {
		return &Response{Error: "missing target"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return &Response{Verdict: engine.Diagnose(ctx, req.Target)}
}

// readMessage reads one length-prefixed JSON request.
func readMessage(r io.Reader) (*Request, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, io.EOF
		}
		return nil, err
	}
	n := binary.LittleEndian.Uint32(hdr[:])
	if n == 0 || n > maxMessage {
		return nil, fmt.Errorf("message length %d out of range", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	var req Request
	if err := json.Unmarshal(buf, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

// writeMessage frames and writes a response. Write errors are returned to the
// caller's next read; a best-effort write is acceptable for a per-message reply.
func writeMessage(w io.Writer, resp *Response) {
	body, err := json.Marshal(resp)
	if err != nil {
		body, _ = json.Marshal(&Response{Error: "marshal failed"})
	}
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(len(body)))
	_, _ = w.Write(hdr[:])
	_, _ = w.Write(body)
}
