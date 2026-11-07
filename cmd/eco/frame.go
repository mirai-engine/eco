package main

// Wire format: one TLS connection carries many independent streams as binary frames.
//
//	+------+------------+------------+---------+
//	| type | stream (4) | length (4) | payload |
//	+------+------------+------------+---------+
//
// Control payloads are JSON; data payloads are raw bytes (no base64). Each stream has credit-based
// flow control per direction, so a slow consumer on one stream never blocks the others and memory
// stays bounded.

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
)

const (
	fOpen     byte = 1 + iota // client -> server: JSON openReq starts a stream
	fStdin                    // client -> server: stdin or upload data
	fStdinEOF                 // client -> server: end of stdin/upload; optional JSON {"sha256"}
	fCancel                   // client -> server: kill the job / abort the transfer
	fCredit                   // both ways: 4-byte big-endian bytes of new window credit
	fOut                      // server -> client: stdout (or file) data
	fErr                      // server -> client: stderr data
	fExit                     // server -> client: JSON exitInfo, ends the stream
	fError                    // server -> client: JSON {"error"}, ends the stream
	fMeta                     // server -> client: JSON metaInfo
	fDetach                   // client -> server: stop the output, leave the job running (answered by fMeta detached)
)

const (
	maxFrame      = 1 << 20
	chunkSize     = 64 << 10
	initialWindow = 4 << 20
	creditStep    = 1 << 20
)

var errClosed = errors.New("connection closed")

type frame struct {
	typ     byte
	stream  uint32
	payload []byte
}

func writeFrame(w io.Writer, typ byte, stream uint32, payload []byte) error {
	if len(payload) > maxFrame {
		return errors.New("frame too large")
	}
	buf := make([]byte, 9+len(payload))
	buf[0] = typ
	binary.BigEndian.PutUint32(buf[1:], stream)
	binary.BigEndian.PutUint32(buf[5:], uint32(len(payload)))
	copy(buf[9:], payload)
	_, err := w.Write(buf) // one Write: header and payload are never split across writers
	return err
}

func readFrame(r io.Reader) (frame, error) {
	var h [9]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return frame{}, err
	}
	n := binary.BigEndian.Uint32(h[5:])
	if n > maxFrame {
		return frame{}, errors.New("frame too large")
	}
	f := frame{typ: h[0], stream: binary.BigEndian.Uint32(h[1:]), payload: make([]byte, n)}
	if _, err := io.ReadFull(r, f.payload); err != nil {
		return frame{}, err
	}
	return f, nil
}

func creditPayload(n int) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(n))
	return b[:]
}

// window is the sender side of flow control: take blocks until credit is available.
type window struct {
	mu     sync.Mutex
	cond   *sync.Cond
	n      int64
	closed bool
}

func newWindow(n int64) *window {
	w := &window{n: n}
	w.cond = sync.NewCond(&w.mu)
	return w
}

func (w *window) add(n int64) {
	w.mu.Lock()
	if w.n+n <= 1<<40 { // a misbehaving peer cannot overflow the counter
		w.n += n
	}
	w.cond.Broadcast()
	w.mu.Unlock()
}

// take reserves up to max bytes of credit, blocking until some is available.
func (w *window) take(max int) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for w.n <= 0 && !w.closed {
		w.cond.Wait()
	}
	if w.closed {
		return 0, errClosed
	}
	k := min(int64(max), w.n)
	w.n -= k
	return int(k), nil
}

func (w *window) close() {
	w.mu.Lock()
	w.closed = true
	w.cond.Broadcast()
	w.mu.Unlock()
}

// frameQueue hands frames from a connection's read loop to one stream consumer without ever blocking
// the read loop; its size is bounded by the credit granted to the peer.
type frameQueue struct {
	mu     sync.Mutex
	cond   *sync.Cond
	q      []frame
	closed bool
	err    error
}

func newFrameQueue() *frameQueue {
	q := &frameQueue{}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *frameQueue) push(f frame) {
	q.mu.Lock()
	if !q.closed {
		q.q = append(q.q, f)
		q.cond.Signal()
	}
	q.mu.Unlock()
}

// pop returns queued frames first, then the close error.
func (q *frameQueue) pop() (frame, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.q) == 0 && !q.closed {
		q.cond.Wait()
	}
	if len(q.q) > 0 {
		f := q.q[0]
		q.q[0] = frame{}
		q.q = q.q[1:]
		return f, nil
	}
	return frame{}, q.err
}

func (q *frameQueue) close(err error) {
	q.mu.Lock()
	if !q.closed {
		q.closed = true
		q.err = err
	}
	q.cond.Broadcast()
	q.mu.Unlock()
}

// creditor batches credit returns on the receiver side.
type creditor struct {
	mu       sync.Mutex
	consumed int
	grant    func(n int)
}

func (c *creditor) consume(n int) {
	c.mu.Lock()
	c.consumed += n
	var give int
	if c.consumed >= creditStep {
		give, c.consumed = c.consumed, 0
	}
	c.mu.Unlock()
	if give > 0 {
		c.grant(give)
	}
}
