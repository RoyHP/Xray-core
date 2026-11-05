package tun

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type testCounter struct {
	value int64
}

func (c *testCounter) Value() int64 {
	return atomic.LoadInt64(&c.value)
}

func (c *testCounter) Set(value int64) int64 {
	return atomic.SwapInt64(&c.value, value)
}

func (c *testCounter) Add(value int64) int64 {
	return atomic.AddInt64(&c.value, value) - value
}

type testConn struct {
	reader *bytes.Reader
	writer bytes.Buffer
}

func newTestConn(input []byte) *testConn {
	return &testConn{reader: bytes.NewReader(input)}
}

func (c *testConn) Read(payload []byte) (int, error) {
	return c.reader.Read(payload)
}

func (c *testConn) Write(payload []byte) (int, error) {
	return c.writer.Write(payload)
}

func (c *testConn) Close() error {
	return nil
}

func (c *testConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1080}
}

func (c *testConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 12345}
}

func (c *testConn) SetDeadline(time.Time) error {
	return nil
}

func (c *testConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *testConn) SetWriteDeadline(time.Time) error {
	return nil
}

type testDispatcher struct {
	writePayload []byte
	readBytes    int32
}

func (d *testDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

func (d *testDispatcher) Start() error {
	return nil
}

func (d *testDispatcher) Close() error {
	return nil
}

func (d *testDispatcher) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
	return nil, nil
}

func (d *testDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	mb, err := link.Reader.ReadMultiBuffer()
	if err != nil {
		return err
	}
	atomic.StoreInt32(&d.readBytes, mb.Len())
	buf.ReleaseMulti(mb)

	return link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(d.writePayload)})
}

// closableConn is a connection that is its own writer, as the ones of the stack are
type closableConn struct {
	*testConn
	closed int32
}

func (c *closableConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return nil
}

func (c *closableConn) Close() error {
	atomic.AddInt32(&c.closed, 1)
	return nil
}

// closingDispatcher does what an outbound does when the other side has no more to send
type closingDispatcher struct {
	testDispatcher
	conn   *closableConn
	closed int32
}

func (d *closingDispatcher) DispatchLink(_ context.Context, _ xnet.Destination, link *transport.Link) error {
	common.Close(link.Writer)
	d.closed = atomic.LoadInt32(&d.conn.closed)
	return nil
}

func TestHandlerClosesTunConnectionWhenBothSidesAreDone(t *testing.T) {
	conn := &closableConn{testConn: newTestConn(nil)}
	dispatcher := &closingDispatcher{conn: conn}
	handler := &Handler{
		ctx:        context.Background(),
		config:     &Config{},
		dispatcher: dispatcher,
	}
	handler.HandleConnection(conn, xnet.TCPDestination(xnet.LocalHostIP, 443))

	if dispatcher.closed != 0 {
		t.Fatal("the connection was closed with its writer, while the system may still be sending")
	}
	if got := atomic.LoadInt32(&conn.closed); got != 1 {
		t.Fatalf("connection closed %d times, want 1", got)
	}
}

func TestHandlerCountsTunConnectionTraffic(t *testing.T) {
	uplinkCounter := new(testCounter)
	downlinkCounter := new(testCounter)
	dispatcher := &testDispatcher{writePayload: []byte("downlink")}
	conn := newTestConn([]byte("uplink"))

	handler := &Handler{
		ctx:             context.Background(),
		config:          &Config{},
		dispatcher:      dispatcher,
		uplinkCounter:   uplinkCounter,
		downlinkCounter: downlinkCounter,
	}
	handler.HandleConnection(conn, xnet.TCPDestination(xnet.LocalHostIP, 443))

	if got := uplinkCounter.Value(); got != int64(len("uplink")) {
		t.Fatalf("unexpected uplink counter: got %d, want %d", got, len("uplink"))
	}
	if got := downlinkCounter.Value(); got != int64(len("downlink")) {
		t.Fatalf("unexpected downlink counter: got %d, want %d", got, len("downlink"))
	}
	if got := int(atomic.LoadInt32(&dispatcher.readBytes)); got != len("uplink") {
		t.Fatalf("dispatcher read unexpected bytes: got %d, want %d", got, len("uplink"))
	}
	if got := conn.writer.String(); got != "downlink" {
		t.Fatalf("connection write mismatch: got %q, want %q", got, "downlink")
	}
}

// blockingConn is a connection the system keeps open and silent, as a keep-alive is, until it is closed
type blockingConn struct {
	*testConn
	closed chan struct{}
	once   sync.Once
}

func newBlockingConn() *blockingConn {
	return &blockingConn{testConn: newTestConn(nil), closed: make(chan struct{})}
}

func (c *blockingConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.EOF
}

func (c *blockingConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func TestHandlerClosesTheLongestIdleFlowForASlot(t *testing.T) {
	h := &Handler{
		ctx:        context.Background(),
		config:     &Config{},
		tcpSlots:   make(chan struct{}, 1),
		flowWait:   3 * time.Second,
		idleEvict:  20 * time.Millisecond,
		flows:      map[*tcpFlow]struct{}{},
		dispatcher: &testDispatcher{writePayload: []byte("reply")},
	}
	dest := xnet.TCPDestination(xnet.IPAddress([]byte{93, 184, 216, 34}), 443)

	idle := newBlockingConn()
	done := make(chan struct{})
	go func() {
		h.HandleConnection(idle, dest)
		close(done)
	}()
	for i := 0; i < 200; i++ {
		h.flowsMu.Lock()
		n := len(h.flows)
		h.flowsMu.Unlock()
		if n == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(30 * time.Millisecond)

	started := time.Now()
	h.HandleConnection(newTestConn([]byte("hello")), dest)
	if took := time.Since(started); took >= h.flowWait {
		t.Fatalf("the new flow waited the whole flowWait (%v) instead of taking the idle flow's slot", took)
	}
	select {
	case <-idle.closed:
	default:
		t.Fatal("the idle flow was not closed for its slot")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the idle flow's dispatch did not end after it was closed")
	}
	if len(h.tcpSlots) != 0 {
		t.Fatalf("%d slot(s) still taken after both flows ended", len(h.tcpSlots))
	}
}

func TestHandlerKeepsBusyFlowsAndResetsTheNewOne(t *testing.T) {
	h := &Handler{
		ctx:        context.Background(),
		config:     &Config{},
		tcpSlots:   make(chan struct{}, 1),
		flowWait:   150 * time.Millisecond,
		idleEvict:  time.Hour,
		flows:      map[*tcpFlow]struct{}{},
		dispatcher: &testDispatcher{writePayload: []byte("reply")},
	}
	dest := xnet.TCPDestination(xnet.IPAddress([]byte{93, 184, 216, 34}), 443)
	busy := newBlockingConn()
	go h.HandleConnection(busy, dest)
	time.Sleep(30 * time.Millisecond)

	started := time.Now()
	h.HandleConnection(newTestConn([]byte("hello")), dest)
	if took := time.Since(started); took < h.flowWait {
		t.Fatalf("the new flow got a slot after %v although the only flow was not idle enough", took)
	}
	select {
	case <-busy.closed:
		t.Fatal("a flow below the idle threshold was closed")
	default:
	}
	busy.Close()
}
