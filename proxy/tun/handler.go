package tun

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Handler is managing object that tie together tun interface, ip stack and dispatch connections to the routing
type Handler struct {
	ctx    context.Context
	config *Config
	// tcpSlots bounds concurrently dispatched TCP flows when xray.tun.tcp.maxflows is set
	tcpSlots chan struct{}
	flowWait time.Duration
	// idleEvict is how long a dispatched flow must have carried nothing to be closed for a slot
	idleEvict time.Duration
	// flows are the dispatched TCP flows of the cap
	flowsMu         sync.Mutex
	flows           map[*tcpFlow]struct{}
	stack           Stack
	tun             Tun
	policyManager   policy.Manager
	dispatcher      routing.Dispatcher
	tag             string
	sniffingRequest session.SniffingRequest
	uplinkCounter   stats.Counter
	downlinkCounter stats.Counter
}

type tunUDPStatsWriter struct {
	writer  buf.Writer
	counter stats.Counter
}

func (w *tunUDPStatsWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for len(mb) > 0 {
		remaining, packet := buf.SplitFirst(mb)
		packetSize := packet.Len()
		if err := w.writer.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
			buf.ReleaseMulti(remaining)
			return err
		}
		w.counter.Add(int64(packetSize))
		mb = remaining
	}
	return nil
}

// tcpFlow is a dispatched TCP flow of the cap: its connection, to close it for its slot, and when it last
// carried a byte either way
type tcpFlow struct {
	conn net.Conn
	dest net.Destination
	// last is the time of the last byte, in nanoseconds since the Unix epoch
	last atomic.Int64
	// closing is set once the flow is closed for its slot, so it is not chosen again
	closing atomic.Bool
}

func (f *tcpFlow) touch() {
	f.last.Store(time.Now().UnixNano())
}

// activityReader stamps the flow when the system sends
type activityReader struct {
	buf.Reader
	flow *tcpFlow
}

func (r *activityReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	if !mb.IsEmpty() {
		r.flow.touch()
	}
	return mb, err
}

// TCPWriter is the writing side of a TCP connection of the stack for the dispatcher. The outbound closes its
// writer when the other side has no more to send; that is passed on to the system as a half-close (FIN), so
// a flow whose far end is gone ends as soon as the system closes in turn rather than at its idle timeout,
// while the system may still be sending
type TCPWriter struct {
	Writer buf.Writer
	// Counter counts what is written, if there is one
	Counter stats.Counter
	// Conn is the connection behind Writer, for the half-close
	Conn net.Conn
	// Flow is stamped with what is written, if the flow is one of the cap
	Flow *tcpFlow
}

// Close implements common.Closable: a half-close of the system's side
func (w *TCPWriter) Close() error {
	if hc, ok := w.Conn.(interface{ CloseWrite() error }); ok {
		return hc.CloseWrite()
	}
	return nil
}

func (w *TCPWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	size := mb.Len()
	if err := w.Writer.WriteMultiBuffer(mb); err != nil {
		return err
	}
	if w.Counter != nil {
		w.Counter.Add(int64(size))
	}
	if w.Flow != nil && size > 0 {
		w.Flow.touch()
	}
	return nil
}

// ConnectionHandler interface with the only method that stack is going to push new connections to
type ConnectionHandler interface {
	HandleConnection(conn net.Conn, destination net.Destination)
}

// Handler implements ConnectionHandler
var _ ConnectionHandler = (*Handler)(nil)

// Handler implements common.Runnable
var _ common.Runnable = (*Handler)(nil)

// Init the Handler instance with necessary parameters
func (t *Handler) Init(ctx context.Context, pm policy.Manager, dispatcher routing.Dispatcher) error {
	// Retrieve tag and sniffing config from context (set by AlwaysOnInboundHandler)
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		t.tag = inbound.Tag
	}
	if content := session.ContentFromContext(ctx); content != nil {
		t.sniffingRequest = content.SniffingRequest
	}

	t.ctx = core.ToBackgroundDetachedContext(ctx)
	t.policyManager = pm
	t.dispatcher = dispatcher
	if n := platform.NewEnvFlag(platform.TunMaxTCPFlowsKey).GetValueAsInt(0); n > 0 {
		t.tcpSlots = make(chan struct{}, n)
		t.flowWait = time.Duration(platform.NewEnvFlag(platform.TunFlowWaitKey).GetValueAsInt(15)) * time.Second
		t.idleEvict = time.Duration(platform.NewEnvFlag(platform.TunIdleEvictKey).GetValueAsInt(5)) * time.Second
		t.flows = make(map[*tcpFlow]struct{})
	}

	if len(t.tag) > 0 && pm.ForSystem().Stats.InboundUplink {
		statsManager := core.MustFromContext(ctx).GetFeature(stats.ManagerType()).(stats.Manager)
		name := "inbound>>>" + t.tag + ">>>traffic>>>uplink"
		c, _ := statsManager.GetOrRegisterCounter(name)
		if c != nil {
			t.uplinkCounter = c
		}
	}
	if len(t.tag) > 0 && pm.ForSystem().Stats.InboundDownlink {
		statsManager := core.MustFromContext(ctx).GetFeature(stats.ManagerType()).(stats.Manager)
		name := "inbound>>>" + t.tag + ">>>traffic>>>downlink"
		c, _ := statsManager.GetOrRegisterCounter(name)
		if c != nil {
			t.downlinkCounter = c
		}
	}

	return nil
}

func (t *Handler) Start() error {
	tunName := t.config.Name
	tunInterface, err := NewTun(t.config)
	if err != nil {
		return err
	}

	if t.config.AutoOutboundsInterface != "" {
		tunIndex, err := tunInterface.Index()
		if err != nil {
			_ = tunInterface.Close()
			return err
		}
		if t.config.AutoOutboundsInterface == "auto" {
			t.config.AutoOutboundsInterface = ""
		}
		updater = &InterfaceUpdater{tunIndex: tunIndex, fixedName: t.config.AutoOutboundsInterface}
		updater.Update()
		internet.RegisterDialerController(func(network, address string, c syscall.RawConn) error {
			iface := updater.Get()
			if iface == nil {
				errors.LogInfo(context.Background(), "[tun] falied to set interface > iface == nil")
				return errors.New("iface not found")
			}
			var controlErr, sockErr error
			controlErr = c.Control(func(fd uintptr) {
				addrPort, _ := netip.ParseAddrPort(address)
				// skip loopback
				if addrPort.Addr().IsLoopback() || strings.HasPrefix(strings.ToLower(address), "localhost:") {
					return
				}
				err := setinterface(network, address, fd, iface)
				if err != nil {
					sockErr = errors.New("[tun] falied to set interface").Base(err)
				}
			})
			if sockErr != nil {
				return sockErr
			}
			return controlErr
		})
	}

	errors.LogInfo(t.ctx, tunName, " created")

	tunStackOptions := StackOptions{
		Tun:         tunInterface,
		MTU:         t.config.MTU,
		IdleTimeout: t.policyManager.ForLevel(t.config.UserLevel).Timeouts.ConnectionIdle,
	}
	tunStack, err := NewStack(t.ctx, tunStackOptions, t)
	if err != nil {
		_ = tunInterface.Close()
		return err
	}

	err = tunStack.Start()
	if err != nil {
		_ = tunStack.Close()
		_ = tunInterface.Close()
		return err
	}

	err = tunInterface.Start()
	if err != nil {
		_ = tunStack.Close()
		_ = tunInterface.Close()
		return err
	}

	// Platform-specific system DNS takeover, where the platform implements it.
	// Rather no TUN than one that the system DNS bypasses.
	if c, ok := tunInterface.(interface {
		ConfigureSystemDNS(context.Context, string) error
	}); ok {
		if err := c.ConfigureSystemDNS(t.ctx, t.tag); err != nil {
			_ = tunStack.Close()
			_ = tunInterface.Close()
			return errors.New("unable to set the system DNS (remove autoSystemDnsToGateway to run without)").Base(err)
		}
	}

	t.stack = tunStack
	t.tun = tunInterface

	errors.LogInfo(t.ctx, tunName, " up")
	return nil
}

// HandleConnection pass the connection coming from the ip stack to the routing dispatcher
func (t *Handler) HandleConnection(conn net.Conn, destination net.Destination) {
	// when handling is done with any outcome, always signal back to the incoming connection
	// to close, send completion packets back to the network, and cleanup
	defer conn.Close()

	ctx, cancel := context.WithCancel(t.ctx)
	defer cancel()
	ctx = c.ContextWithID(ctx, session.NewID())

	source := net.DestinationFromAddr(conn.RemoteAddr())

	// Port 53 is never capped: DNS over TCP is rare and tiny, and a client's health probe
	// to its resolver must not queue behind a page's worth of busy flows.
	var flow *tcpFlow
	if t.tcpSlots != nil && destination.Network == net.Network_TCP && destination.Port != 53 {
		if !t.acquireSlot(ctx, destination) {
			return
		}
		defer func() { <-t.tcpSlots }()
		flow = &tcpFlow{conn: conn, dest: destination}
		flow.touch()
		t.flowsMu.Lock()
		t.flows[flow] = struct{}{}
		t.flowsMu.Unlock()
		defer func() {
			t.flowsMu.Lock()
			delete(t.flows, flow)
			t.flowsMu.Unlock()
		}()
	}

	inbound := session.Inbound{
		Name:          "tun",
		Tag:           t.tag,
		CanSpliceCopy: 3,
		Source:        source,
		User: &protocol.MemoryUser{
			Level: t.config.UserLevel,
		},
	}

	ctx = session.ContextWithInbound(ctx, &inbound)
	ctx = session.ContextWithContent(ctx, &session.Content{
		SniffingRequest: t.sniffingRequest,
	})
	ctx = session.SubContextFromMuxInbound(ctx)

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   inbound.Source,
		To:     destination,
		Status: log.AccessAccepted,
		Reason: "",
	})
	errors.LogInfo(ctx, "processing from ", source, " to ", destination)

	// both kinds of connection are buf.Reader and buf.Writer, what they carry is counted on the way
	var inner buf.Reader = buf.NewReader(conn)
	if flow != nil {
		inner = &activityReader{Reader: inner, flow: flow}
	}
	reader := &buf.TimeoutWrapperReader{Reader: inner, Counter: t.uplinkCounter}
	writer := buf.NewWriter(conn)
	if destination.Network != net.Network_UDP {
		writer = &TCPWriter{Writer: writer, Counter: t.downlinkCounter, Conn: conn, Flow: flow}
	} else if t.downlinkCounter != nil {
		writer = &tunUDPStatsWriter{writer: writer, counter: t.downlinkCounter}
	}

	link := &transport.Link{
		Reader: reader,
		Writer: writer,
	}
	if err := t.dispatcher.DispatchLink(ctx, destination, link); err != nil {
		errors.LogError(ctx, errors.New("connection closed").Base(err))
	}
}

// acquireSlot takes a slot of the cap for a new flow. The system's side is established and its data waits
// in the stack's window meanwhile. When no slot is free, the dispatched flow that has carried nothing for
// the longest is closed for its slot, if that is idleEvict or more: a keep-alive the application holds for
// later, which it opens again when it needs it, while a page's worth of them would otherwise sit in every
// slot for as long as the servers keep them. A flow that still gets no slot within flowWait is reset so the
// application retries instead of hanging.
func (t *Handler) acquireSlot(ctx context.Context, destination net.Destination) bool {
	select {
	case t.tcpSlots <- struct{}{}:
		return true
	default:
	}
	deadline := time.Now().Add(t.flowWait)
	evicted := 0
	for {
		if t.evictIdle(ctx) {
			evicted++
		}
		wait := time.Until(deadline)
		if wait <= 0 {
			break
		}
		if wait > time.Second {
			wait = time.Second
		}
		timer := time.NewTimer(wait)
		select {
		case t.tcpSlots <- struct{}{}:
			timer.Stop()
			return true
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return false
		}
	}
	errors.LogWarning(ctx, "no flow slot for ", destination, " within ", t.flowWait, ", ", evicted, " idle closed")
	return false
}

// evictIdle closes the dispatched flow that has carried nothing for the longest, if that is idleEvict or
// more, and says whether it did. Its slot frees when its dispatch ends on the closed connection.
func (t *Handler) evictIdle(ctx context.Context) bool {
	if t.idleEvict <= 0 {
		return false
	}
	now := time.Now().UnixNano()
	var oldest *tcpFlow
	var oldestLast int64
	t.flowsMu.Lock()
	for f := range t.flows {
		if f.closing.Load() {
			continue
		}
		if last := f.last.Load(); oldest == nil || last < oldestLast {
			oldest, oldestLast = f, last
		}
	}
	if oldest == nil || now-oldestLast < int64(t.idleEvict) {
		t.flowsMu.Unlock()
		return false
	}
	oldest.closing.Store(true)
	t.flowsMu.Unlock()
	errors.LogWarning(ctx, "closing the flow to ", oldest.dest, " idle for ", time.Duration(now-oldestLast).Round(time.Second), " for a slot")
	_ = oldest.conn.Close()
	return true
}

// Close implements common.Closable.
func (t *Handler) Close() error {
	return errors.Combine(common.CloseIfExists(t.stack), common.CloseIfExists(t.tun))
}

// Network implements proxy.Inbound
// and exists only to comply to proxy interface, declaring it doesn't listen on any network,
// making the process not open any port for this inbound (input will be network interface)
func (t *Handler) Network() []net.Network {
	return []net.Network{}
}

// Process implements proxy.Inbound
// and exists only to comply to proxy interface, which should never get any inputs due to no listening ports
func (t *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		t := &Handler{config: config.(*Config)}
		err := core.RequireFeatures(ctx, func(pm policy.Manager, dispatcher routing.Dispatcher) error {
			return t.Init(ctx, pm, dispatcher)
		})
		return t, err
	}))
}
