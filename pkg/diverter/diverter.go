package diverter

import (
	"errors"
	"sync"

	"github.com/gone-lib/go-windivert/pkg/ffi"
	"golang.org/x/sys/windows"
)

type Diverter struct {
	sendChan chan *ffi.Packet
	recvChan chan *ffi.Packet

	l      *ffi.LibraryReference
	c      *Config
	handle uintptr
	params map[ffi.Param]uint64

	openOnce sync.Once
	routines sync.WaitGroup
	critical sync.Mutex
	started  bool // if a valid handle is available
}

func New(config *Config) (ret *Diverter, err error) {
	config.fixMissingValue()

	ret = &Diverter{
		c:       config,
		handle:  uintptr(windows.InvalidHandle),
		params:  map[ffi.Param]uint64{},
		started: false,
	}
	ret.l, err = ffi.NewDLLReference(ret.c.DLLPath)

	return
}

func (d *Diverter) LibraryReference() *ffi.LibraryReference {
	return d.l
}

func (d *Diverter) Handle() uintptr {
	return d.handle
}

func (d *Diverter) SendChan() chan<- *ffi.Packet {
	return d.sendChan
}

func (d *Diverter) RecvChan() <-chan *ffi.Packet {
	return d.recvChan
}

func (d *Diverter) sendLoop() (err error) {
	d.routines.Add(1)
	defer d.routines.Done()

	for pkt := range d.sendChan {
		_, err = d.l.Send(d.handle, pkt)
		if err != nil {
			break
		}
	}

	if err != nil {
		return
	}

	err = d.l.Shutdown(d.handle, ffi.Send)
	return
}

func (d *Diverter) receiveLoop() (err error) {
	d.routines.Add(1)
	defer d.routines.Done()

	var pkt *ffi.Packet
	for {
		pkt, err = d.l.Recv(d.handle, d.c.ReceiveBufferSize)
		if err != nil {
			break
		}

		d.recvChan <- pkt
	}

	close(d.recvChan)
	if err != nil {
		if errors.Is(err, windows.ERROR_NO_DATA) { // d.l.Shutdown called elsewhere
			return nil
		}

		return
	}

	err = d.l.Shutdown(d.handle, ffi.Recv)
	return
}

// Start executes the event loop in a new goroutine and returns immediately
func (d *Diverter) Start() (err error) {
	d.critical.Lock()
	defer d.critical.Unlock()

	d.routines.Add(1)
	defer d.routines.Done()

	d.sendChan = make(chan *ffi.Packet, d.c.SendChanSize)
	d.recvChan = make(chan *ffi.Packet, d.c.RecvChanSize)

	d.handle, err = d.l.Open(d.c.Filter, d.c.Layer, d.c.Priority, d.c.Flag)
	if errors.Is(err, windows.ERROR_SUCCESS) {
		err = nil
	}
	if err != nil {
		return
	}

	for k, v := range d.params {
		err = d.l.SetParam(d.handle, k, v)
		if err != nil {
			return
		}
	}

	go func() {
		_ = d.receiveLoop()
	}()

	go func() {
		_ = d.sendLoop()
	}()

	d.started = true

	return
}

// Stop gracefully stops the WinDivert session, giving the program time to drain the queue.
func (d *Diverter) Stop() (err error) {
	d.critical.Lock()
	defer d.critical.Unlock()

	// stop new packets from being queued into the send channel
	close(d.sendChan)

	// stop new packets from being received
	err = d.l.Shutdown(d.handle, ffi.Recv)
	if err != nil {
		return
	}

	// wait for queue to be drained
	d.routines.Wait()

	d.started = false

	// shutdown
	_ = d.l.Shutdown(d.handle, ffi.Both)
	err = d.Terminate()
	return
}

// Terminate stops the WinDivert session abruptly, causing all packets in the queue to be discarded immediately.
func (d *Diverter) Terminate() (err error) {
	d.started = false
	err = d.l.Close(d.handle)
	return
}
