// Albert Espín 2020 MIT
// +build !windows,!plan9

package goggler

import (
	"bytes"
	"errors"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/crewjam/rfc5424"
	"github.com/prometheus/common/log"
)

// A Writer is a connection to a syslog server.
type Writer struct {
	priority rfc5424.Priority
	network  string
	raddr    string
	hostname string
	appname  string
	mu       sync.Mutex // guards conn
	conn     net.Conn
}

// Dial establishes a connection to a log daemon by connecting to
// address raddr on the specified network. Each write to the returned
// writer sends a log message with the facility and severity
// (from priority) and tag. If tag is empty, the os.Args[0] is used.
// If network is empty, Dial will connect to the local syslog server.
// Otherwise, see the documentation for net.Dial for valid values
// of network and raddr.
func Dial(network, raddr, appname string, p rfc5424.Priority) (*Writer, error) {
	// check for valid priority
	if p < 0 || p > rfc5424.Local7|rfc5424.Debug {
		return nil, errors.New("log/syslog: invalid priority")
	}
	// if network is empty udp
	if network == "" {
		network = "udp"
	}
	// if appname is empty os.Args[0]
	if appname == "" {
		appname = os.Args[0]
	}
	// if appname is empty os.Args[0]
	if raddr == "" {
		return nil, errors.New("syslog server address is needed")
	}
	// create a writer
	w := new(Writer)
	// locking
	w.mu.Lock()
	defer w.mu.Unlock()
	w.raddr = raddr
	w.priority = p
	w.hostname, _ = os.Hostname()
	w.appname = appname
	w.network = network
	// connection
	err := w.connect()
	if err != nil {
		return nil, err
	}
	return w, err
}

// Close closes a connection to the syslog daemon.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.conn != nil {
		err := w.conn.Close()
		w.conn = nil
		return err
	}
	return nil
}

// Write sends a log message to the syslog daemon.
func (w *Writer) Write(b []byte) (int, error) {
	return w.writeAndRetry(w.priority, string(b))
}

// write generates and writes a syslog formatted string.
func (w *Writer) write(p rfc5424.Priority, msg string) (int, error) {
	// bytes holder
	var b []byte
	// creates a syslog RFC5424 message
	logMsg := new(rfc5424.Message)
	logMsg.Priority = p
	logMsg.Timestamp = time.Now()
	logMsg.Hostname = w.hostname
	logMsg.AppName = w.appname
	logMsg.ProcessID = strconv.Itoa(os.Getpid())
	logMsg.MessageID = ""
	logMsg.StructuredData = []rfc5424.StructuredData{}
	logMsg.Message = []byte(msg)
	// buffer
	buf := bytes.NewBuffer(b)
	// writes message
	logMsg.WriteTo(buf)
	log.Infof("syslog message content: %s", buf.String())
	// writer
	res, err := logMsg.WriteTo(w.conn)
	return int(res), err
}

func (w *Writer) writeAndRetry(p rfc5424.Priority, s string) (int, error) {
	pr := w.priority | p
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.conn != nil {
		if n, err := w.write(pr, s); err == nil {
			return n, err
		}
	}
	if err := w.connect(); err == nil {
		return 0, err
	}
	return w.write(pr, s)
}

func (w *Writer) connect() (err error) {
	var c net.Conn
	if w.conn != nil {
		// ignore err from close, it makes sense to continue anyway
		w.conn.Close()
		w.conn = nil
	}
	c, err = net.Dial(w.network, w.raddr)
	if err == nil {
		w.conn = c
	}
	return
}

// Emerg logs a message with severity LOG_EMERG
func (w *Writer) Emerg(m string) error {
	_, err := w.writeAndRetry(rfc5424.Emergency, m)
	return err
}

// Alert logs a message with severity LOG_ALERT
func (w *Writer) Alert(m string) error {
	_, err := w.writeAndRetry(rfc5424.Alert, m)
	return err
}

// Crit logs a message with severity LOG_CRIT
func (w *Writer) Crit(m string) error {
	_, err := w.writeAndRetry(rfc5424.Crit, m)
	return err
}

// Err logs a message with severity LOG_ERR
func (w *Writer) Err(m string) error {
	_, err := w.writeAndRetry(rfc5424.Error, m)
	return err
}

// Warning logs a message with severity LOG_WARNING
func (w *Writer) Warning(m string) error {
	_, err := w.writeAndRetry(rfc5424.Warning, m)
	return err
}

// Notice logs a message with severity LOG_NOTICE
func (w *Writer) Notice(m string) error {
	_, err := w.writeAndRetry(rfc5424.Notice, m)
	return err
}

// Info logs a message with severity LOG_INFO
func (w *Writer) Info(m string) error {
	_, err := w.writeAndRetry(rfc5424.Info, m)
	return err
}

// Debug logs a message with severity LOG_DEBUG
func (w *Writer) Debug(m string) error {
	_, err := w.writeAndRetry(rfc5424.Debug, m)
	return err
}
