/*
Open Source Initiative OSI - The MIT License (MIT):Licensing

The MIT License (MIT)
Copyright (c) 2013 DutchCoders <http://github.com/dutchcoders/>

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package clamd

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"
)

const (
	RES_OK          = "OK"
	RES_FOUND       = "FOUND"
	RES_ERROR       = "ERROR"
	RES_PARSE_ERROR = "PARSE ERROR"
)

type Clamd struct {
	address string

	newConnection func() (*Conn, error)
}

type Stats struct {
	Pools    string
	State    string
	Threads  string
	Memstats string
	Queue    string
}

type ScanResult struct {
	Raw         string
	Description string
	Path        string
	Hash        string
	Size        int
	Status      string
}

func (c *Clamd) simpleCommand(command string) (<-chan *ScanResult, error) {
	conn, err := c.newConnection()
	if err != nil {
		return nil, err
	}

	err = conn.sendCommand(command)
	if err != nil {
		return nil, err
	}

	ch, errCh := conn.readResponse()

	go func() {
		<-errCh
		conn.Close()
	}()

	return ch, nil
}

/*
Check the daemon's state (should reply with PONG).
*/
func (c *Clamd) Ping() error {
	ch, err := c.simpleCommand("PING")
	if err != nil {
		return err
	}

	switch s := <-ch; s.Raw {
	case "PONG":
		return nil
	default:
		return fmt.Errorf("invalid response, got %#+v.", s)
	}
}

/*
Print program and database versions.
*/
func (c *Clamd) Version() (string, error) {
	ch, err := c.simpleCommand("VERSION")
	if err != nil {
		return "", err
	}
	s := <-ch
	return s.Raw, nil
}

/*
On this command clamd provides statistics about the scan queue, contents of scan
queue, and memory usage. The exact reply format is subject to changes in future
releases.
*/
func (c *Clamd) Stats() (*Stats, error) {
	ch, err := c.simpleCommand("STATS")
	if err != nil {
		return nil, err
	}

	stats := &Stats{}

	for s := range ch {
		if strings.HasPrefix(s.Raw, "POOLS") {
			stats.Pools = strings.Trim(s.Raw[6:], " ")
		} else if strings.HasPrefix(s.Raw, "STATE") {
			stats.State = s.Raw[7:]
		} else if strings.HasPrefix(s.Raw, "THREADS") {
			stats.Threads = s.Raw[9:]
		} else if strings.HasPrefix(s.Raw, "QUEUE") {
			stats.Queue = s.Raw[7:]
		} else if strings.HasPrefix(s.Raw, "MEMSTATS") {
			stats.Memstats = s.Raw[10:]
		} else if s.Raw == "" || strings.HasPrefix(s.Raw, "END") || strings.HasPrefix(s.Raw, "\tSTATS") {
		} else {
			return nil, fmt.Errorf("invalid response, got %#+v.", s)
		}
	}

	return stats, nil
}

/*
Reload the databases.
*/
func (c *Clamd) Reload() error {
	ch, err := c.simpleCommand("RELOAD")
	if err != nil {
		return err
	}

	switch s := <-ch; s.Raw {
	case "RELOADING":
		return nil
	default:
		return fmt.Errorf("invalid response, got %#+v.", s)
	}
}

func (c *Clamd) Shutdown() error {
	_, err := c.simpleCommand("SHUTDOWN")
	return err
}

/*
Scan file or directory (recursively) with archive support enabled (a full path is
required).
*/
func (c *Clamd) ScanFile(path string) (<-chan *ScanResult, error) {
	command := fmt.Sprintf("SCAN %s", path)
	ch, err := c.simpleCommand(command)
	return ch, err
}

/*
Scan file or directory (recursively) with archive and special file support disabled
(a full path is required).
*/
func (c *Clamd) RawScanFile(path string) (<-chan *ScanResult, error) {
	command := fmt.Sprintf("RAWSCAN %s", path)
	ch, err := c.simpleCommand(command)
	return ch, err
}

/*
Scan file in a standard way or scan directory (recursively) using multiple threads
(to make the scanning faster on SMP machines).
*/
func (c *Clamd) MultiScanFile(path string) (<-chan *ScanResult, error) {
	command := fmt.Sprintf("MULTISCAN %s", path)
	ch, err := c.simpleCommand(command)
	return ch, err
}

/*
Scan file or directory (recursively) with archive support enabled and don’t stop
the scanning when a virus is found.
*/
func (c *Clamd) ContScanFile(path string) (<-chan *ScanResult, error) {
	command := fmt.Sprintf("CONTSCAN %s", path)
	ch, err := c.simpleCommand(command)
	return ch, err
}

/*
Scan file or directory (recursively) with archive support enabled and don’t stop
the scanning when a virus is found.
*/
func (c *Clamd) AllMatchScanFile(path string) (<-chan *ScanResult, error) {
	command := fmt.Sprintf("ALLMATCHSCAN %s", path)
	ch, err := c.simpleCommand(command)
	return ch, err
}

/*
Scan a stream of data. The stream is sent to clamd in chunks, after INSTREAM,
on the same socket on which the command was sent. This avoids the overhead
of establishing new TCP connections and problems with NAT. The format of the
chunk is: <length><data> where <length> is the size of the following data in
bytes expressed as a 4 byte unsigned integer in network byte order and <data> is
the actual chunk. Streaming is terminated by sending a zero-length chunk. Note:
do not exceed StreamMaxLength as defined in clamd.conf, otherwise clamd will
reply with INSTREAM size limit exceeded and close the connection
*/
func (c *Clamd) ScanStream(ctx context.Context, r io.Reader) (<-chan *ScanResult, error) {
	conn, err := c.newConnection()
	if err != nil {
		return nil, err
	}

	conn.sendCommand("INSTREAM")

	for {
		buf := make([]byte, CHUNK_SIZE)

		n, err := r.Read(buf)
		if n > 0 {
			if err = conn.sendChunk(buf[:n]); err != nil {
				break
			}
		}
		if err != nil {
			break
		}

	}

	err = conn.sendEOF()
	if err != nil {
		return nil, err
	}

	ch, errCh := conn.readResponse()

	go func() {
		select {
		case <-errCh:
		case <-ctx.Done():
		}
		conn.Close()
	}()

	return ch, err
}

func NewClamd(addr string) (*Clamd, error) {
	if strings.HasPrefix(addr, "/") {
		addr = "unix:" + addr
	}
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}

	clamd := &Clamd{address: addr}

	switch u.Scheme {
	case "tcp":
		clamd.newConnection = func() (*Conn, error) { return newCLAMDTcpConn(u.Host) }
	case "unix":
		clamd.newConnection = func() (*Conn, error) { return newCLAMDUnixConn(u.Path) }
	default:
		clamd.newConnection = func() (*Conn, error) { return newCLAMDUnixConn(addr) }
	}

	return clamd, nil
}
