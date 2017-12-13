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
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const CHUNK_SIZE = 1024
const TCP_TIMEOUT = time.Second * 2

var resultRegex = regexp.MustCompile(
	`^(?P<path>[^:]+): ((?P<desc>[^:]+)(\((?P<virhash>([^:]+)):(?P<virsize>\d+)\))? )?(?P<status>FOUND|ERROR|OK)$`,
)

type Conn struct {
	net.Conn
}

func (conn *Conn) sendCommand(command string) error {
	commandBytes := []byte(fmt.Sprintf("n%s\n", command))

	_, err := conn.Write(commandBytes)
	return err
}

func (conn *Conn) sendEOF() error {
	_, err := conn.Write([]byte{0, 0, 0, 0})
	return err
}

var putUint32 = binary.BigEndian.PutUint32

func (conn *Conn) sendChunk(data []byte) error {
	var blen [4]byte
	putUint32(blen[:], uint32(len(data)))

	_, _ = conn.Write(blen[:])
	_, err := conn.Write(data)
	return err
}

func (c *Conn) readResponse() (<-chan *ScanResult, <-chan error) {
	var (
		reader = bufio.NewReader(c)
		ch     = make(chan *ScanResult)
		errCh  = make(chan error, 1)
	)
	go func() {
		var err error
		defer func() {
			close(ch)
			errCh <- err
			close(errCh)
		}()

		for {
			var line string
			if line, err = reader.ReadString('\n'); err != nil {
				if err == io.EOF {
					err = nil
				}
				return
			}
			line = strings.TrimRight(line, " \t\r\n")
			ch <- parseResult(line)
		}
	}()

	return ch, errCh
}

func parseResult(line string) *ScanResult {
	res := &ScanResult{}
	res.Raw = line

	matches := resultRegex.FindStringSubmatch(line)
	if len(matches) == 0 {
		res.Description = "Regex had no matches"
		res.Status = RES_PARSE_ERROR
		return res
	}

	for i, name := range resultRegex.SubexpNames() {
		switch name {
		case "path":
			res.Path = matches[i]
		case "desc":
			res.Description = matches[i]
		case "virhash":
			res.Hash = matches[i]
		case "virsize":
			i, err := strconv.Atoi(matches[i])
			if err == nil {
				res.Size = i
			}
		case "status":
			switch matches[i] {
			case RES_OK:
			case RES_FOUND:
			case RES_ERROR:
				break
			default:
				res.Description = "Invalid status field: " + matches[i]
				res.Status = RES_PARSE_ERROR
				return res
			}
			res.Status = matches[i]
		}
	}

	return res
}

func newCLAMDTcpConn(address string) (*Conn, error) {
	conn, err := net.DialTimeout("tcp", address, TCP_TIMEOUT)

	if err != nil {
		if nerr, isOk := err.(net.Error); isOk && nerr.Timeout() {
			return nil, nerr
		}

		return nil, err
	}

	return &Conn{Conn: conn}, err
}

func newCLAMDUnixConn(address string) (*Conn, error) {
	conn, err := net.Dial("unix", address)
	if err != nil {
		return nil, err
	}

	return &Conn{Conn: conn}, err
}
