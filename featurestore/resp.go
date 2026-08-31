// A tiny, dependency-free Redis/Valkey client (RESP protocol) — just the commands the
// online feature store needs: PING, HSET, HGETALL, EXPIRE. Staying on net/bufio (no
// go-redis) keeps the image a distroless static binary, like statemachine/hpo.
package main

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type redisClient struct {
	addr string
	mu   sync.Mutex
	conn net.Conn
	r    *bufio.Reader
}

func newRedis(addr string) *redisClient { return &redisClient{addr: addr} }

func (c *redisClient) connect() error {
	if c.conn != nil {
		return nil
	}
	conn, err := net.DialTimeout("tcp", c.addr, 5*time.Second)
	if err != nil {
		return err
	}
	c.conn = conn
	c.r = bufio.NewReader(conn)
	return nil
}

func (c *redisClient) reset() {
	if c.conn != nil {
		c.conn.Close()
	}
	c.conn = nil
	c.r = nil
}

// do sends one command and returns the parsed reply. On any I/O error the connection is
// reset so the next call reconnects (a one-shot retry covers a dropped idle connection).
func (c *redisClient) do(args ...string) (any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	reply, err := c.doOnce(args...)
	if err != nil {
		c.reset()
		reply, err = c.doOnce(args...)
		if err != nil {
			c.reset()
		}
	}
	return reply, err
}

func (c *redisClient) doOnce(args ...string) (any, error) {
	if err := c.connect(); err != nil {
		return nil, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := c.conn.Write([]byte(b.String())); err != nil {
		return nil, err
	}
	return readReply(c.r)
}

// readReply parses one RESP reply (simple string, error, integer, bulk string, array).
func readReply(r *bufio.Reader) (any, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if len(line) < 3 {
		return nil, fmt.Errorf("short reply %q", line)
	}
	typ := line[0]
	body := strings.TrimRight(line[1:], "\r\n")
	switch typ {
	case '+':
		return body, nil
	case '-':
		return nil, fmt.Errorf("redis: %s", body)
	case ':':
		return strconv.ParseInt(body, 10, 64)
	case '$':
		n, err := strconv.Atoi(body)
		if err != nil {
			return nil, err
		}
		if n < 0 {
			return nil, nil // nil bulk
		}
		buf := make([]byte, n+2) // include trailing CRLF
		if _, err := readFull(r, buf); err != nil {
			return nil, err
		}
		return string(buf[:n]), nil
	case '*':
		n, err := strconv.Atoi(body)
		if err != nil {
			return nil, err
		}
		if n < 0 {
			return nil, nil
		}
		arr := make([]any, n)
		for i := 0; i < n; i++ {
			arr[i], err = readReply(r)
			if err != nil {
				return nil, err
			}
		}
		return arr, nil
	}
	return nil, fmt.Errorf("unknown reply type %q", string(typ))
}

func readFull(r *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (c *redisClient) ping() error {
	_, err := c.do("PING")
	return err
}

// hset writes all fields of a hash in one call.
func (c *redisClient) hset(key string, fields map[string]string) error {
	args := []string{"HSET", key}
	for k, v := range fields {
		args = append(args, k, v)
	}
	_, err := c.do(args...)
	return err
}

// hgetall returns the hash as a map (empty map if the key is absent).
func (c *redisClient) hgetall(key string) (map[string]string, error) {
	reply, err := c.do("HGETALL", key)
	if err != nil {
		return nil, err
	}
	arr, ok := reply.([]any)
	if !ok {
		return map[string]string{}, nil
	}
	out := make(map[string]string, len(arr)/2)
	for i := 0; i+1 < len(arr); i += 2 {
		k, _ := arr[i].(string)
		v, _ := arr[i+1].(string)
		out[k] = v
	}
	return out, nil
}

func (c *redisClient) expire(key string, seconds int) error {
	_, err := c.do("EXPIRE", key, strconv.Itoa(seconds))
	return err
}
