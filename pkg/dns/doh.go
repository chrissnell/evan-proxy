package dns

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type dohClient struct {
	url    string
	client *http.Client
}

func newDoH(serverURL string) (*Resolver, error) {
	if serverURL == "" {
		return nil, fmt.Errorf("DoH server URL required")
	}
	c := &dohClient{
		url: serverURL,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
	return &Resolver{doh: c}, nil
}

func (c *dohClient) lookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		return nil, fmt.Errorf("invalid hostname %q: %w", host, err)
	}

	type result struct {
		addrs []net.IPAddr
		err   error
	}
	ch := make(chan result, 2)

	// Query A and AAAA in parallel.
	for _, qtype := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		go func(qt dnsmessage.Type) {
			addrs, err := c.query(ctx, name, qt)
			ch <- result{addrs, err}
		}(qtype)
	}

	var all []net.IPAddr
	var firstErr error
	for range 2 {
		r := <-ch
		if r.err != nil && firstErr == nil {
			firstErr = r.err
		}
		all = append(all, r.addrs...)
	}
	if len(all) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return all, nil
}

func (c *dohClient) query(ctx context.Context, name dnsmessage.Name, qtype dnsmessage.Type) ([]net.IPAddr, error) {
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  qtype,
			Class: dnsmessage.ClassINET,
		}},
	}
	packed, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.url, bytes.NewReader(packed))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var parser dnsmessage.Parser
	if _, err := parser.Start(body); err != nil {
		return nil, err
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return nil, err
	}

	var addrs []net.IPAddr
	for {
		h, err := parser.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, err
		}
		switch h.Type {
		case dnsmessage.TypeA:
			a, err := parser.AResource()
			if err != nil {
				return nil, err
			}
			addrs = append(addrs, net.IPAddr{IP: net.IP(a.A[:])})
		case dnsmessage.TypeAAAA:
			a, err := parser.AAAAResource()
			if err != nil {
				return nil, err
			}
			addrs = append(addrs, net.IPAddr{IP: net.IP(a.AAAA[:])})
		default:
			if err := parser.SkipAnswer(); err != nil {
				return nil, err
			}
		}
	}
	return addrs, nil
}
