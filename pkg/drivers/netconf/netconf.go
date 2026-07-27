package netconf

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/drivers"
	"github.com/gwoodwa1/network-collector/pkg/drivers/hostkey"
	"github.com/scrapli/scrapligo/driver/netconf"
	"github.com/scrapli/scrapligo/driver/opoptions"
	scraplioptions "github.com/scrapli/scrapligo/driver/options"
	"github.com/scrapli/scrapligo/response"
	"github.com/scrapli/scrapligo/util"
)

type Option = drivers.Option

type ScrapligoNETCONF struct {
	host          string
	network       *netconf.Driver
	socketTimeout time.Duration
	opsTimeout    time.Duration
	hostKeyPolicy hostkey.Policy
	hostKeyError  error
}

func WithNetconfTimeouts(socketTimeout, opsTimeout time.Duration) Option {
	return func(d interface{}) {
		if socketTimeout <= 0 && opsTimeout <= 0 {
			return
		}
		if device, ok := d.(*ScrapligoNETCONF); ok {
			if socketTimeout > 0 {
				device.socketTimeout = socketTimeout
			}
			if opsTimeout > 0 {
				device.opsTimeout = opsTimeout
			}
		}
	}
}

func WithHostKeyPolicy(policy, knownHostsFile string) Option {
	return func(d interface{}) {
		device, ok := d.(*ScrapligoNETCONF)
		if !ok || device == nil {
			return
		}
		device.hostKeyPolicy, device.hostKeyError = hostkey.New(policy, knownHostsFile)
	}
}

func (n *ScrapligoNETCONF) Connect(host, username, password string, opts ...Option) error {
	if n == nil {
		return errors.New("NETCONF client is nil")
	}
	if strings.TrimSpace(host) == "" {
		return errors.New("host is required")
	}
	if strings.TrimSpace(username) == "" {
		return errors.New("username is required")
	}
	if strings.TrimSpace(password) == "" {
		return errors.New("password is required")
	}

	n.host = strings.TrimSpace(host)

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(n)
	}
	if n.hostKeyError != nil {
		return n.hostKeyError
	}
	if n.hostKeyPolicy == nil {
		n.hostKeyPolicy, n.hostKeyError = hostkey.New("", "")
		if n.hostKeyError != nil {
			return n.hostKeyError
		}
	}
	if n.hostKeyPolicy.Name() == "insecure" {
		slog.Warn("NETCONF SSH host-key verification is disabled; use only for explicitly approved lab devices", "host", n.host)
	}

	options := []util.Option{
		scraplioptions.WithAuthUsername(username),
		scraplioptions.WithAuthPassword(password),
		scraplioptions.WithPort(830),
	}
	options, err := n.hostKeyPolicy.Apply(options)
	if err != nil {
		return err
	}
	if n.socketTimeout > 0 {
		options = append(options, scraplioptions.WithTimeoutSocket(n.socketTimeout))
	}
	if n.opsTimeout > 0 {
		options = append(options, scraplioptions.WithTimeoutOps(n.opsTimeout))
	}

	d, err := netconf.NewDriver(n.host, options...)
	if err != nil {
		return fmt.Errorf("failed to create NETCONF driver: %w", err)
	}

	if err := d.Open(); err != nil {
		return fmt.Errorf("failed to open NETCONF driver: %w", err)
	}

	n.network = d
	return nil
}

func (n *ScrapligoNETCONF) Execute(cmd string) (string, error) {
	return n.RPC(cmd)
}

func (n *ScrapligoNETCONF) ready(payloadRequired bool, payload string) error {
	if n == nil {
		return errors.New("NETCONF client is nil")
	}
	if n.network == nil {
		return errors.New("NETCONF client is not connected")
	}
	if payloadRequired && strings.TrimSpace(payload) == "" {
		return errors.New("NETCONF payload is required")
	}
	return nil
}

func netconfResult(operation string, r *response.NetconfResponse, err error) (string, error) {
	if err != nil {
		return "", fmt.Errorf("failed to execute NETCONF %s: %w", operation, err)
	}
	if r.Failed != nil {
		return "", fmt.Errorf("NETCONF %s response indicates failure: %+v", operation, r.Failed)
	}
	return r.Result, nil
}

func (n *ScrapligoNETCONF) RPC(payload string) (string, error) {
	if err := n.ready(true, payload); err != nil {
		return "", err
	}
	response, err := n.network.RPC(opoptions.WithFilter(payload))
	return netconfResult("RPC", response, err)
}

func (n *ScrapligoNETCONF) EditConfig(target, payload string) (string, error) {
	if err := n.ready(true, payload); err != nil {
		return "", err
	}
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		target = "candidate"
	}
	switch target {
	case "candidate", "running":
	default:
		return "", fmt.Errorf("unsupported NETCONF edit-config target %q", target)
	}
	response, err := n.network.EditConfig(target, payload)
	return netconfResult("edit-config", response, err)
}

func (n *ScrapligoNETCONF) Commit(confirmed bool, confirmTimeoutSeconds int) (string, error) {
	return n.CommitPersistent(confirmed, confirmTimeoutSeconds, "", "")
}

func (n *ScrapligoNETCONF) CommitPersistent(confirmed bool, confirmTimeoutSeconds int, persist, persistID string) (string, error) {
	if err := n.ready(false, ""); err != nil {
		return "", err
	}
	if confirmTimeoutSeconds < 0 {
		return "", errors.New("NETCONF commit confirm timeout must be greater than or equal to 0")
	}
	options := []util.Option{}
	if confirmed {
		options = append(options, opoptions.WithCommitConfirmed())
	}
	if confirmTimeoutSeconds > 0 {
		options = append(options, opoptions.WithCommitConfirmTimeout(uint(confirmTimeoutSeconds)))
	}
	if persist != "" {
		options = append(options, opoptions.WithCommitConfirmedPersist(persist))
	}
	if persistID != "" {
		options = append(options, opoptions.WithCommitConfirmedPersistID(persistID))
	}
	response, err := n.network.Commit(options...)
	return netconfResult("commit", response, err)
}

func (n *ScrapligoNETCONF) DiscardChanges() (string, error) {
	if err := n.ready(false, ""); err != nil {
		return "", err
	}
	response, err := n.network.Discard()
	return netconfResult("discard-changes", response, err)
}

func (n *ScrapligoNETCONF) Lock(target string) (string, error) {
	if err := n.ready(false, ""); err != nil {
		return "", err
	}
	target, err := normalizeDatastore(target, "candidate", "candidate", "running", "startup")
	if err != nil {
		return "", err
	}
	response, err := n.network.Lock(target)
	return netconfResult("lock", response, err)
}

func (n *ScrapligoNETCONF) Unlock(target string) (string, error) {
	if err := n.ready(false, ""); err != nil {
		return "", err
	}
	target, err := normalizeDatastore(target, "candidate", "candidate", "running", "startup")
	if err != nil {
		return "", err
	}
	response, err := n.network.Unlock(target)
	return netconfResult("unlock", response, err)
}

func (n *ScrapligoNETCONF) Validate(source string) (string, error) {
	if err := n.ready(false, ""); err != nil {
		return "", err
	}
	source, err := normalizeDatastore(source, "candidate", "candidate", "running", "startup")
	if err != nil {
		return "", err
	}
	response, err := n.network.Validate(source)
	return netconfResult("validate", response, err)
}

func (n *ScrapligoNETCONF) GetConfig(source, filter string) (string, error) {
	if err := n.ready(false, ""); err != nil {
		return "", err
	}
	source, err := normalizeDatastore(source, "running", "running", "candidate", "startup")
	if err != nil {
		return "", err
	}
	options := []util.Option{}
	if strings.TrimSpace(filter) != "" {
		options = append(options, opoptions.WithFilter(filter))
	}
	response, err := n.network.GetConfig(source, options...)
	return netconfResult("get-config", response, err)
}

func (n *ScrapligoNETCONF) CopyConfig(source, target string) (string, error) {
	if err := n.ready(false, ""); err != nil {
		return "", err
	}
	source, err := normalizeDatastore(source, "", "running", "candidate", "startup")
	if err != nil {
		return "", err
	}
	target, err = normalizeDatastore(target, "", "running", "candidate", "startup")
	if err != nil {
		return "", err
	}
	response, err := n.network.CopyConfig(source, target)
	return netconfResult("copy-config", response, err)
}

func (n *ScrapligoNETCONF) DeleteConfig(target string) (string, error) {
	if err := n.ready(false, ""); err != nil {
		return "", err
	}
	target, err := normalizeDatastore(target, "", "startup")
	if err != nil {
		return "", err
	}
	response, err := n.network.DeleteConfig(target)
	return netconfResult("delete-config", response, err)
}

func (n *ScrapligoNETCONF) CancelCommit(persistID string) (string, error) {
	var payload string
	if strings.TrimSpace(persistID) == "" {
		payload = `<cancel-commit xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"/>`
	} else {
		var escaped bytes.Buffer
		if err := xml.EscapeText(&escaped, []byte(persistID)); err != nil {
			return "", err
		}
		payload = `<cancel-commit xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><persist-id>` + escaped.String() + `</persist-id></cancel-commit>`
	}
	return n.RPC(payload)
}

func normalizeDatastore(value, fallback string, allowed ...string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		value = fallback
	}
	for _, candidate := range allowed {
		if value == candidate {
			return value, nil
		}
	}
	return "", fmt.Errorf("unsupported NETCONF datastore %q", value)
}

func (n *ScrapligoNETCONF) Close() error {
	if n == nil || n.network == nil {
		return nil
	}
	if err := n.network.Close(); err != nil {
		return fmt.Errorf("failed to close NETCONF client: %w", err)
	}
	return nil
}
