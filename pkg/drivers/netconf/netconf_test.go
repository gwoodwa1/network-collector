package netconf

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scrapli/scrapligo/response"
	"github.com/scrapli/scrapligo/util"
)

type fakeNETCONFSession struct {
	mu         sync.Mutex
	calls      []string
	openBlock  <-chan struct{}
	openErr    error
	readyErr   error
	closeBlock <-chan struct{}
	closeErr   error
	closePanic interface{}
	abortErr   error
	aborts     int
	result     *response.NetconfResponse
	resultErr  error
}

func (f *fakeNETCONFSession) record(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
}

func (f *fakeNETCONFSession) Open() error {
	f.record("open")
	if f.openBlock != nil {
		<-f.openBlock
	}
	return f.openErr
}

func (f *fakeNETCONFSession) Ready() error {
	f.record("ready")
	return f.readyErr
}

func (f *fakeNETCONFSession) Close() error {
	f.record("close")
	if f.closePanic != nil {
		panic(f.closePanic)
	}
	if f.closeBlock != nil {
		<-f.closeBlock
	}
	return f.closeErr
}

func (f *fakeNETCONFSession) Abort() error {
	f.record("abort")
	f.mu.Lock()
	f.aborts++
	f.mu.Unlock()
	return f.abortErr
}

func (f *fakeNETCONFSession) response(name string) (*response.NetconfResponse, error) {
	f.record(name)
	if f.result == nil {
		f.result = &response.NetconfResponse{Result: "ok"}
	}
	return f.result, f.resultErr
}

func (f *fakeNETCONFSession) RPC(...util.Option) (*response.NetconfResponse, error) {
	return f.response("rpc")
}
func (f *fakeNETCONFSession) EditConfig(target, _ string) (*response.NetconfResponse, error) {
	return f.response("edit:" + target)
}
func (f *fakeNETCONFSession) Commit(...util.Option) (*response.NetconfResponse, error) {
	return f.response("commit")
}
func (f *fakeNETCONFSession) Discard() (*response.NetconfResponse, error) {
	return f.response("discard")
}
func (f *fakeNETCONFSession) Lock(target string) (*response.NetconfResponse, error) {
	return f.response("lock:" + target)
}
func (f *fakeNETCONFSession) Unlock(target string) (*response.NetconfResponse, error) {
	return f.response("unlock:" + target)
}
func (f *fakeNETCONFSession) Validate(source string) (*response.NetconfResponse, error) {
	return f.response("validate:" + source)
}
func (f *fakeNETCONFSession) GetConfig(source string, _ ...util.Option) (*response.NetconfResponse, error) {
	return f.response("get-config:" + source)
}
func (f *fakeNETCONFSession) CopyConfig(source, target string) (*response.NetconfResponse, error) {
	return f.response("copy:" + source + ":" + target)
}
func (f *fakeNETCONFSession) DeleteConfig(target string) (*response.NetconfResponse, error) {
	return f.response("delete:" + target)
}

func TestValidationAndLifecycleErrors(t *testing.T) {
	var nilClient *ScrapligoNETCONF
	if err := nilClient.Connect("host", "user", "pass"); err == nil {
		t.Fatal("nil client connect accepted")
	}
	client := &ScrapligoNETCONF{}
	tests := []struct{ host, user, pass, want string }{{"", "user", "pass", "host is required"}, {"host", "", "pass", "username is required"}, {"host", "user", "", "password is required"}}
	for _, tc := range tests {
		if err := client.Connect(tc.host, tc.user, tc.pass); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("Connect error=%v want=%q", err, tc.want)
		}
	}
	if _, err := client.Execute("<get/>"); err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("unexpected execute error: %v", err)
	}
	if _, err := client.EditConfig("candidate", "<config/>"); err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("unexpected edit-config error: %v", err)
	}
	if _, err := client.Commit(false, 0); err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("unexpected commit error: %v", err)
	}
	if _, err := client.DiscardChanges(); err == nil || !strings.Contains(err.Error(), "not connected") {
		t.Fatalf("unexpected discard-changes error: %v", err)
	}
	operations := []struct {
		name string
		call func() error
	}{
		{name: "lock", call: func() error { _, err := client.Lock("candidate"); return err }},
		{name: "unlock", call: func() error { _, err := client.Unlock("candidate"); return err }},
		{name: "validate", call: func() error { _, err := client.Validate("candidate"); return err }},
		{name: "get-config", call: func() error { _, err := client.GetConfig("running", ""); return err }},
		{name: "copy-config", call: func() error { _, err := client.CopyConfig("running", "startup"); return err }},
		{name: "delete-config", call: func() error { _, err := client.DeleteConfig("startup"); return err }},
		{name: "cancel-commit", call: func() error { _, err := client.CancelCommit("change-1"); return err }},
	}
	for _, operation := range operations {
		if err := operation.call(); err == nil || !strings.Contains(err.Error(), "not connected") {
			t.Fatalf("unexpected %s error: %v", operation.name, err)
		}
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close disconnected client: %v", err)
	}
	if err := nilClient.Close(); err != nil {
		t.Fatalf("close nil client: %v", err)
	}
}

func TestTimeoutOptions(t *testing.T) {
	client := &ScrapligoNETCONF{}
	WithNetconfTimeouts(3*time.Second, 7*time.Second)(client)
	if client.socketTimeout != 3*time.Second || client.opsTimeout != 7*time.Second {
		t.Fatalf("timeouts not applied: socket=%s ops=%s", client.socketTimeout, client.opsTimeout)
	}
	WithNetconfTimeouts(0, 0)(client)
	if client.socketTimeout != 3*time.Second || client.opsTimeout != 7*time.Second {
		t.Fatal("non-positive timeout unexpectedly replaced values")
	}
}

func TestConnectWaitsForOpenAndReadinessBeforePublishingSession(t *testing.T) {
	releaseOpen := make(chan struct{})
	session := &fakeNETCONFSession{openBlock: releaseOpen}
	client := &ScrapligoNETCONF{
		newSession: func(string, ...util.Option) (netconfSession, error) {
			return session, nil
		},
	}
	result := make(chan error, 1)
	go func() {
		result <- client.Connect("router.example", "user", "pass", WithHostKeyPolicy("insecure", ""))
	}()
	select {
	case err := <-result:
		t.Fatalf("Connect returned before NETCONF Open completed: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	if client.network != nil {
		t.Fatal("NETCONF session was published before Open and readiness completed")
	}
	close(releaseOpen)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if client.network != session {
		t.Fatal("ready NETCONF session was not published")
	}
	if got := strings.Join(session.calls, ","); got != "open,ready" {
		t.Fatalf("connection lifecycle = %q, want open,ready", got)
	}
}

func TestConnectRejectsOpenThatReturnsBeforeSessionIsReady(t *testing.T) {
	session := &fakeNETCONFSession{readyErr: errors.New("server hello unavailable")}
	client := &ScrapligoNETCONF{
		newSession: func(string, ...util.Option) (netconfSession, error) {
			return session, nil
		},
	}
	err := client.Connect("router.example", "user", "pass", WithHostKeyPolicy("insecure", ""))
	if err == nil || !strings.Contains(err.Error(), "did not become ready") {
		t.Fatalf("unready NETCONF session was accepted: %v", err)
	}
	if client.network != nil {
		t.Fatal("unready NETCONF session was retained")
	}
	if session.aborts != 1 {
		t.Fatalf("unready NETCONF session aborts = %d, want 1", session.aborts)
	}
}

func TestCloseIsBoundedAfterDisconnectAndClearsState(t *testing.T) {
	never := make(chan struct{})
	session := &fakeNETCONFSession{closeBlock: never}
	client := &ScrapligoNETCONF{network: session, closeTimeout: 20 * time.Millisecond}
	started := time.Now()
	err := client.Close()
	close(never)
	if err == nil || !strings.Contains(err.Error(), "forcibly aborted") {
		t.Fatalf("blocked close error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("blocked NETCONF close took %s", elapsed)
	}
	if client.network != nil {
		t.Fatal("failed NETCONF close retained stale session")
	}
	if session.aborts != 1 {
		t.Fatalf("forced aborts = %d, want 1", session.aborts)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("second close was not idempotent: %v", err)
	}
}

func TestCloseRecoversDependencyPanicAndClearsState(t *testing.T) {
	session := &fakeNETCONFSession{closePanic: "double close"}
	client := &ScrapligoNETCONF{network: session, closeTimeout: time.Second}
	err := client.Close()
	if err == nil || !strings.Contains(err.Error(), "panic while closing") {
		t.Fatalf("close panic was not converted to an error: %v", err)
	}
	if client.network != nil {
		t.Fatal("panic during NETCONF close retained stale session")
	}
	if session.aborts != 1 {
		t.Fatalf("panic cleanup aborts = %d, want 1", session.aborts)
	}
}

func TestNETCONFOperationsRouteThroughReadySession(t *testing.T) {
	session := &fakeNETCONFSession{}
	client := &ScrapligoNETCONF{network: session}
	operations := []struct {
		name string
		call func() (string, error)
	}{
		{"rpc", func() (string, error) { return client.RPC("<get/>") }},
		{"edit", func() (string, error) { return client.EditConfig(" running ", "<config/>") }},
		{"commit", func() (string, error) { return client.CommitPersistent(true, 30, "persist", "persist-id") }},
		{"discard", client.DiscardChanges},
		{"lock", func() (string, error) { return client.Lock("") }},
		{"unlock", func() (string, error) { return client.Unlock("startup") }},
		{"validate", func() (string, error) { return client.Validate("running") }},
		{"get-config", func() (string, error) { return client.GetConfig("", "<filter/>") }},
		{"copy-config", func() (string, error) { return client.CopyConfig("running", "startup") }},
		{"delete-config", func() (string, error) { return client.DeleteConfig("startup") }},
		{"cancel-commit", func() (string, error) { return client.CancelCommit(`<unsafe&"' >`) }},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			got, err := operation.call()
			if err != nil || got != "ok" {
				t.Fatalf("result=%q error=%v", got, err)
			}
		})
	}
}

func TestNETCONFOperationValidationAndResponseErrors(t *testing.T) {
	session := &fakeNETCONFSession{}
	client := &ScrapligoNETCONF{network: session}
	for name, call := range map[string]func() error{
		"empty-rpc":          func() error { _, err := client.RPC(" "); return err },
		"edit-target":        func() error { _, err := client.EditConfig("startup", "<config/>"); return err },
		"negative-confirm":   func() error { _, err := client.Commit(false, -1); return err },
		"lock-datastore":     func() error { _, err := client.Lock("invalid"); return err },
		"copy-source":        func() error { _, err := client.CopyConfig("", "startup"); return err },
		"delete-datastore":   func() error { _, err := client.DeleteConfig("running"); return err },
		"validate-datastore": func() error { _, err := client.Validate("invalid"); return err },
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); err == nil {
				t.Fatal("invalid operation was accepted")
			}
		})
	}

	session.resultErr = errors.New("transport disconnected")
	if _, err := client.RPC("<get/>"); err == nil || !strings.Contains(err.Error(), "transport disconnected") {
		t.Fatalf("transport error was not preserved: %v", err)
	}
	session.resultErr = nil
	session.result = &response.NetconfResponse{Failed: errors.New("rpc-error")}
	if _, err := client.RPC("<get/>"); err == nil || !strings.Contains(err.Error(), "indicates failure") {
		t.Fatalf("NETCONF failure response was accepted: %v", err)
	}

	if _, err := normalizeDatastore("RUNNING", "", "running"); err != nil {
		t.Fatal(err)
	}
	if _, err := normalizeDatastore("bad", "", "running"); err == nil {
		t.Fatal("unsupported datastore was accepted")
	}
	if got := fmt.Sprint(client.host); got != "" {
		t.Fatalf("unexpected host mutation: %q", got)
	}
}
