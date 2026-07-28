package gnmi

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/gnmic/pkg/api/path"
	"github.com/openconfig/gnmic/pkg/api/target"
	"google.golang.org/grpc"
)

type testGNMIServer struct {
	gnmipb.UnimplementedGNMIServer
	t             *testing.T
	responseValue string
}

type oversizedSubscriptionServer struct {
	gnmipb.UnimplementedGNMIServer
	canceled chan struct{}
}

type budgetBreachSubscriptionServer struct {
	gnmipb.UnimplementedGNMIServer
	canceled chan struct{}
}

func (s *oversizedSubscriptionServer) Subscribe(stream gnmipb.GNMI_SubscribeServer) error {
	if _, err := stream.Recv(); err != nil {
		return err
	}
	response := &gnmipb.SubscribeResponse{
		Response: &gnmipb.SubscribeResponse_Update{
			Update: &gnmipb.Notification{Update: []*gnmipb.Update{{
				Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{
					StringVal: strings.Repeat("x", MaxGRPCReceiveMessageBytes+1),
				}},
			}}},
		},
	}
	if err := stream.Send(response); err != nil {
		close(s.canceled)
		return err
	}
	<-stream.Context().Done()
	close(s.canceled)
	return stream.Context().Err()
}

func (s *budgetBreachSubscriptionServer) Subscribe(stream gnmipb.GNMI_SubscribeServer) error {
	if _, err := stream.Recv(); err != nil {
		return err
	}
	response := &gnmipb.SubscribeResponse{
		Response: &gnmipb.SubscribeResponse_Update{
			Update: &gnmipb.Notification{Update: []*gnmipb.Update{{
				Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: "up"}},
			}}},
		},
	}
	if err := stream.Send(response); err != nil {
		return err
	}
	<-stream.Context().Done()
	close(s.canceled)
	return stream.Context().Err()
}

func (s *testGNMIServer) Subscribe(stream gnmipb.GNMI_SubscribeServer) error {
	request, err := stream.Recv()
	if err != nil {
		return err
	}
	if len(request.GetSubscribe().GetSubscription()) == 0 {
		s.t.Error("subscription has no paths")
	}
	if err := stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_Update{Update: &gnmipb.Notification{Timestamp: 2, Update: []*gnmipb.Update{{Path: request.GetSubscribe().GetSubscription()[0].Path, Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: "UP"}}}}}}}); err != nil {
		return err
	}
	return stream.Send(&gnmipb.SubscribeResponse{Response: &gnmipb.SubscribeResponse_SyncResponse{SyncResponse: true}})
}

func (s *testGNMIServer) Get(_ context.Context, request *gnmipb.GetRequest) (*gnmipb.GetResponse, error) {
	if len(request.Path) != 1 {
		s.t.Errorf("unexpected paths: %+v", request.Path)
	}
	value := s.responseValue
	if value == "" {
		value = "interface-up"
	}
	return &gnmipb.GetResponse{Notification: []*gnmipb.Notification{{Timestamp: 1, Update: []*gnmipb.Update{{Path: request.Path[0], Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: value}}}}}}}, nil
}

func TestConnectExecuteCloseAgainstLocalServer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	gnmipb.RegisterGNMIServer(server, &testGNMIServer{t: t})
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	client := &GNMIClient{}
	if err := client.Connect(listener.Addr().String(), "admin", "secret", WithSkipTLS(), WithRequestTimeout(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	output, err := client.Execute("/interfaces/interface[name=Loopback0]/state/oper-status")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "interface-up") {
		t.Fatalf("unexpected gNMI output: %s", output)
	}
	subscriptionOutput, err := client.Subscribe(context.Background(), Subscription{Paths: []string{"/interfaces/interface[name=Loopback0]/state/oper-status"}, Mode: "once"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(subscriptionOutput, "UP") || !strings.Contains(subscriptionOutput, "sync-response") {
		t.Fatalf("unexpected subscription output: %s", subscriptionOutput)
	}
	if _, err := client.Subscribe(context.Background(), Subscription{
		Paths: []string{"/interfaces/interface[name=Loopback0]/state/oper-status"},
		Mode:  "once", MaxResponseBytes: 1,
	}); err == nil || !strings.Contains(err.Error(), "aggregate response limit") {
		t.Fatalf("aggregate response budget was not enforced: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestValidationErrors(t *testing.T) {
	client := &GNMIClient{}
	if err := client.Connect("", "user", "pass"); err == nil {
		t.Fatal("empty address accepted")
	}
	if _, err := client.Execute("/interfaces"); err == nil {
		t.Fatal("execute before connect accepted")
	}
	client.target = &target.Target{}
	if _, err := client.Subscribe(context.Background(), Subscription{Paths: []string{"/interfaces"}, Mode: "stream"}); err == nil {
		t.Fatal("unbounded stream accepted")
	}
	if _, err := client.Subscribe(context.Background(), Subscription{
		Paths: []string{"/interfaces"}, Mode: "once", SampleInterval: -time.Second,
	}); err == nil {
		t.Fatal("negative sample interval accepted")
	}
	for _, config := range []Subscription{
		{Paths: []string{"/interfaces"}, Mode: "stream", Duration: MaxSubscriptionDuration + time.Second},
		{Paths: []string{"/interfaces"}, Mode: "stream", MaxUpdates: MaxSubscriptionUpdates + 1},
		{Paths: []string{"/interfaces"}, Mode: "once", MaxResponseBytes: MaxSubscriptionResponseBytes + 1},
		{Paths: []string{"/interfaces"}, Mode: "once", MaxResponseCount: MaxSubscriptionResponses + 1},
	} {
		if _, err := client.Subscribe(context.Background(), config); err == nil {
			t.Fatalf("oversized subscription budget accepted: %+v", config)
		}
	}
}

func TestGetRejectsResponseAtGRPCReceiveBoundary(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	gnmipb.RegisterGNMIServer(server, &testGNMIServer{
		t:             t,
		responseValue: strings.Repeat("x", MaxGRPCReceiveMessageBytes+1),
	})
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()

	client := &GNMIClient{}
	if err := client.Connect(listener.Addr().String(), "admin", "secret", WithSkipTLS(), WithRequestTimeout(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Execute("/interfaces"); err == nil || !strings.Contains(err.Error(), "larger than max") {
		t.Fatalf("oversized gRPC response was not rejected at receive boundary: %v", err)
	}
}

func TestOversizedSubscriptionCancelsGRPCStream(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	canceled := make(chan struct{})
	server := grpc.NewServer()
	gnmipb.RegisterGNMIServer(server, &oversizedSubscriptionServer{canceled: canceled})
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()

	client := &GNMIClient{}
	if err := client.Connect(listener.Addr().String(), "admin", "secret", WithSkipTLS(), WithRequestTimeout(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, err = client.Subscribe(context.Background(), Subscription{Paths: []string{"/interfaces"}, Mode: "once"})
	if err == nil || !strings.Contains(err.Error(), "larger than max") {
		t.Fatalf("oversized subscription response was not rejected at receive boundary: %v", err)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("oversized subscription did not cancel the gRPC stream")
	}
}

func TestAggregateBudgetCancelsStreamWithDeadlinedParent(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	canceled := make(chan struct{})
	server := grpc.NewServer()
	gnmipb.RegisterGNMIServer(server, &budgetBreachSubscriptionServer{canceled: canceled})
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()

	client := &GNMIClient{}
	if err := client.Connect(listener.Addr().String(), "admin", "secret", WithSkipTLS(), WithRequestTimeout(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	parent, parentCancel := context.WithTimeout(context.Background(), time.Minute)
	defer parentCancel()
	_, err = client.SubscribeEvents(parent, Subscription{
		Paths:            []string{"/interfaces"},
		Mode:             "once",
		MaxResponseBytes: 1,
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "aggregate response limit") {
		t.Fatalf("aggregate response budget was not enforced: %v", err)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("budget rejection did not cancel a stream whose parent already had a deadline")
	}
}

func TestNotificationEventsIncludeFullPathsAndDeletes(t *testing.T) {
	prefix := &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: "interfaces"}, {Name: "interface", Key: map[string]string{"name": "Ethernet1"}}}}
	notification := &gnmipb.Notification{
		Timestamp: 42,
		Prefix:    prefix,
		Update: []*gnmipb.Update{{
			Path: &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: "state"}, {Name: "oper-status"}}},
			Val:  &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: "UP"}},
		}},
		Delete: []*gnmipb.Path{{Elem: []*gnmipb.PathElem{{Name: "subinterfaces"}, {Name: "subinterface", Key: map[string]string{"index": "100"}}}}},
	}
	var events []Event
	if err := handleNotification(notification, true, func(event Event) error {
		events = append(events, event)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	if events[0].Type != "update" || events[0].Path != "/interfaces/interface[name=Ethernet1]/state/oper-status" || events[0].Value != "UP" || !events[0].Initial {
		t.Fatalf("unexpected update event: %+v", events[0])
	}
	if events[1].Type != "delete" || events[1].Path != "/interfaces/interface[name=Ethernet1]/subinterfaces/subinterface[index=100]" {
		t.Fatalf("unexpected delete event: %+v", events[1])
	}
}

func TestTLSOptionsKeepPlaintextAndSkipVerifySeparate(t *testing.T) {
	client := &GNMIClient{}
	WithInsecure(true)(client)
	WithSkipVerify(false)(client)
	WithTLSCredentials("ca.pem", "client.pem", "client-key.pem", "router.example.net")(client)
	if !client.Insecure || client.SkipVerify {
		t.Fatalf("unexpected security flags: %+v", client.TLSConfig)
	}
	if client.CAFile != "ca.pem" || client.CertFile != "client.pem" || client.KeyFile != "client-key.pem" || client.ServerName != "router.example.net" {
		t.Fatalf("unexpected TLS credentials: %+v", client.TLSConfig)
	}
}

func TestWildcardOpticalSubscriptionPathsParse(t *testing.T) {
	for _, value := range []string{
		"/components/component[name=*]/transceiver/physical-channels/channel[index=*]/state/input-power/instant",
		"/components/component[name=*]/transceiver/physical-channels/channel[index=*]/state/output-power/instant",
	} {
		if _, err := path.ParsePath(value); err != nil {
			t.Fatalf("failed to parse wildcard optical path %q: %v", value, err)
		}
	}
}

func TestWildcardRoutingNeighborSubscriptionPathsParse(t *testing.T) {
	for _, value := range []string{
		"/network-instances/network-instance[name=*]/protocols/protocol[identifier=ISIS][name=*]/isis/interfaces/interface[interface-id=*]/levels/level[level-number=*]/adjacencies/adjacency[system-id=*]/state/adjacency-state",
		"/network-instances/network-instance[name=*]/mpls/signaling-protocols/ldp/neighbors/neighbor[lsr-id=*][label-space-id=*]/state/session-state",
		"/network-instances/network-instance[name=*]/protocols/protocol[identifier=BGP][name=*]/bgp/neighbors/neighbor[neighbor-address=*]/state/session-state",
	} {
		if _, err := path.ParsePath(value); err != nil {
			t.Fatalf("failed to parse wildcard routing-neighbor path %q: %v", value, err)
		}
	}
}
