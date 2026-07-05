package gnmi

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/gnmic/pkg/api/target"
	"google.golang.org/grpc"
)

type testGNMIServer struct {
	gnmipb.UnimplementedGNMIServer
	t *testing.T
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
	return &gnmipb.GetResponse{Notification: []*gnmipb.Notification{{Timestamp: 1, Update: []*gnmipb.Update{{Path: request.Path[0], Val: &gnmipb.TypedValue{Value: &gnmipb.TypedValue_StringVal{StringVal: "interface-up"}}}}}}}, nil
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
}
