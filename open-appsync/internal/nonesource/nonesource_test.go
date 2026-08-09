package nonesource

import (
	"context"
	"reflect"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
)

func TestNone_EchoesPayload(t *testing.T) {
	s := New()
	payload := map[string]any{"id": "1", "name": "Ada"}
	got, err := s.Execute(context.Background(), runtime.Operation{"version": "2018-05-29", "payload": payload})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, payload) {
		t.Errorf("result = %#v, want the payload %#v", got, payload)
	}
}

func TestNone_NoPayloadIsNil(t *testing.T) {
	got, err := New().Execute(context.Background(), runtime.Operation{"version": "2018-05-29"})
	if err != nil || got != nil {
		t.Errorf("no payload → (nil,nil), got (%v,%v)", got, err)
	}
}
