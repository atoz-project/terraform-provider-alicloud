package alicloud

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func saeTestApplicationInstance(id, status, health, ip string) saeApplicationInstance {
	return saeApplicationInstance{
		GroupId:         "group-1",
		InstanceId:      id,
		ContainerStatus: status,
		HealthStatus:    health,
		ContainerIp:     ip,
	}
}

func TestUnitAlicloudSaeApplicationInstancesEvaluation(t *testing.T) {
	ready := func(id, ip string) saeApplicationInstance {
		return saeTestApplicationInstance(id, "Running", "Healthy", ip)
	}

	tests := []struct {
		name      string
		expected  int
		desired   int
		instances []saeApplicationInstance
		wantReady bool
		wantHard  bool
		wantIps   []string
		reasonHas []string
	}{
		{
			name:      "healthy full set returns sorted unique ips",
			expected:  2,
			desired:   2,
			instances: []saeApplicationInstance{ready("i-2", "172.25.2.146"), ready("i-1", "172.25.2.145")},
			wantReady: true,
			wantIps:   []string{"172.25.2.145", "172.25.2.146"},
		},
		{
			name:     "instances duplicated across overlapping pages are deduplicated",
			expected: 2,
			desired:  2,
			instances: []saeApplicationInstance{
				ready("i-1", "172.25.2.145"), ready("i-2", "172.25.2.146"),
				ready("i-1", "172.25.2.145"),
			},
			wantReady: true,
			wantIps:   []string{"172.25.2.145", "172.25.2.146"},
		},
		{
			name:      "partial page: fewer observed instances than expected is not ready",
			expected:  3,
			desired:   3,
			instances: []saeApplicationInstance{ready("i-1", "172.25.2.145"), ready("i-2", "172.25.2.146")},
			wantReady: false,
			wantHard:  false,
			reasonHas: []string{"2", "3"},
		},
		{
			name:      "unhealthy instance is not ready",
			expected:  2,
			desired:   2,
			instances: []saeApplicationInstance{ready("i-1", "172.25.2.145"), saeTestApplicationInstance("i-2", "Running", "Unhealthy", "172.25.2.146")},
			wantReady: false,
			wantHard:  false,
			reasonHas: []string{"i-2", `health status is "Unhealthy"`},
		},
		{
			name:      "not running instance is not ready",
			expected:  2,
			desired:   2,
			instances: []saeApplicationInstance{ready("i-1", "172.25.2.145"), saeTestApplicationInstance("i-2", "Pending", "", "")},
			wantReady: false,
			wantHard:  false,
			reasonHas: []string{"i-2", `container status is "Pending"`},
		},
		{
			name:      "running healthy instance without IP is not ready",
			expected:  2,
			desired:   2,
			instances: []saeApplicationInstance{ready("i-1", "172.25.2.145"), saeTestApplicationInstance("i-2", "Running", "Healthy", "")},
			wantReady: false,
			wantHard:  false,
			reasonHas: []string{"i-2", "no container IP"},
		},
		{
			name:      "desired count mismatch fails hard without waiting",
			expected:  2,
			desired:   3,
			instances: []saeApplicationInstance{ready("i-1", "172.25.2.145"), ready("i-2", "172.25.2.146")},
			wantReady: false,
			wantHard:  true,
			reasonHas: []string{"3", "2"},
		},
		{
			name:      "zero expected with nonzero desired fails hard",
			expected:  0,
			desired:   1,
			instances: nil,
			wantReady: false,
			wantHard:  true,
		},
		{
			name:      "zero legitimate replicas yields an empty set",
			expected:  0,
			desired:   0,
			instances: nil,
			wantReady: true,
			wantIps:   []string{},
		},
		{
			name:      "zero replicas tolerates terminating leftovers",
			expected:  0,
			desired:   0,
			instances: []saeApplicationInstance{saeTestApplicationInstance("i-1", "Terminating", "", "")},
			wantReady: true,
			wantIps:   []string{},
		},
		{
			name:      "zero replicas with a running instance is not ready",
			expected:  0,
			desired:   0,
			instances: []saeApplicationInstance{saeTestApplicationInstance("i-1", "Running", "Healthy", "172.25.2.145")},
			wantReady: false,
			wantHard:  false,
			reasonHas: []string{"1", "still Running"},
		},
		{
			name:      "blue-green double set converges instead of returning extra ips",
			expected:  2,
			desired:   2,
			instances: []saeApplicationInstance{ready("i-1", "172.25.2.145"), ready("i-2", "172.25.2.146"), ready("i-3", "172.25.2.147"), ready("i-4", "172.25.2.148")},
			wantReady: false,
			wantHard:  false,
			reasonHas: []string{"4", "2"},
		},
		{
			name:      "negative expected fails hard",
			expected:  -1,
			desired:   0,
			instances: nil,
			wantReady: false,
			wantHard:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluateSaeApplicationInstances(tt.expected, tt.desired, tt.instances)
			if got.ready != tt.wantReady {
				t.Fatalf("ready = %v, want %v (reason: %s)", got.ready, tt.wantReady, got.reason)
			}
			if got.hardFail != tt.wantHard {
				t.Fatalf("hardFail = %v, want %v (reason: %s)", got.hardFail, tt.wantHard, got.reason)
			}
			if tt.wantReady {
				if got.ips == nil {
					t.Fatal("ready evaluation must return a non-nil ips slice")
				}
				if !reflect.DeepEqual(got.ips, tt.wantIps) {
					t.Fatalf("ips = %v, want %v", got.ips, tt.wantIps)
				}
			} else {
				if got.reason == "" {
					t.Fatal("not-ready evaluation must carry a reason")
				}
				for _, fragment := range tt.reasonHas {
					if !strings.Contains(got.reason, fragment) {
						t.Fatalf("reason %q does not contain %q", got.reason, fragment)
					}
				}
			}
		})
	}
}

func TestUnitAlicloudSaeApplicationInstancesWalkPages(t *testing.T) {
	t.Run("stops on a short last page", func(t *testing.T) {
		counts := map[int]int{1: 2, 2: 2, 3: 1}
		var pages []int
		err := walkSaeApplicationPages(2, 5, func(currentPage int) (int, error) {
			pages = append(pages, currentPage)
			return counts[currentPage], nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reflect.DeepEqual(pages, []int{1, 2, 3}) {
			t.Fatalf("fetched pages = %v, want [1 2 3]", pages)
		}
	})

	t.Run("fetches one extra empty page on an exact page-size multiple", func(t *testing.T) {
		counts := map[int]int{1: 2, 2: 2, 3: 0}
		var calls int
		err := walkSaeApplicationPages(2, 5, func(currentPage int) (int, error) {
			calls++
			return counts[currentPage], nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if calls != 3 {
			t.Fatalf("calls = %d, want 3", calls)
		}
	})

	t.Run("propagates a page error and stops", func(t *testing.T) {
		var calls int
		err := walkSaeApplicationPages(2, 5, func(currentPage int) (int, error) {
			calls++
			if currentPage == 2 {
				return 0, fmt.Errorf("api exploded")
			}
			return 2, nil
		})
		if err == nil || !strings.Contains(err.Error(), "api exploded") {
			t.Fatalf("err = %v, want the page error", err)
		}
		if calls != 2 {
			t.Fatalf("calls = %d, want 2 (no fetch after failure)", calls)
		}
	})

	t.Run("fails closed when pages never run short", func(t *testing.T) {
		var calls int
		err := walkSaeApplicationPages(2, 3, func(currentPage int) (int, error) {
			calls++
			return 2, nil
		})
		if err == nil || !strings.Contains(err.Error(), "pagination did not terminate") {
			t.Fatalf("err = %v, want a pagination bound error", err)
		}
		if calls != 3 {
			t.Fatalf("calls = %d, want exactly maxPages", calls)
		}
	})
}

func TestUnitAlicloudSaeApplicationInstancesParseDesiredReplicas(t *testing.T) {
	tests := []struct {
		name     string
		response map[string]interface{}
		want     int
		wantErr  bool
	}{
		{name: "json number decodes to int", response: map[string]interface{}{"Data": map[string]interface{}{"Replicas": float64(2)}}, want: 2},
		{name: "zero replicas", response: map[string]interface{}{"Data": map[string]interface{}{"Replicas": float64(0)}}, want: 0},
		{name: "absent replicas is an error, never a silent zero", response: map[string]interface{}{"Data": map[string]interface{}{}}, wantErr: true},
		{name: "null replicas is an error", response: map[string]interface{}{"Data": map[string]interface{}{"Replicas": nil}}, wantErr: true},
		{name: "non-object data is an error", response: map[string]interface{}{"Data": "oops"}, wantErr: true},
		{name: "absent data is an error", response: map[string]interface{}{}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSaeApplicationDesiredReplicas(tt.response)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %d", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("desired = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestUnitAlicloudSaeApplicationInstancesParseGroupsPage(t *testing.T) {
	t.Run("missing or null data means an empty page", func(t *testing.T) {
		for _, response := range []map[string]interface{}{
			{},
			{"Data": nil},
		} {
			groups, err := parseSaeGroupsPage(response)
			if err != nil {
				t.Fatalf("unexpected error for %v: %v", response, err)
			}
			if len(groups) != 0 {
				t.Fatalf("groups = %v, want empty", groups)
			}
		}
	})
	t.Run("group list is returned", func(t *testing.T) {
		groups, err := parseSaeGroupsPage(map[string]interface{}{"Data": []interface{}{
			map[string]interface{}{"GroupId": "g-1"},
			map[string]interface{}{"GroupId": "g-2"},
		}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(groups) != 2 {
			t.Fatalf("len(groups) = %d, want 2", len(groups))
		}
	})
	t.Run("non-list data fails closed", func(t *testing.T) {
		if _, err := parseSaeGroupsPage(map[string]interface{}{"Data": "oops"}); err == nil {
			t.Fatal("expected an error for a non-list Data")
		}
	})
	t.Run("group without id fails closed", func(t *testing.T) {
		if _, err := parseSaeGroupId(map[string]interface{}{"GroupName": "default"}); err == nil {
			t.Fatal("expected an error for a group without GroupId")
		}
		id, err := parseSaeGroupId(map[string]interface{}{"GroupId": "g-1"})
		if err != nil || id != "g-1" {
			t.Fatalf("id = %q, err = %v; want g-1, nil", id, err)
		}
	})
}

func TestUnitAlicloudSaeApplicationInstancesParseInstancesPage(t *testing.T) {
	t.Run("missing keys mean an empty page, matching the API omitting empty lists", func(t *testing.T) {
		for _, response := range []map[string]interface{}{
			{},
			{"Data": nil},
			{"Data": map[string]interface{}{}},
			{"Data": map[string]interface{}{"Instances": nil}},
		} {
			instances, err := parseSaeInstancesPage(response)
			if err != nil {
				t.Fatalf("unexpected error for %v: %v", response, err)
			}
			if len(instances) != 0 {
				t.Fatalf("instances = %v, want empty", instances)
			}
		}
	})
	t.Run("instance entries are returned", func(t *testing.T) {
		instances, err := parseSaeInstancesPage(map[string]interface{}{"Data": map[string]interface{}{
			"Instances": []interface{}{
				map[string]interface{}{"InstanceId": "i-1"},
				map[string]interface{}{"InstanceId": "i-2"},
			},
		}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(instances) != 2 {
			t.Fatalf("len(instances) = %d, want 2", len(instances))
		}
	})
	t.Run("wrong shapes fail closed", func(t *testing.T) {
		for _, response := range []map[string]interface{}{
			{"Data": "oops"},
			{"Data": map[string]interface{}{"Instances": "oops"}},
			{"Data": map[string]interface{}{"Instances": []interface{}{"oops"}}},
		} {
			if _, err := parseSaeInstancesPage(response); err == nil {
				t.Fatalf("expected an error for %v", response)
			}
		}
	})
}

func TestUnitAlicloudSaeApplicationInstancesSchema(t *testing.T) {
	r := dataSourceAlicloudSaeApplicationInstances()

	appId, ok := r.Schema["app_id"]
	if !ok || !appId.Required || appId.Computed || appId.Type != schema.TypeString {
		t.Fatalf("app_id schema = %+v, want a required string", appId)
	}

	expected, ok := r.Schema["expected_replicas"]
	if !ok || !expected.Required || expected.Computed || expected.Type != schema.TypeInt {
		t.Fatalf("expected_replicas schema = %+v, want a required int", expected)
	}
	if expected.ValidateFunc == nil {
		t.Fatal("expected_replicas must validate its range")
	}
	if _, errs := expected.ValidateFunc(-1, "expected_replicas"); len(errs) == 0 {
		t.Fatal("expected_replicas must reject negative values")
	}
	if _, errs := expected.ValidateFunc(0, "expected_replicas"); len(errs) != 0 {
		t.Fatalf("expected_replicas must accept 0 (scaled-to-zero applications), got %v", errs)
	}

	ips, ok := r.Schema["ips"]
	if !ok || !ips.Computed || ips.Required || ips.Type != schema.TypeSet {
		t.Fatalf("ips schema = %+v, want a computed set", ips)
	}
	elem, ok := ips.Elem.(*schema.Schema)
	if !ok || elem.Type != schema.TypeString {
		t.Fatalf("ips elem = %+v, want string elements", ips.Elem)
	}

	if r.Timeouts == nil || r.Timeouts.Read == nil || *r.Timeouts.Read <= 0 {
		t.Fatalf("read timeout = %+v, want a positive default", r.Timeouts)
	}
}
