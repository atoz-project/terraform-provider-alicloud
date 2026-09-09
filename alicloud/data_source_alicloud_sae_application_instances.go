package alicloud

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aliyun/terraform-provider-alicloud/alicloud/connectivity"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
)

const (
	saeApplicationInstancesPageSize = 100
	// saeApplicationInstancesMaxPages bounds pagination so a misbehaving API
	// fails closed instead of looping forever.
	saeApplicationInstancesMaxPages     = 1000
	saeApplicationInstancesPollInterval = 5 * time.Second
)

// dataSourceAlicloudSaeApplicationInstances natively replaces the
// external "sae-eni-ips" data source: it returns the deduplicated container
// IPs of an SAE application's instances, but only once every instance across
// all groups is Running, Healthy and has an IP assigned, and the collected
// set matches both expected_replicas and the cloud desired replica count.
// Any ambiguity (rolling deploy middle state, partial pages, drift between
// expected_replicas and the cloud desired count) fails closed with a
// meaningful error instead of emitting a partial IP set. The read is
// strictly read-only.
func dataSourceAlicloudSaeApplicationInstances() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceAlicloudSaeApplicationInstancesRead,

		Timeouts: &schema.ResourceTimeout{
			Read: schema.DefaultTimeout(5 * time.Minute),
		},

		Schema: map[string]*schema.Schema{
			"app_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The ID of the SAE application whose instance container IPs are collected.",
			},
			"expected_replicas": {
				Type:         schema.TypeInt,
				Required:     true,
				ValidateFunc: validation.IntAtLeast(0),
				Description:  "The replica count the application is expected to run. Must equal the cloud desired replica count; 0 is only valid when the application is scaled to zero and yields an empty ips set.",
			},
			"ips": {
				Type:        schema.TypeSet,
				Computed:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Deduplicated container IPs of all Running and Healthy instances across all instance groups of the application.",
			},
		},
	}
}

// saeApplicationInstance is the subset of DescribeApplicationInstances
// fields needed to decide readiness.
type saeApplicationInstance struct {
	GroupId         string
	InstanceId      string
	ContainerStatus string
	HealthStatus    string
	ContainerIp     string
}

// saeApplicationInstancesEvaluation is the fail-closed verdict for one
// observed snapshot of the application.
type saeApplicationInstancesEvaluation struct {
	// ready is true only when ips satisfies the whole contract.
	ready bool
	// hardFail marks violations no amount of waiting can fix (e.g. the
	// cloud desired replica count differs from expected_replicas).
	hardFail bool
	reason   string
	ips      []string
}

// evaluateSaeApplicationInstances is pure so it can be unit tested without
// cloud access. expected comes from the data source configuration, desired
// from DescribeApplicationConfig, instances from every group page of
// DescribeApplicationInstances.
func evaluateSaeApplicationInstances(expected, desired int, instances []saeApplicationInstance) saeApplicationInstancesEvaluation {
	if expected < 0 {
		return saeApplicationInstancesEvaluation{hardFail: true, reason: fmt.Sprintf("expected_replicas must be >= 0, got %d", expected)}
	}
	if expected != desired {
		return saeApplicationInstancesEvaluation{hardFail: true, reason: fmt.Sprintf("desired replica count mismatch: the cloud application is configured with %d replicas but expected_replicas is %d; update expected_replicas (or scale the application) so both agree", desired, expected)}
	}

	ipSet := make(map[string]struct{})
	running := 0
	notReady := make([]string, 0)
	seen := make(map[string]struct{})
	for _, inst := range instances {
		// Pages may overlap while the instance list shifts during a
		// rolling deploy; never count one instance twice.
		key := inst.InstanceId
		if key == "" {
			key = inst.GroupId + "|" + inst.ContainerIp
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		id := inst.InstanceId
		if id == "" {
			id = "<unknown>"
		}
		if inst.ContainerStatus != "Running" {
			notReady = append(notReady, fmt.Sprintf("instance %s (group %s) container status is %q, want %q", id, inst.GroupId, inst.ContainerStatus, "Running"))
			continue
		}
		running++
		if expected == 0 {
			continue
		}
		if inst.HealthStatus != "Healthy" {
			notReady = append(notReady, fmt.Sprintf("instance %s (group %s) health status is %q, want %q", id, inst.GroupId, inst.HealthStatus, "Healthy"))
			continue
		}
		if inst.ContainerIp == "" {
			notReady = append(notReady, fmt.Sprintf("instance %s (group %s) has no container IP assigned yet", id, inst.GroupId))
			continue
		}
		ipSet[inst.ContainerIp] = struct{}{}
	}

	if expected == 0 {
		// Empty ips is legitimate only when the cloud confirms zero
		// desired replicas and no instance is Running anymore.
		if running > 0 {
			return saeApplicationInstancesEvaluation{reason: fmt.Sprintf("%d instance(s) are still Running although the application desired replica count is 0; waiting for scale-in to finish", running)}
		}
		return saeApplicationInstancesEvaluation{ready: true, ips: []string{}}
	}

	if len(notReady) > 0 {
		detail := notReady
		if len(detail) > 5 {
			detail = append(detail[:5], fmt.Sprintf("and %d more", len(notReady)-5))
		}
		return saeApplicationInstancesEvaluation{reason: fmt.Sprintf("%d of %d observed instance(s) are not ready: %s", len(notReady), len(seen), strings.Join(detail, "; "))}
	}
	if len(ipSet) != expected {
		return saeApplicationInstancesEvaluation{reason: fmt.Sprintf("collected %d unique ready instance IP(s) across all groups, but expected_replicas is %d; the instance list is still converging (e.g. rolling or blue-green deploy in progress)", len(ipSet), expected)}
	}
	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	return saeApplicationInstancesEvaluation{ready: true, ips: ips}
}

// walkSaeApplicationPages invokes fetch for each 1-based page until a short
// page (fewer than pageSize entries) is returned, and fails closed when the
// API never returns a short page.
func walkSaeApplicationPages(pageSize, maxPages int, fetch func(currentPage int) (int, error)) error {
	for page := 1; page <= maxPages; page++ {
		n, err := fetch(page)
		if err != nil {
			return err
		}
		if n < pageSize {
			return nil
		}
	}
	return fmt.Errorf("pagination did not terminate within %d pages of size %d", maxPages, pageSize)
}

// parseSaeApplicationDesiredReplicas extracts the desired replica count from
// a describeApplicationConfig response. Unlike the list endpoints a missing
// Replicas field is an error: silently guessing 0 could bless a scaled
// application as empty.
func parseSaeApplicationDesiredReplicas(response map[string]interface{}) (int, error) {
	data, ok := response["Data"].(map[string]interface{})
	if !ok {
		return 0, fmt.Errorf("unexpected $.Data shape %T, want an object", response["Data"])
	}
	raw, ok := data["Replicas"]
	if !ok || raw == nil {
		return 0, fmt.Errorf("$.Data.Replicas is absent; refusing to guess the desired replica count")
	}
	return formatInt(raw), nil
}

// parseSaeGroupsPage extracts the group entries of one
// describeApplicationGroups page. A missing or null Data key means an empty
// page; any other shape is an error.
func parseSaeGroupsPage(response map[string]interface{}) ([]interface{}, error) {
	raw, ok := response["Data"]
	if !ok || raw == nil {
		return nil, nil
	}
	groups, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected $.Data shape %T, want a list of groups", raw)
	}
	return groups, nil
}

// parseSaeGroupId extracts a group id, failing closed when it is absent: an
// unqueryable group would silently hide its instances.
func parseSaeGroupId(item interface{}) (string, error) {
	group, ok := item.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("unexpected group entry shape %T", item)
	}
	groupId := saeApplicationInstanceStringAttr(group, "GroupId")
	if groupId == "" {
		return "", fmt.Errorf("group entry has no GroupId")
	}
	return groupId, nil
}

// parseSaeInstancesPage extracts the instance attribute maps of one
// describeApplicationInstances page. A missing/null Data or Instances key
// means an empty page (the API omits empty lists); any other shape is an
// error.
func parseSaeInstancesPage(response map[string]interface{}) ([]map[string]interface{}, error) {
	dataRaw, ok := response["Data"]
	if !ok || dataRaw == nil {
		return nil, nil
	}
	data, ok := dataRaw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected $.Data shape %T, want an object", dataRaw)
	}
	raw, ok := data["Instances"]
	if !ok || raw == nil {
		return nil, nil
	}
	list, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected $.Data.Instances shape %T, want a list of instances", raw)
	}
	instances := make([]map[string]interface{}, 0, len(list))
	for _, item := range list {
		m, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("unexpected instance entry shape %T", item)
		}
		instances = append(instances, m)
	}
	return instances, nil
}

func saeApplicationInstanceStringAttr(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func fetchSaeApplicationDesiredReplicas(client *connectivity.AliyunClient, appId string) (int, error) {
	action := "/pop/v1/sam/app/describeApplicationConfig"
	request := map[string]*string{
		"AppId": StringPointer(appId),
	}
	response, err := client.RoaGet("sae", "2019-05-06", action, request, nil, nil)
	addDebug(action, response, request)
	if err != nil {
		return 0, fmt.Errorf("GET %s: %w", action, err)
	}
	desired, err := parseSaeApplicationDesiredReplicas(response)
	if err != nil {
		return 0, fmt.Errorf("GET %s: %w", action, err)
	}
	return desired, nil
}

func fetchSaeApplicationGroupIds(client *connectivity.AliyunClient, appId string) ([]string, error) {
	action := "/pop/v1/sam/app/describeApplicationGroups"
	request := map[string]*string{
		"AppId":    StringPointer(appId),
		"PageSize": StringPointer(strconv.Itoa(saeApplicationInstancesPageSize)),
	}
	groupIds := make([]string, 0)
	err := walkSaeApplicationPages(saeApplicationInstancesPageSize, saeApplicationInstancesMaxPages, func(currentPage int) (int, error) {
		request["CurrentPage"] = StringPointer(strconv.Itoa(currentPage))
		response, err := client.RoaGet("sae", "2019-05-06", action, request, nil, nil)
		addDebug(action, response, request)
		if err != nil {
			return 0, fmt.Errorf("GET %s: %w", action, err)
		}
		groups, err := parseSaeGroupsPage(response)
		if err != nil {
			return 0, fmt.Errorf("GET %s: %w", action, err)
		}
		for _, item := range groups {
			groupId, err := parseSaeGroupId(item)
			if err != nil {
				return 0, fmt.Errorf("GET %s: %s", action, err)
			}
			groupIds = append(groupIds, groupId)
		}
		return len(groups), nil
	})
	if err != nil {
		return nil, err
	}
	return groupIds, nil
}

func fetchSaeGroupInstances(client *connectivity.AliyunClient, appId, groupId string) ([]saeApplicationInstance, error) {
	action := "/pop/v1/sam/app/describeApplicationInstances"
	request := map[string]*string{
		"AppId":    StringPointer(appId),
		"GroupId":  StringPointer(groupId),
		"PageSize": StringPointer(strconv.Itoa(saeApplicationInstancesPageSize)),
	}
	instances := make([]saeApplicationInstance, 0)
	err := walkSaeApplicationPages(saeApplicationInstancesPageSize, saeApplicationInstancesMaxPages, func(currentPage int) (int, error) {
		request["CurrentPage"] = StringPointer(strconv.Itoa(currentPage))
		response, err := client.RoaGet("sae", "2019-05-06", action, request, nil, nil)
		addDebug(action, response, request)
		if err != nil {
			return 0, fmt.Errorf("GET %s: %w", action, err)
		}
		page, err := parseSaeInstancesPage(response)
		if err != nil {
			return 0, fmt.Errorf("GET %s: %w", action, err)
		}
		for _, raw := range page {
			instances = append(instances, saeApplicationInstance{
				GroupId:         groupId,
				InstanceId:      saeApplicationInstanceStringAttr(raw, "InstanceId"),
				ContainerStatus: saeApplicationInstanceStringAttr(raw, "InstanceContainerStatus"),
				HealthStatus:    saeApplicationInstanceStringAttr(raw, "InstanceHealthStatus"),
				ContainerIp:     saeApplicationInstanceStringAttr(raw, "InstanceContainerIp"),
			})
		}
		return len(page), nil
	})
	if err != nil {
		return nil, err
	}
	return instances, nil
}

// collectSaeApplicationInstanceSnapshot reads (read-only) the cloud desired
// replica count, every instance group and every paginated instance of the
// application. Any API or response-shape problem is an error: the data
// source never works with a knowingly partial view.
func collectSaeApplicationInstanceSnapshot(client *connectivity.AliyunClient, appId string) (int, []saeApplicationInstance, error) {
	desired, err := fetchSaeApplicationDesiredReplicas(client, appId)
	if err != nil {
		return 0, nil, err
	}
	groupIds, err := fetchSaeApplicationGroupIds(client, appId)
	if err != nil {
		return 0, nil, err
	}
	instances := make([]saeApplicationInstance, 0)
	for _, groupId := range groupIds {
		groupInstances, err := fetchSaeGroupInstances(client, appId, groupId)
		if err != nil {
			return 0, nil, err
		}
		instances = append(instances, groupInstances...)
	}
	return desired, instances, nil
}

func dataSourceAlicloudSaeApplicationInstancesRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*connectivity.AliyunClient)
	appId := d.Get("app_id").(string)
	expected := d.Get("expected_replicas").(int)
	timeout := d.Timeout(schema.TimeoutRead)
	deadline := time.Now().Add(timeout)
	ctx := context.Background()

	// Bounded health polling: re-read the whole snapshot until the instance
	// set satisfies the contract or the read timeout is exhausted.
	var lastReason string
	for {
		desired, instances, err := collectSaeApplicationInstanceSnapshot(client, appId)
		if err != nil {
			if IsExpectedErrors(err, []string{"InvalidAppId.NotFound"}) {
				return WrapErrorf(NotFoundErr("SAE:Application", appId), NotFoundMsg, ProviderERROR)
			}
			if !NeedRetry(err) {
				return WrapErrorf(err, DataDefaultErrorMsg, "alicloud_sae_application_instances", appId, AlibabaCloudSdkGoERROR)
			}
			lastReason = err.Error()
		} else {
			evaluation := evaluateSaeApplicationInstances(expected, desired, instances)
			if evaluation.ready {
				d.SetId(appId)
				if err := d.Set("ips", evaluation.ips); err != nil {
					return WrapError(err)
				}
				return nil
			}
			if evaluation.hardFail {
				return WrapErrorf(Error("%s", evaluation.reason), DataDefaultErrorMsg, "alicloud_sae_application_instances", appId, ProviderERROR)
			}
			lastReason = evaluation.reason
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return WrapErrorf(Error("SAE application %s instances did not become ready within %s: %s", appId, timeout, lastReason), DataDefaultErrorMsg, "alicloud_sae_application_instances", appId, ProviderERROR)
		}
		sleep := saeApplicationInstancesPollInterval
		if sleep > remaining {
			sleep = remaining
		}
		select {
		case <-ctx.Done():
			return WrapError(ctx.Err())
		case <-time.After(sleep):
		}
	}
}
