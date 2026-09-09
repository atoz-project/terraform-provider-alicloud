package alicloud

// Publication recovery for alicloud_sae_application deployments.
//
// DeployApplication (POST /pop/v1/sam/app/deployApplication) offers no
// idempotency token, so a submit whose outcome is unknown (transport error,
// 5xx, gateway timeout, client cancellation) must never be blindly
// re-dispatched: the server may have accepted it and created a change order.
//
// This file implements the conservative recovery protocol:
//
//   - Before a deploy POST is issued, the intent (random token + a keyed
//     HMAC-SHA256 digest of the complete deploy request) is durably
//     journaled to local disk with fsync and mutual exclusion, and mirrored
//     into the computed `pending_change_order` state attribute. The random
//     digest key stays in the local journal only, so the digest stored in
//     Terraform state cannot be brute-forced into secret request values
//     (Envs, OssAkSecret, ...). The journal survives SIGKILL of the
//     provider process on the same runner; the state record survives error
//     returns (partial state) and refresh.
//   - The token is embedded into the change order description
//     (tf-deploy:<digest12>:<token>) so the submitted change order can
//     later be correlated unambiguously through ListChangeOrders /
//     DescribeChangeOrder. Correlation requires an exact token match plus
//     AppId match; zero matches never proves the request never landed, and
//     digest equality alone never proves correlation.
//   - Only documented change order status 2 means deployment succeeded.
//     Statuses 3/6/10 are terminal failures and are reported as failures;
//     they never silently pass as success and never trigger an automatic
//     re-submit inside the invocation that first observes them.
//   - While a pending record is unresolved (unknown or still running) both
//     the update submit path and the read/refresh path fail closed with an
//     explicit error; an operator who has verified the real outcome out of
//     band can force-clear the pending record (see below).

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/alibabacloud-go/tea/tea"
	"github.com/aliyun/terraform-provider-alicloud/alicloud/connectivity"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

const (
	// saeDeployRecoveryAttrName is the computed-only state attribute that
	// mirrors the pending recovery record. It never carries secret data:
	// only a random token, a keyed HMAC-SHA256 digest (key journal-only),
	// and a change order id.
	saeDeployRecoveryAttrName = "pending_change_order"

	// saeDeployDescPrefix marks change orders submitted by this provider
	// through the recovery-aware path. Format:
	//   tf-deploy:<digest12>:<token>[ <user change_order_desc>]
	saeDeployDescPrefix    = "tf-deploy:"
	saeDeployDescMaxLength = 128

	// saeDeployJournalDirEnvVar overrides the journal directory. The
	// journal guarantees same-runner recovery across provider process
	// kills; cross-host recovery after SIGKILL cannot be promised when the
	// journal directory is ephemeral.
	saeDeployJournalDirEnvVar = "ALICLOUD_SAE_DEPLOY_JOURNAL_DIR"
	// saeDeployForceClearEnvVar is the operator escape hatch: after
	// verifying the real outcome of the pending change order out of band
	// (SAE console / CLI), setting it to "true" makes the provider drop the
	// pending record without submitting anything.
	saeDeployForceClearEnvVar = "ALICLOUD_SAE_DEPLOY_FORCE_CLEAR_PENDING"

	saeDeployJournalDirName = "alicloud-sae-deploy-journal"
	saeDeployJournalVersion = 1

	// saeChangeOrderStatusSucceeded is the only documented terminal success
	// status of a change order. Documented statuses:
	//   0 preparing, 1 in progress, 2 succeeded, 3 failed, 6 terminated,
	//   8 awaiting manual confirmation, 9 awaiting automatic confirmation,
	//   10 failed due to a system error, 11 pending approval,
	//   12 approved and pending execution
	saeChangeOrderStatusSucceeded = "2"
)

// saeChangeOrderTerminalFailureStatuses are documented terminal statuses in
// which the change definitively did not complete successfully.
var saeChangeOrderTerminalFailureStatuses = map[string]bool{"3": true, "6": true, "10": true}

// saeChangeOrderInFlightStatuses are documented non-terminal statuses. Any
// undocumented status is treated as in-flight as well (fail-safe).
var saeChangeOrderInFlightStatuses = map[string]bool{"0": true, "1": true, "8": true, "9": true, "11": true, "12": true}

// saeDeployRecoveryRecord is the durable recovery intent. It is persisted
// twice: in the local fsync'd journal (before the POST is issued) and in
// the Terraform state attribute (survives error returns via partial
// state). Only the journal copy carries DigestKey; the state copy never
// does, so the digest in state cannot be brute-forced into secret request
// values (Envs, OssAkSecret, ...).
type saeDeployRecoveryRecord struct {
	Version   int    `json:"v"`
	AppId     string `json:"app_id"`
	AccountId string `json:"account_id,omitempty"`
	Token     string `json:"token"`
	// Digest is a keyed HMAC-SHA256 over the COMPLETE deploy request
	// (every field except the correlation description), so the skip-
	// submission decision stays sound even when secret-bearing fields
	// change. DigestKey is the random per-attempt key, persisted only in
	// the local journal (file mode 0600) and never in Terraform state,
	// logs, or diagnostics.
	Digest        string `json:"digest"`
	DigestKey     string `json:"digest_key,omitempty"`
	ChangeOrderId string `json:"change_order_id,omitempty"`
	// Failed is set once a terminal failure status (3/6/10) has been
	// observed AND reported to the operator by an invocation. Only a record
	// carrying Failed=true may be dropped in favor of a fresh submit by a
	// later invocation; the invocation that first observes the failure must
	// report it and stop.
	Failed  bool   `json:"failed,omitempty"`
	Created string `json:"created"`
}

func newSaeDeployRecoveryRecord(appId, accountId string, req map[string]*string) (*saeDeployRecoveryRecord, error) {
	token, err := uuid.GenerateUUID()
	if err != nil {
		return nil, WrapError(err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, WrapError(err)
	}
	return &saeDeployRecoveryRecord{
		Version:   saeDeployJournalVersion,
		AppId:     appId,
		AccountId: accountId,
		Token:     token,
		Digest:    saeDeployRequestDigest(key, req),
		DigestKey: hex.EncodeToString(key),
		Created:   time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// digestMatches reports whether the record provably pins this exact deploy
// request. Without the journal-held key no claim can be made.
func (rec *saeDeployRecoveryRecord) digestMatches(req map[string]*string) bool {
	if rec.DigestKey == "" || rec.Digest == "" {
		return false
	}
	key, err := hex.DecodeString(rec.DigestKey)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(rec.Digest), []byte(saeDeployRequestDigest(key, req))) == 1
}

func parseSaeDeployRecoveryRecord(raw string) *saeDeployRecoveryRecord {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	rec := &saeDeployRecoveryRecord{}
	if err := json.Unmarshal([]byte(raw), rec); err != nil || rec.Token == "" {
		log.Printf("[WARN] Ignoring unparsable %s state value; a fresh deploy intent will be journaled. value=%q err=%v", saeDeployRecoveryAttrName, raw, err)
		return nil
	}
	return rec
}

func (rec *saeDeployRecoveryRecord) encode() (string, error) {
	raw, err := json.Marshal(rec)
	if err != nil {
		return "", WrapError(err)
	}
	return string(raw), nil
}

// saeDeployRequestDigest computes a keyed HMAC-SHA256 over the complete
// deploy request. Every request field participates except ChangeOrderDesc
// (correlation metadata, not deployment identity). The digest and key are
// never logged together with request values.
func saeDeployRequestDigest(key []byte, req map[string]*string) string {
	keys := make([]string, 0, len(req))
	for k := range req {
		if k == "ChangeOrderDesc" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	mac := hmac.New(sha256.New, key)
	for _, k := range keys {
		mac.Write([]byte(k))
		mac.Write([]byte{0})
		if req[k] != nil {
			mac.Write([]byte(*req[k]))
		}
		mac.Write([]byte{0})
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func saeDeployDigestShort(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}

// composeSaeDeployChangeOrderDesc embeds the recovery token into the change
// order description. The token prefix is never truncated; only the optional
// user supplied suffix is cut to stay within saeDeployDescMaxLength.
func composeSaeDeployChangeOrderDesc(digest, token, userDesc string) string {
	prefix := fmt.Sprintf("%s%s:%s", saeDeployDescPrefix, saeDeployDigestShort(digest), token)
	userDesc = strings.TrimSpace(userDesc)
	if userDesc == "" {
		return prefix
	}
	budget := saeDeployDescMaxLength - len(prefix) - 1
	if budget <= 0 {
		return prefix
	}
	if len(userDesc) > budget {
		userDesc = userDesc[:budget]
	}
	return prefix + " " + userDesc
}

// parseSaeDeployChangeOrderDesc extracts the embedded digest prefix and
// token from a change order description previously composed by this provider.
func parseSaeDeployChangeOrderDesc(desc string) (digest12, token string, ok bool) {
	if !strings.HasPrefix(desc, saeDeployDescPrefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(desc, saeDeployDescPrefix)
	parts := strings.SplitN(rest, ":", 2)
	if len(parts) != 2 || parts[0] == "" {
		return "", "", false
	}
	token = parts[1]
	if i := strings.IndexByte(token, ' '); i >= 0 {
		token = token[:i]
	}
	if token == "" {
		return "", "", false
	}
	return parts[0], token, true
}

// saeDeploySubmitVerdict classifies a failed DeployApplication call.
type saeDeploySubmitVerdict int

const (
	// saeDeploySubmitRejectedRetryable: the server explicitly refused the
	// request before accepting it (business rejection or POP throttling);
	// no change order could have been created, retrying is unambiguous.
	saeDeploySubmitRejectedRetryable saeDeploySubmitVerdict = iota
	// saeDeploySubmitRejectedFinal: definitive client-side rejection (4xx);
	// nothing is pending server-side, fail without a recovery record.
	saeDeploySubmitRejectedFinal
	// saeDeploySubmitAmbiguous: outcome unknown (transport error, timeout,
	// 5xx, cancellation). Never auto-resubmit; correlate instead.
	saeDeploySubmitAmbiguous
)

func classifySaeDeploySubmitError(err error) saeDeploySubmitVerdict {
	if err == nil {
		return saeDeploySubmitRejectedFinal
	}
	if IsExpectedErrors(err, []string{"Application.InvalidStatus", "Application.ChangerOrderRunning"}) {
		return saeDeploySubmitRejectedRetryable
	}
	if sdkErr, ok := err.(*tea.SDKError); ok {
		code := tea.StringValue(sdkErr.Code) + " " + tea.StringValue(sdkErr.Message)
		if strings.Contains(code, "Throttling") {
			return saeDeploySubmitRejectedRetryable
		}
		if sdkErr.StatusCode != nil {
			sc := *sdkErr.StatusCode
			if sc >= 400 && sc < 500 {
				return saeDeploySubmitRejectedFinal
			}
			if sc >= 500 {
				return saeDeploySubmitAmbiguous
			}
		}
		// No status code: cannot prove the server rejected the request.
		return saeDeploySubmitAmbiguous
	}
	// Raw transport errors (connection reset, EOF, context canceled, ...)
	// and every unknown error shape are ambiguous by default (fail-safe).
	return saeDeploySubmitAmbiguous
}

// saeChangeOrderOutcome is the recovery decision for an observed change order.
type saeChangeOrderOutcome int

const (
	saeChangeOrderOutcomeSucceeded saeChangeOrderOutcome = iota
	saeChangeOrderOutcomeFailed
	saeChangeOrderOutcomeInFlight
)

// classifySaeChangeOrderStatus maps the documented change order status codes
// to recovery outcomes. Only "2" is success; "3"/"6"/"10" are terminal
// failures; everything else (including undocumented codes) is in-flight.
func classifySaeChangeOrderStatus(status string) saeChangeOrderOutcome {
	switch {
	case status == saeChangeOrderStatusSucceeded:
		return saeChangeOrderOutcomeSucceeded
	case saeChangeOrderTerminalFailureStatuses[status]:
		return saeChangeOrderOutcomeFailed
	default:
		return saeChangeOrderOutcomeInFlight
	}
}

// saeDeployRemote abstracts the SAE API surface the recovery engine needs, so
// the decision logic can be regression-tested without cloud access.
type saeDeployRemote interface {
	// submitDeployOnce issues exactly one DeployApplication POST. Errors
	// must be returned raw so classifySaeDeploySubmitError can judge them.
	submitDeployOnce(req map[string]*string) (map[string]interface{}, error)
	// describeChangeOrder returns the Data object of DescribeChangeOrder.
	describeChangeOrder(changeOrderId string) (map[string]interface{}, error)
	// listChangeOrdersPage returns one page of the change order history of
	// an application plus the reported total size.
	listChangeOrdersPage(appId string, currentPage, pageSize int) ([]map[string]interface{}, int, error)
}

type saeDeployRemoteClient struct {
	client *connectivity.AliyunClient
}

func (r *saeDeployRemoteClient) submitDeployOnce(req map[string]*string) (map[string]interface{}, error) {
	action := "/pop/v1/sam/app/deployApplication"
	// autoRetry=false: the tea runtime must not silently repeat a mutating
	// call whose first attempt may already have been accepted.
	// NOTE: the request is deliberately not passed to addDebug here because
	// it contains secret-bearing fields (Envs, OssAkSecret, ...).
	return r.client.RoaPost("sae", "2019-05-06", action, req, nil, nil, false)
}

func (r *saeDeployRemoteClient) describeChangeOrder(changeOrderId string) (map[string]interface{}, error) {
	saeService := SaeService{r.client}
	return saeService.DescribeSaeApplicationChangeOrder(changeOrderId)
}

func (r *saeDeployRemoteClient) listChangeOrdersPage(appId string, currentPage, pageSize int) ([]map[string]interface{}, int, error) {
	action := "/pop/v1/sam/changeorder/ListChangeOrders"
	request := map[string]*string{
		"AppId":       StringPointer(appId),
		"CurrentPage": StringPointer(fmt.Sprintf("%d", currentPage)),
		"PageSize":    StringPointer(fmt.Sprintf("%d", pageSize)),
	}
	var response map[string]interface{}
	var err error
	wait := incrementalWait(3*time.Second, 3*time.Second)
	err = resource.Retry(5*time.Minute, func() *resource.RetryError {
		response, err = r.client.RoaGet("sae", "2019-05-06", action, request, nil, nil)
		if err != nil {
			if NeedRetry(err) {
				wait()
				return resource.RetryableError(err)
			}
			return resource.NonRetryableError(err)
		}
		return nil
	})
	addDebug(action, response, request)
	if err != nil {
		return nil, 0, WrapErrorf(err, DefaultErrorMsg, appId, "GET "+action, AlibabaCloudSdkGoERROR)
	}
	data, ok := response["Data"].(map[string]interface{})
	if !ok {
		return nil, 0, WrapError(fmt.Errorf("ListChangeOrders response for application %s misses the Data object", appId))
	}
	total := 0
	if v, ok := data["TotalSize"]; ok && v != nil {
		fmt.Sscanf(fmt.Sprint(v), "%d", &total)
	}
	items := make([]map[string]interface{}, 0)
	if v, ok := data["ChangeOrderList"].([]interface{}); ok {
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok {
				items = append(items, m)
			}
		}
	}
	return items, total, nil
}

// saeDeployRecoveryTimeouts bounds the engine. They are explicit so unit
// tests can drive the engine without real waiting.
type saeDeployRecoveryTimeouts struct {
	submitRetry  time.Duration
	correlate    time.Duration
	observe      time.Duration
	pollInterval time.Duration
}

// saeDeployJournal is the fsync'd on-disk recovery journal, scoped per
// account and application and guarded by an advisory file lock.
type saeDeployJournal struct {
	dir string
}

func defaultSaeDeployJournal() (*saeDeployJournal, error) {
	if dir := strings.TrimSpace(os.Getenv(saeDeployJournalDirEnvVar)); dir != "" {
		return &saeDeployJournal{dir: dir}, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, WrapError(fmt.Errorf("unable to resolve the working directory for the SAE deploy recovery journal: %w", err))
	}
	return &saeDeployJournal{dir: filepath.Join(cwd, ".terraform", saeDeployJournalDirName)}, nil
}

func saeDeployJournalFileComponent(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

func (j *saeDeployJournal) recordPath(accountId, appId string) string {
	name := fmt.Sprintf("%s-%s.json", saeDeployJournalFileComponent(accountId), saeDeployJournalFileComponent(appId))
	return filepath.Join(j.dir, name)
}

func (j *saeDeployJournal) lockPath(accountId, appId string) string {
	name := fmt.Sprintf("%s-%s.lock", saeDeployJournalFileComponent(accountId), saeDeployJournalFileComponent(appId))
	return filepath.Join(j.dir, name)
}

// exists reports whether a journal record file is present.
func (j *saeDeployJournal) exists(accountId, appId string) bool {
	_, err := os.Stat(j.recordPath(accountId, appId))
	return err == nil
}

func (j *saeDeployJournal) load(accountId, appId string) (*saeDeployRecoveryRecord, error) {
	raw, err := os.ReadFile(j.recordPath(accountId, appId))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, WrapError(err)
	}
	rec := &saeDeployRecoveryRecord{}
	if err := json.Unmarshal(raw, rec); err != nil || rec.Token == "" {
		// A corrupt journal cannot prove anything; fail closed and let the
		// operator remove the file manually.
		return nil, WrapError(fmt.Errorf("the SAE deploy recovery journal %s is unreadable (err=%v); refusing to guess the pending deploy outcome, delete the file manually after verifying the application %s in the SAE console", j.recordPath(accountId, appId), err, appId))
	}
	return rec, nil
}

// store writes the record atomically: write temp file, fsync, rename, fsync
// the directory. It must complete BEFORE the deploy POST is issued.
func (j *saeDeployJournal) store(rec *saeDeployRecoveryRecord) error {
	if err := os.MkdirAll(j.dir, 0o755); err != nil {
		return WrapError(err)
	}
	raw, err := rec.encode()
	if err != nil {
		return err
	}
	path := j.recordPath(rec.AccountId, rec.AppId)
	tmp, err := os.CreateTemp(j.dir, ".journal-*")
	if err != nil {
		return WrapError(err)
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()
	if _, err := tmp.WriteString(raw); err != nil {
		return WrapError(err)
	}
	if err := tmp.Sync(); err != nil {
		return WrapError(err)
	}
	if err := tmp.Close(); err != nil {
		return WrapError(err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return WrapError(err)
	}
	if dir, err := os.Open(j.dir); err == nil {
		dir.Sync()
		dir.Close()
	}
	return nil
}

func (j *saeDeployJournal) remove(accountId, appId string) error {
	err := os.Remove(j.recordPath(accountId, appId))
	if err != nil && !os.IsNotExist(err) {
		return WrapError(err)
	}
	return nil
}

// lock serializes deploy submissions for one application on this runner.
// blocking=false is used by the read gate: a lock already held by another
// process means a deploy is actively in flight, i.e. the outcome is unknown.
func (j *saeDeployJournal) lock(accountId, appId string, blocking bool) (func(), error) {
	if err := os.MkdirAll(j.dir, 0o755); err != nil {
		return nil, WrapError(err)
	}
	lockPath := j.lockPath(accountId, appId)
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, WrapError(err)
	}
	if err := saeDeployLockFile(f, blocking); err != nil {
		f.Close()
		if !blocking {
			return nil, WrapError(fmt.Errorf("another process holds the deploy recovery lock %s for application %s; a deploy may be in flight and its outcome is unknown: %w", lockPath, appId, err))
		}
		return nil, WrapError(err)
	}
	return func() {
		saeDeployUnlockFile(f)
		f.Close()
	}, nil
}

// saeDeployRecoveryContext carries the engine dependencies; tests inject a
// fake remote and a temp-dir journal.
type saeDeployRecoveryContext struct {
	remote    saeDeployRemote
	journal   *saeDeployJournal
	accountId string
	timeouts  saeDeployRecoveryTimeouts
}

func newSaeDeployRecoveryContext(d *schema.ResourceData, client *connectivity.AliyunClient) (*saeDeployRecoveryContext, error) {
	journal, err := defaultSaeDeployJournal()
	if err != nil {
		return nil, err
	}
	accountId, err := client.AccountId()
	if err != nil {
		// The journal is additionally scoped by the (globally unique)
		// application id, so an unresolved account id degrades scoping only.
		log.Printf("[WARN] Unable to resolve the account id for the SAE deploy recovery journal of %s: %v", d.Id(), err)
		accountId = ""
	}
	updateTimeout := d.Timeout(schema.TimeoutUpdate)
	return &saeDeployRecoveryContext{
		remote:    &saeDeployRemoteClient{client: client},
		journal:   journal,
		accountId: accountId,
		timeouts: saeDeployRecoveryTimeouts{
			submitRetry:  client.GetRetryTimeout(updateTimeout),
			correlate:    5 * time.Minute,
			observe:      updateTimeout,
			pollInterval: 3 * time.Second,
		},
	}, nil
}

// ---- state persistence helpers ----

func persistSaeDeployRecoveryRecord(d *schema.ResourceData, rec *saeDeployRecoveryRecord, partial bool) error {
	raw, err := rec.encode()
	if err != nil {
		return err
	}
	if err := d.Set(saeDeployRecoveryAttrName, raw); err != nil {
		return WrapError(err)
	}
	if partial {
		d.SetPartial(saeDeployRecoveryAttrName)
	}
	return nil
}

func clearSaeDeployRecoveryRecord(d *schema.ResourceData, partial bool) {
	d.Set(saeDeployRecoveryAttrName, "")
	if partial {
		d.SetPartial(saeDeployRecoveryAttrName)
	}
}

// ---- error messages ----

func saeDeployRecoveryUnknownError(appId string, rec *saeDeployRecoveryRecord, journalPath string, cause error) error {
	changeOrder := "unknown (no change order id was returned; the request may or may not have been accepted)"
	if rec.ChangeOrderId != "" {
		changeOrder = rec.ChangeOrderId
	}
	return WrapError(fmt.Errorf("the outcome of a previous DeployApplication call for application %s is unknown and will NOT be blindly resubmitted. Change order: %s. Recovery token: %s (embedded in the change order description as %s%s:%s). Local journal: %s. "+
		"Re-run terraform apply: the provider reconciles the change order before submitting anything. If reconciliation keeps failing, verify the outcome in the SAE console (ListChangeOrders/DescribeChangeOrder); after you have confirmed the real outcome, set %s=true and re-run to drop the pending record without submitting. Cause: %v",
		appId, changeOrder, rec.Token, saeDeployDescPrefix, saeDeployDigestShort(rec.Digest), rec.Token, journalPath, saeDeployForceClearEnvVar, cause))
}

func saeDeployRecoveryTerminalFailureError(appId, changeOrderId string, object map[string]interface{}) error {
	return WrapError(fmt.Errorf("the deploy change order %s for application %s reached terminal failure (Status=%s, SubStatus=%s, ErrorMessage=%s). The change was NOT applied successfully. This failure is reported without automatic resubmission; re-run terraform apply to submit a fresh deploy after investigating the cause",
		changeOrderId, appId, fmt.Sprint(object["Status"]), fmt.Sprint(object["SubStatus"]), fmt.Sprint(object["ErrorMessage"])))
}

// ---- remote helpers ----

func listAllSaeDeployChangeOrders(remote saeDeployRemote, appId string) ([]map[string]interface{}, error) {
	const pageSize = 100
	const maxPages = 100
	all := make([]map[string]interface{}, 0)
	for page := 1; page <= maxPages; page++ {
		items, total, err := remote.listChangeOrdersPage(appId, page, pageSize)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
		if len(items) == 0 || len(all) >= total {
			return all, nil
		}
	}
	return nil, WrapError(fmt.Errorf("the change order history of application %s is too large to correlate exhaustively; refusing to guess", appId))
}

// findSaeDeployChangeOrderByToken returns the index of the change order whose
// embedded recovery token AND application id match exactly. Digest
// equality alone is never accepted as proof.
func findSaeDeployChangeOrderByToken(items []map[string]interface{}, appId string, rec *saeDeployRecoveryRecord) (map[string]interface{}, bool) {
	matches := make([]map[string]interface{}, 0)
	for _, item := range items {
		if fmt.Sprint(item["AppId"]) != appId {
			continue
		}
		digest12, token, ok := parseSaeDeployChangeOrderDesc(fmt.Sprint(item["Description"]))
		if !ok || token != rec.Token || digest12 != saeDeployDigestShort(rec.Digest) {
			continue
		}
		matches = append(matches, item)
	}
	if len(matches) != 1 {
		return nil, false
	}
	return matches[0], true
}

// ---- engine ----

// mergeSaeDeployRecoveryRecords combines the state record with the local
// journal. Conflicting tokens mean two different submit attempts claim the
// application; that ambiguity can only be resolved manually.
func mergeSaeDeployRecoveryRecords(stateRec, journalRec *saeDeployRecoveryRecord, journalPath string) (*saeDeployRecoveryRecord, error) {
	switch {
	case stateRec == nil && journalRec == nil:
		return nil, nil
	case stateRec == nil:
		return journalRec, nil
	case journalRec == nil:
		return stateRec, nil
	case stateRec.Token != journalRec.Token:
		return nil, WrapError(fmt.Errorf("conflicting pending deploy records for application %s: Terraform state tracks recovery token %s while the local journal %s tracks token %s. Both submissions may have been accepted and cannot be attributed safely; refusing to continue. Inspect the change order history in the SAE console, then clear the stale record manually (state attribute %s and/or the journal file) or set %s=true after verification",
			stateRec.AppId, stateRec.Token, journalPath, journalRec.Token, saeDeployRecoveryAttrName, saeDeployForceClearEnvVar))
	}
	merged := *stateRec
	if merged.ChangeOrderId == "" {
		merged.ChangeOrderId = journalRec.ChangeOrderId
	}
	// The journal is authoritative for the digest key: the state copy
	// never carries it.
	merged.DigestKey = journalRec.DigestKey
	merged.Failed = merged.Failed || journalRec.Failed
	return &merged, nil
}

func saeDeployForceClearPendingRequested() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(saeDeployForceClearEnvVar)), "true")
}

// loadMergedRecord loads state + journal records and merges them.
// partial controls SetPartial usage.
func (ctx *saeDeployRecoveryContext) loadMergedRecord(d *schema.ResourceData, partial bool) (*saeDeployRecoveryRecord, error) {
	journalRec, err := ctx.journal.load(ctx.accountId, d.Id())
	if err != nil {
		return nil, err
	}
	stateRec := parseSaeDeployRecoveryRecord(d.Get(saeDeployRecoveryAttrName).(string))
	return mergeSaeDeployRecoveryRecords(stateRec, journalRec, ctx.journal.recordPath(ctx.accountId, d.Id()))
}

func (ctx *saeDeployRecoveryContext) dropRecord(d *schema.ResourceData, partial bool) error {
	clearSaeDeployRecoveryRecord(d, partial)
	return ctx.journal.remove(ctx.accountId, d.Id())
}

// persistRecord writes the record to the journal (fsync) and to state.
// The state copy never carries the digest key: without the journal the
// skip-submission proof is impossible and a fresh deliberate deploy is
// required instead.
func (ctx *saeDeployRecoveryContext) persistRecord(d *schema.ResourceData, rec *saeDeployRecoveryRecord, partial bool) error {
	if err := ctx.journal.store(rec); err != nil {
		return WrapError(fmt.Errorf("unable to persist the deploy recovery journal for application %s: %v. The deploy was NOT submitted", rec.AppId, err))
	}
	stateRec := *rec
	stateRec.DigestKey = ""
	return persistSaeDeployRecoveryRecord(d, &stateRec, partial)
}

// correlateByToken polls the change order history until the submitted change
// order (exact token + AppId match) appears or the correlate budget expires.
// Zero matches never proves the request never landed (eventual consistency),
// so an exhausted budget is an unresolved outcome, not clearance.
func (ctx *saeDeployRecoveryContext) correlateByToken(rec *saeDeployRecoveryRecord) (map[string]interface{}, error) {
	deadline := time.Now().Add(ctx.timeouts.correlate)
	var lastErr error
	for {
		items, err := listAllSaeDeployChangeOrders(ctx.remote, rec.AppId)
		if err != nil {
			lastErr = err
		} else if item, found := findSaeDeployChangeOrderByToken(items, rec.AppId, rec); found {
			return item, nil
		}
		if time.Now().After(deadline) || ctx.timeouts.correlate <= 0 {
			if lastErr != nil {
				return nil, WrapError(fmt.Errorf("unable to read the change order history of application %s to attribute recovery token %s: %v", rec.AppId, rec.Token, lastErr))
			}
			return nil, nil
		}
		time.Sleep(ctx.timeouts.pollInterval)
	}
}

// observeChangeOrder waits for a change order to reach a terminal state.
// Only status "2" counts as success. The returned outcomeFailed carries the
// last observed object on terminal failure.
func (ctx *saeDeployRecoveryContext) observeChangeOrder(changeOrderId string) (saeChangeOrderOutcome, map[string]interface{}, error) {
	var lastObject map[string]interface{}
	var terminalFailure bool
	refresh := func() (interface{}, string, error) {
		object, err := ctx.remote.describeChangeOrder(changeOrderId)
		if err != nil {
			if NotFoundError(err) || IsExpectedErrors(err, []string{"InvalidChangeOrder.NotFound"}) {
				// Freshly created change orders may lag; keep waiting.
				return nil, "", nil
			}
			return nil, "", err
		}
		lastObject = object
		status := fmt.Sprint(object["Status"])
		if saeChangeOrderTerminalFailureStatuses[status] {
			terminalFailure = true
			return object, status, WrapError(Error(FailedToReachTargetStatus, status))
		}
		return object, status, nil
	}
	pending := []string{""}
	for s := range saeChangeOrderInFlightStatuses {
		pending = append(pending, s)
	}
	stateConf := BuildStateConf(pending, []string{saeChangeOrderStatusSucceeded}, ctx.timeouts.observe, ctx.timeouts.pollInterval, resource.StateRefreshFunc(refresh))
	_, err := stateConf.WaitForState()
	if err != nil {
		if terminalFailure {
			return saeChangeOrderOutcomeFailed, lastObject, nil
		}
		return saeChangeOrderOutcomeInFlight, lastObject, err
	}
	return saeChangeOrderOutcomeSucceeded, lastObject, nil
}

// resolvePendingChangeOrder observes/correlates a pending record to a
// terminal outcome. It never submits anything.
//
// resolvedSuccess=true means the pending deployment demonstrably succeeded
// (status 2) and the record has been dropped. A terminal failure observed
// for the first time by THIS invocation is recorded (Failed=true) and
// returned as an error; it never triggers a resubmission in the same
// invocation.
func (ctx *saeDeployRecoveryContext) resolvePendingChangeOrder(d *schema.ResourceData, rec *saeDeployRecoveryRecord, partial bool) (resolvedSuccess bool, err error) {
	if rec.ChangeOrderId == "" {
		item, err := ctx.correlateByToken(rec)
		if err != nil {
			return false, err
		}
		if item == nil {
			// No change order carries our token. That is not proof the
			// request never landed, so the record stays pending.
			return false, saeDeployRecoveryUnknownError(rec.AppId, rec, ctx.journal.recordPath(ctx.accountId, rec.AppId), fmt.Errorf("no change order with the recovery token appeared in the history"))
		}
		rec.ChangeOrderId = fmt.Sprint(item["ChangeOrderId"])
		if rec.ChangeOrderId == "" {
			return false, saeDeployRecoveryUnknownError(rec.AppId, rec, ctx.journal.recordPath(ctx.accountId, rec.AppId), fmt.Errorf("the correlated change order carries no ChangeOrderId"))
		}
		if err := ctx.persistRecord(d, rec, partial); err != nil {
			return false, err
		}
	}

	outcome, object, err := ctx.observeChangeOrder(rec.ChangeOrderId)
	if err != nil {
		// Still in flight after the observe budget, or the change order is
		// unreadable: the outcome remains unknown. Fail closed, keep record.
		return false, saeDeployRecoveryUnknownError(rec.AppId, rec, ctx.journal.recordPath(ctx.accountId, rec.AppId), err)
	}
	switch outcome {
	case saeChangeOrderOutcomeSucceeded:
		if err := ctx.dropRecord(d, partial); err != nil {
			return false, err
		}
		return true, nil
	case saeChangeOrderOutcomeFailed:
		rec.Failed = true
		if perr := ctx.persistRecord(d, rec, partial); perr != nil {
			return false, perr
		}
		return false, saeDeployRecoveryTerminalFailureError(rec.AppId, rec.ChangeOrderId, object)
	default:
		return false, saeDeployRecoveryUnknownError(rec.AppId, rec, ctx.journal.recordPath(ctx.accountId, rec.AppId), fmt.Errorf("change order %s is still in a non-terminal status %s", rec.ChangeOrderId, fmt.Sprint(object["Status"])))
	}
}

// submitOnce dispatches a single DeployApplication POST, retrying only
// rejections that provably never created a change order.
func (ctx *saeDeployRecoveryContext) submitOnce(req map[string]*string) (response map[string]interface{}, ambiguous error, err error) {
	wait := incrementalWait(3*time.Second, 3*time.Second)
	var ambiguousErr error
	err = resource.Retry(ctx.timeouts.submitRetry, func() *resource.RetryError {
		resp, submitErr := ctx.remote.submitDeployOnce(req)
		if submitErr == nil {
			response = resp
			return nil
		}
		switch classifySaeDeploySubmitError(submitErr) {
		case saeDeploySubmitRejectedRetryable:
			wait()
			return resource.RetryableError(submitErr)
		case saeDeploySubmitRejectedFinal:
			return resource.NonRetryableError(submitErr)
		default:
			ambiguousErr = submitErr
			return resource.NonRetryableError(submitErr)
		}
	})
	if err != nil && ambiguousErr != nil {
		return nil, ambiguousErr, nil
	}
	if err != nil {
		return nil, nil, err
	}
	return response, nil, nil
}

// execute runs the recovery-aware deploy for the update path. partial is true
// because the update function enables partial state mode before calling.
func (ctx *saeDeployRecoveryContext) execute(d *schema.ResourceData, req map[string]*string) error {
	appId := d.Id()
	unlock, err := ctx.journal.lock(ctx.accountId, appId, true)
	if err != nil {
		return err
	}
	defer unlock()

	if saeDeployForceClearPendingRequested() {
		// Operator escape hatch: drop any pending record and STOP the whole
		// update. No deploy is ever submitted while the switch is set — not
		// even when refresh already cleared the record earlier in this run.
		if err := ctx.dropRecord(d, true); err != nil {
			return err
		}
		return WrapError(fmt.Errorf("%s is set: the pending deploy recovery record of application %s (if any) was dropped and NO deploy was submitted; unset %s and re-run terraform apply to proceed",
			saeDeployForceClearEnvVar, appId, saeDeployForceClearEnvVar))
	}

	rec, err := ctx.loadMergedRecord(d, true)
	if err != nil {
		return err
	}

	if rec != nil && rec.Failed {
		// The terminal failure was already reported by a previous
		// invocation and the operator re-ran apply: the failed change order
		// definitively did not apply, so the record can be dropped in favor
		// of one fresh submit.
		if err := ctx.dropRecord(d, true); err != nil {
			return err
		}
		rec = nil
	}

	if rec != nil {
		resolvedSuccess, err := ctx.resolvePendingChangeOrder(d, rec, true)
		if err != nil {
			return err
		}
		if resolvedSuccess && rec.digestMatches(req) {
			// The pending deploy demonstrably succeeded AND the keyed
			// digest proves it applied exactly this request (secret-bearing
			// fields included). Counted once: no resubmission.
			log.Printf("[INFO] The pending deploy of application %s (change order %s) already applied the desired configuration; skipping resubmission", appId, rec.ChangeOrderId)
			return nil
		}
		// Either the previous intent succeeded but the desired request
		// provably differs, or the digest key is unavailable on this
		// runner (state-only record): no exact-match claim is possible, so
		// one deliberate fresh submit follows. That is not an ambiguous
		// resubmission — the previous change order reached a terminal
		// success state.
	}

	// Fresh submit path: journal the intent durably BEFORE the POST.
	rec, err = newSaeDeployRecoveryRecord(appId, ctx.accountId, req)
	if err != nil {
		return err
	}
	if err := ctx.persistRecord(d, rec, true); err != nil {
		return err
	}

	userDesc := ""
	if v, ok := req["ChangeOrderDesc"]; ok && v != nil {
		userDesc = *v
	}
	req["ChangeOrderDesc"] = StringPointer(composeSaeDeployChangeOrderDesc(rec.Digest, rec.Token, userDesc))

	response, ambiguousErr, err := ctx.submitOnce(req)
	if err != nil {
		// Definitive server-side rejection: nothing is pending, drop the
		// journaled intent and report the plain error.
		if derr := ctx.dropRecord(d, true); derr != nil {
			return derr
		}
		return WrapErrorf(err, DefaultErrorMsg, appId, "POST /pop/v1/sam/app/deployApplication", AlibabaCloudSdkGoERROR)
	}

	if ambiguousErr != nil {
		// Ambiguous submit: never resubmit. Try to attribute the change
		// order by its recovery token; unresolved stays fail-closed.
		item, corrErr := ctx.correlateByToken(rec)
		if corrErr != nil {
			return saeDeployRecoveryUnknownError(appId, rec, ctx.journal.recordPath(ctx.accountId, appId), corrErr)
		}
		if item == nil {
			return saeDeployRecoveryUnknownError(appId, rec, ctx.journal.recordPath(ctx.accountId, appId), ambiguousErr)
		}
		rec.ChangeOrderId = fmt.Sprint(item["ChangeOrderId"])
		if err := ctx.persistRecord(d, rec, true); err != nil {
			return err
		}
	} else {
		data, ok := response["Data"].(map[string]interface{})
		if !ok || fmt.Sprint(data["ChangeOrderId"]) == "" {
			// The request was accepted but returned no change order id;
			// attribute it through the history instead of guessing.
			item, corrErr := ctx.correlateByToken(rec)
			if corrErr != nil {
				return saeDeployRecoveryUnknownError(appId, rec, ctx.journal.recordPath(ctx.accountId, appId), corrErr)
			}
			if item == nil {
				return saeDeployRecoveryUnknownError(appId, rec, ctx.journal.recordPath(ctx.accountId, appId), fmt.Errorf("DeployApplication returned success without a ChangeOrderId"))
			}
			rec.ChangeOrderId = fmt.Sprint(item["ChangeOrderId"])
		} else {
			rec.ChangeOrderId = fmt.Sprint(data["ChangeOrderId"])
		}
		if err := ctx.persistRecord(d, rec, true); err != nil {
			return err
		}
	}

	resolvedSuccess, err := ctx.resolvePendingChangeOrder(d, rec, true)
	if err != nil {
		return err
	}
	if !resolvedSuccess {
		return saeDeployRecoveryUnknownError(appId, rec, ctx.journal.recordPath(ctx.accountId, appId), fmt.Errorf("change order %s did not reach a terminal success state", rec.ChangeOrderId))
	}
	return nil
}

// gate is the read/refresh path: it reconciles the pending record on a
// best-effort basis and fails closed while the outcome is unknown or still
// running, so refresh can never silently mask an ambiguous deploy as
// converged. It never submits and never waits long.
func (ctx *saeDeployRecoveryContext) gate(d *schema.ResourceData) error {
	appId := d.Id()

	// A missing journal directory means this runner has no local record;
	// fall back to the state record only.
	journalPresent := ctx.journal.exists(ctx.accountId, appId)
	if journalPresent {
		unlock, err := ctx.journal.lock(ctx.accountId, appId, false)
		if err != nil {
			return err
		}
		defer unlock()
	}

	if saeDeployForceClearPendingRequested() {
		// Operator escape hatch on the refresh path: drop the pending
		// record without verification and let refresh proceed. The update
		// path refuses to submit while the switch stays set, so a following
		// apply in this run fails closed until the variable is unset.
		log.Printf("[WARN] %s is set: dropping any pending deploy recovery record of application %s without verification, as explicitly requested", saeDeployForceClearEnvVar, appId)
		return ctx.dropRecord(d, false)
	}

	rec, err := ctx.loadMergedRecord(d, false)
	if err != nil {
		return err
	}
	if rec == nil {
		return nil
	}
	// Surface a journal-only record (process kill before state was
	// persisted) in state so it becomes visible and refresh-durable. The
	// state copy never carries the digest key.
	if err := ctx.persistRecord(d, rec, false); err != nil {
		return err
	}

	if rec.Failed {
		// Already reported by a previous invocation; the update path drops
		// the record and submits fresh. Refresh may proceed.
		return nil
	}

	// Resolve once without long waits: adopt a correlatable change order id,
	// then classify its current status.
	if rec.ChangeOrderId == "" {
		items, err := listAllSaeDeployChangeOrders(ctx.remote, appId)
		if err != nil {
			return saeDeployRecoveryUnknownError(appId, rec, ctx.journal.recordPath(ctx.accountId, appId), err)
		}
		if item, found := findSaeDeployChangeOrderByToken(items, appId, rec); found {
			rec.ChangeOrderId = fmt.Sprint(item["ChangeOrderId"])
			if err := ctx.persistRecord(d, rec, false); err != nil {
				return err
			}
		}
	}

	if rec.ChangeOrderId == "" {
		return saeDeployRecoveryUnknownError(appId, rec, ctx.journal.recordPath(ctx.accountId, appId), fmt.Errorf("no change order with the recovery token appeared in the history yet"))
	}

	object, err := ctx.remote.describeChangeOrder(rec.ChangeOrderId)
	if err != nil {
		return saeDeployRecoveryUnknownError(appId, rec, ctx.journal.recordPath(ctx.accountId, appId), err)
	}
	switch classifySaeChangeOrderStatus(fmt.Sprint(object["Status"])) {
	case saeChangeOrderOutcomeSucceeded:
		return ctx.dropRecord(d, false)
	case saeChangeOrderOutcomeFailed:
		rec.Failed = true
		if err := ctx.persistRecord(d, rec, false); err != nil {
			return err
		}
		return nil
	default:
		return saeDeployRecoveryUnknownError(appId, rec, ctx.journal.recordPath(ctx.accountId, appId), fmt.Errorf("change order %s is still in a non-terminal status %s (SubStatus=%s)", rec.ChangeOrderId, fmt.Sprint(object["Status"]), fmt.Sprint(object["SubStatus"])))
	}
}

// saeDeployApplicationWithRecovery replaces the bare DeployApplication POST
// in the resource update path.
func saeDeployApplicationWithRecovery(d *schema.ResourceData, client *connectivity.AliyunClient, req map[string]*string) error {
	ctx, err := newSaeDeployRecoveryContext(d, client)
	if err != nil {
		return err
	}
	return ctx.execute(d, req)
}

// saeDeployRecoveryReadGate is invoked at the end of the resource read so a
// pending ambiguous deploy fails closed instead of passing as converged.
func saeDeployRecoveryReadGate(d *schema.ResourceData, client *connectivity.AliyunClient) error {
	if _, ok := d.GetOk(saeDeployRecoveryAttrName); !ok && !journalRecordExists(d, client) {
		// Fast path: nothing pending in state and no local journal record.
		return nil
	}
	ctx, err := newSaeDeployRecoveryContext(d, client)
	if err != nil {
		return err
	}
	return ctx.gate(d)
}

func journalRecordExists(d *schema.ResourceData, client *connectivity.AliyunClient) bool {
	journal, err := defaultSaeDeployJournal()
	if err != nil {
		return false
	}
	accountId, err := client.AccountId()
	if err != nil {
		accountId = ""
	}
	return journal.exists(accountId, d.Id())
}
