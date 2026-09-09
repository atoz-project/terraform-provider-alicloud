package alicloud

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/stretchr/testify/assert"
)

// fakeSaeDeployRemote scripts the SAE API surface used by the recovery
// engine without any cloud access.
type fakeSaeDeployRemote struct {
	submitCalls    int
	submittedDescs []string
	submittedReqs  []map[string]*string
	submitFunc     func(req map[string]*string) (map[string]interface{}, error)
	describeFunc   func(changeOrderId string) (map[string]interface{}, error)
	listFunc       func(appId string, currentPage, pageSize int) ([]map[string]interface{}, int, error)
}

func (f *fakeSaeDeployRemote) submitDeployOnce(req map[string]*string) (map[string]interface{}, error) {
	f.submitCalls++
	if v, ok := req["ChangeOrderDesc"]; ok && v != nil {
		f.submittedDescs = append(f.submittedDescs, *v)
	}
	// Deep-copy the request so later mutations (e.g. ChangeOrderDesc) don't affect the recorded payload.
	copied := make(map[string]*string, len(req))
	for k, v := range req {
		if v != nil {
			val := *v
			copied[k] = &val
		} else {
			copied[k] = nil
		}
	}
	f.submittedReqs = append(f.submittedReqs, copied)
	return f.submitFunc(req)
}

func (f *fakeSaeDeployRemote) describeChangeOrder(changeOrderId string) (map[string]interface{}, error) {
	return f.describeFunc(changeOrderId)
}

func (f *fakeSaeDeployRemote) listChangeOrdersPage(appId string, currentPage, pageSize int) ([]map[string]interface{}, int, error) {
	return f.listFunc(appId, currentPage, pageSize)
}

func newTestSaeDeployRecoveryContext(remote saeDeployRemote, journalDir string) *saeDeployRecoveryContext {
	return &saeDeployRecoveryContext{
		remote:    remote,
		journal:   &saeDeployJournal{dir: journalDir},
		accountId: "123456789012",
		timeouts: saeDeployRecoveryTimeouts{
			submitRetry:  20 * time.Millisecond,
			correlate:    100 * time.Millisecond,
			observe:      15 * time.Second,
			pollInterval: 2 * time.Millisecond,
		},
	}
}

func newTestSaeDeployResourceData(t *testing.T, appId string) *schema.ResourceData {
	d, err := schema.InternalMap(resourceAliCloudSaeApplication().Schema).Data(nil, nil)
	assert.Nil(t, err)
	d.SetId(appId)
	d.Partial(true)
	return d
}

func testSaeDeployRequest(appId string) map[string]*string {
	return map[string]*string{
		"AppId":    StringPointer(appId),
		"Replicas": StringPointer("2"),
		"ImageUrl": StringPointer("registry-vpc.example.com/app:v1"),
		// Secret-bearing fields must never leak into digests,
		// descriptions, journals or diagnostics.
		"Envs":        StringPointer(`[{"name":"DB_PASSWORD","value":"s3cr3t"}]`),
		"OssAkSecret": StringPointer("oss-secret-value"),
	}
}

func loadTestJournalRecord(t *testing.T, journalDir, accountId, appId string) *saeDeployRecoveryRecord {
	journal := &saeDeployJournal{dir: journalDir}
	rec, err := journal.load(accountId, appId)
	assert.Nil(t, err)
	return rec
}

func deployOkResponse(changeOrderId string) map[string]interface{} {
	return map[string]interface{}{
		"Data": map[string]interface{}{"ChangeOrderId": changeOrderId},
	}
}

func changeOrderHistoryItem(appId, changeOrderId, description, status string) map[string]interface{} {
	return map[string]interface{}{
		"AppId":         appId,
		"ChangeOrderId": changeOrderId,
		"Description":   description,
		"Status":        json.Number(status),
	}
}

func transportError() error {
	return fmt.Errorf(`Post "https://sae.cn-beijing.aliyuncs.com/pop/v1/sam/app/deployApplication": read tcp 10.0.0.2:51514->100.100.0.1:443: read: connection reset by peer`)
}

// An ambiguous submit (transport EOF after the request may have been
// accepted) must be dispatched exactly once and must be attributed through
// the embedded recovery token instead of being resubmitted.
func TestUnitSaeDeployRecoveryAmbiguousSubmitCountedOnce(t *testing.T) {
	appId := "app-counted-once"
	remote := &fakeSaeDeployRemote{
		submitFunc: func(req map[string]*string) (map[string]interface{}, error) {
			return nil, transportError()
		},
		listFunc: func(appId string, currentPage, pageSize int) ([]map[string]interface{}, int, error) {
			return nil, 0, fmt.Errorf("unused")
		},
		describeFunc: func(changeOrderId string) (map[string]interface{}, error) {
			return map[string]interface{}{"Status": json.Number("2"), "SubStatus": json.Number("0")}, nil
		},
	}
	// The change order history answers with a change order carrying the
	// exact recovery token that was embedded in the submitted description.
	remote.listFunc = func(appId string, currentPage, pageSize int) ([]map[string]interface{}, int, error) {
		assert.Len(t, remote.submittedDescs, 1)
		return []map[string]interface{}{
			changeOrderHistoryItem(appId, "co-adopted", remote.submittedDescs[0], "1"),
		}, 1, nil
	}

	d := newTestSaeDeployResourceData(t, appId)
	ctx := newTestSaeDeployRecoveryContext(remote, t.TempDir())

	err := ctx.execute(d, testSaeDeployRequest(appId))
	assert.Nil(t, err)
	assert.Equal(t, 1, remote.submitCalls, "the ambiguous deploy request must be counted exactly once")
	assert.Equal(t, "", d.Get(saeDeployRecoveryAttrName).(string), "recovery record must be dropped after the adopted change order succeeded")
	assert.Nil(t, loadTestJournalRecord(t, ctx.journal.dir, ctx.accountId, appId), "journal record must be removed after success")
	assert.True(t, strings.HasPrefix(remote.submittedDescs[0], saeDeployDescPrefix))
	assert.NotContains(t, remote.submittedDescs[0], "s3cr3t")
	assert.NotContains(t, remote.submittedDescs[0], "oss-secret-value")
}

// An ambiguous submit whose change order never becomes attributable must
// fail closed: no resubmission, recovery record kept in state and journal.
func TestUnitSaeDeployRecoveryAmbiguousSubmitUnresolvedFailClosed(t *testing.T) {
	appId := "app-unresolved"
	remote := &fakeSaeDeployRemote{
		submitFunc: func(req map[string]*string) (map[string]interface{}, error) {
			return nil, transportError()
		},
		listFunc: func(appId string, currentPage, pageSize int) ([]map[string]interface{}, int, error) {
			// Zero matches is NOT proof that the request never landed.
			return []map[string]interface{}{}, 0, nil
		},
		describeFunc: func(changeOrderId string) (map[string]interface{}, error) {
			return nil, fmt.Errorf("unused")
		},
	}
	d := newTestSaeDeployResourceData(t, appId)
	journalDir := t.TempDir()
	ctx := newTestSaeDeployRecoveryContext(remote, journalDir)

	err := ctx.execute(d, testSaeDeployRequest(appId))
	assert.NotNil(t, err)
	assert.Equal(t, 1, remote.submitCalls, "an unresolved ambiguous submit must never be resubmitted")
	assert.Contains(t, err.Error(), "unknown")

	raw := d.Get(saeDeployRecoveryAttrName).(string)
	assert.NotEqual(t, "", raw, "the pending recovery record must survive the failed apply in state")
	rec := parseSaeDeployRecoveryRecord(raw)
	assert.NotNil(t, rec)
	assert.NotEmpty(t, rec.Token)
	assert.Equal(t, "", rec.ChangeOrderId)
	assert.NotNil(t, loadTestJournalRecord(t, journalDir, ctx.accountId, appId), "the journal record must survive on disk")
}

// A crashed apply (journal only, no state record — process killed before
// state was persisted) must be recovered by the next execution through the
// durable journal, without a second submission.
func TestUnitSaeDeployRecoveryRecoverNextExecution(t *testing.T) {
	appId := "app-recover"
	journalDir := t.TempDir()

	// First invocation: ambiguous submit, history not yet attributable.
	remote1 := &fakeSaeDeployRemote{
		submitFunc: func(req map[string]*string) (map[string]interface{}, error) {
			return nil, transportError()
		},
		listFunc: func(appId string, currentPage, pageSize int) ([]map[string]interface{}, int, error) {
			return []map[string]interface{}{}, 0, nil
		},
		describeFunc: func(changeOrderId string) (map[string]interface{}, error) {
			return nil, fmt.Errorf("unused")
		},
	}
	ctx1 := newTestSaeDeployRecoveryContext(remote1, journalDir)
	d1 := newTestSaeDeployResourceData(t, appId)
	assert.NotNil(t, ctx1.execute(d1, testSaeDeployRequest(appId)))
	assert.Equal(t, 1, remote1.submitCalls)

	rec := loadTestJournalRecord(t, journalDir, ctx1.accountId, appId)
	assert.NotNil(t, rec)
	desc := composeSaeDeployChangeOrderDesc(rec.Digest, rec.Token, "")

	// Second invocation simulates a process kill before state persistence:
	// fresh ResourceData without the state attribute; only the journal
	// carries the pending intent. The change order now exists and
	// succeeded, so the execution must NOT submit again.
	remote2 := &fakeSaeDeployRemote{
		submitFunc: func(req map[string]*string) (map[string]interface{}, error) {
			return deployOkResponse("co-should-not-happen"), nil
		},
		listFunc: func(appId string, currentPage, pageSize int) ([]map[string]interface{}, int, error) {
			return []map[string]interface{}{
				changeOrderHistoryItem(appId, "co-real", desc, "1"),
			}, 1, nil
		},
		describeFunc: func(changeOrderId string) (map[string]interface{}, error) {
			assert.Equal(t, "co-real", changeOrderId)
			return map[string]interface{}{"Status": json.Number("2"), "SubStatus": json.Number("0")}, nil
		},
	}
	ctx2 := newTestSaeDeployRecoveryContext(remote2, journalDir)
	d2 := newTestSaeDeployResourceData(t, appId)

	err := ctx2.execute(d2, testSaeDeployRequest(appId))
	assert.Nil(t, err)
	assert.Equal(t, 0, remote2.submitCalls, "a recovered successful deploy must not be resubmitted (counted once)")
	assert.Equal(t, "", d2.Get(saeDeployRecoveryAttrName).(string))
	assert.Nil(t, loadTestJournalRecord(t, journalDir, ctx2.accountId, appId))
}

// A terminal change order failure (documented statuses 3/6/10) must be
// reported as a failure, must not be mistaken for success, and must not be
// resubmitted inside the invocation that first observes it. The next
// invocation may submit one fresh deploy because the failure evidence is
// unambiguous.
func TestUnitSaeDeployRecoveryTerminalFailureNotSuccess(t *testing.T) {
	appId := "app-terminal-failure"
	journalDir := t.TempDir()

	remote1 := &fakeSaeDeployRemote{
		submitFunc: func(req map[string]*string) (map[string]interface{}, error) {
			return deployOkResponse("co-failed"), nil
		},
		listFunc: func(appId string, currentPage, pageSize int) ([]map[string]interface{}, int, error) {
			return nil, 0, fmt.Errorf("unused")
		},
		describeFunc: func(changeOrderId string) (map[string]interface{}, error) {
			return map[string]interface{}{
				"Status":       json.Number("3"),
				"SubStatus":    json.Number("0"),
				"ErrorMessage": "image pull backoff",
			}, nil
		},
	}
	ctx1 := newTestSaeDeployRecoveryContext(remote1, journalDir)
	d1 := newTestSaeDeployResourceData(t, appId)

	err := ctx1.execute(d1, testSaeDeployRequest(appId))
	assert.NotNil(t, err, "a terminal change order failure must not pass as success")
	assert.Contains(t, err.Error(), "terminal failure")
	assert.Equal(t, 1, remote1.submitCalls, "no automatic resubmission after a terminal failure")

	rec := parseSaeDeployRecoveryRecord(d1.Get(saeDeployRecoveryAttrName).(string))
	assert.NotNil(t, rec)
	assert.True(t, rec.Failed, "the observed failure must be recorded durably")
	assert.Equal(t, "co-failed", rec.ChangeOrderId)

	// Next invocation: the failure was already reported, so the recorded
	// Failed flag clears the way for exactly one fresh submit.
	remote2 := &fakeSaeDeployRemote{
		submitFunc: func(req map[string]*string) (map[string]interface{}, error) {
			return deployOkResponse("co-retry"), nil
		},
		listFunc: func(appId string, currentPage, pageSize int) ([]map[string]interface{}, int, error) {
			return nil, 0, fmt.Errorf("unused")
		},
		describeFunc: func(changeOrderId string) (map[string]interface{}, error) {
			return map[string]interface{}{"Status": json.Number("2"), "SubStatus": json.Number("0")}, nil
		},
	}
	ctx2 := newTestSaeDeployRecoveryContext(remote2, journalDir)
	err = ctx2.execute(d1, testSaeDeployRequest(appId))
	assert.Nil(t, err)
	assert.Equal(t, 1, remote2.submitCalls)
	assert.Equal(t, "", d1.Get(saeDeployRecoveryAttrName).(string))
}

// The read/refresh path must fail closed while a pending change order is
// still running or unknown, and must only drop the record on documented
// terminal evidence.
func TestUnitSaeDeployRecoveryReadGate(t *testing.T) {
	appId := "app-read-gate"

	newPendingRecord := func(t *testing.T, ctx *saeDeployRecoveryContext, appId string, changeOrderId string) *saeDeployRecoveryRecord {
		rec, err := newSaeDeployRecoveryRecord(appId, ctx.accountId, testSaeDeployRequest(appId))
		assert.Nil(t, err)
		rec.ChangeOrderId = changeOrderId
		assert.Nil(t, ctx.journal.store(rec))
		return rec
	}

	t.Run("running change order fails closed", func(t *testing.T) {
		ctx := newTestSaeDeployRecoveryContext(&fakeSaeDeployRemote{
			submitFunc: func(req map[string]*string) (map[string]interface{}, error) { return nil, fmt.Errorf("unused") },
			listFunc: func(appId string, currentPage, pageSize int) ([]map[string]interface{}, int, error) {
				return nil, 0, fmt.Errorf("unused")
			},
			describeFunc: func(changeOrderId string) (map[string]interface{}, error) {
				return map[string]interface{}{"Status": json.Number("1"), "SubStatus": json.Number("0")}, nil
			},
		}, t.TempDir())
		newPendingRecord(t, ctx, appId, "co-running")
		d := newTestSaeDeployResourceData(t, appId)

		err := ctx.gate(d)
		assert.NotNil(t, err, "refresh must fail closed while the deploy is still running")
		assert.NotNil(t, loadTestJournalRecord(t, ctx.journal.dir, ctx.accountId, appId), "record must be kept")
	})

	t.Run("succeeded change order clears the record", func(t *testing.T) {
		ctx := newTestSaeDeployRecoveryContext(&fakeSaeDeployRemote{
			submitFunc: func(req map[string]*string) (map[string]interface{}, error) { return nil, fmt.Errorf("unused") },
			listFunc: func(appId string, currentPage, pageSize int) ([]map[string]interface{}, int, error) {
				return nil, 0, fmt.Errorf("unused")
			},
			describeFunc: func(changeOrderId string) (map[string]interface{}, error) {
				return map[string]interface{}{"Status": json.Number("2"), "SubStatus": json.Number("0")}, nil
			},
		}, t.TempDir())
		newPendingRecord(t, ctx, appId, "co-succeeded")
		d := newTestSaeDeployResourceData(t, appId)

		assert.Nil(t, ctx.gate(d))
		assert.Equal(t, "", d.Get(saeDeployRecoveryAttrName).(string))
		assert.Nil(t, loadTestJournalRecord(t, ctx.journal.dir, ctx.accountId, appId))
	})

	t.Run("unattributable change order fails closed", func(t *testing.T) {
		ctx := newTestSaeDeployRecoveryContext(&fakeSaeDeployRemote{
			submitFunc: func(req map[string]*string) (map[string]interface{}, error) { return nil, fmt.Errorf("unused") },
			listFunc: func(appId string, currentPage, pageSize int) ([]map[string]interface{}, int, error) {
				return []map[string]interface{}{
					// Same application but a different token: not ours.
					changeOrderHistoryItem(appId, "co-foreign", "tf-deploy:abcdef123456:00000000-0000-0000-0000-000000000000", "2"),
				}, 1, nil
			},
			describeFunc: func(changeOrderId string) (map[string]interface{}, error) {
				return nil, fmt.Errorf("unused")
			},
		}, t.TempDir())
		newPendingRecord(t, ctx, appId, "")
		d := newTestSaeDeployResourceData(t, appId)

		err := ctx.gate(d)
		assert.NotNil(t, err, "zero exact-token matches must fail closed, not clear the record")
		assert.NotNil(t, loadTestJournalRecord(t, ctx.journal.dir, ctx.accountId, appId))
	})

	t.Run("terminal failure is recorded and refresh proceeds", func(t *testing.T) {
		ctx := newTestSaeDeployRecoveryContext(&fakeSaeDeployRemote{
			submitFunc: func(req map[string]*string) (map[string]interface{}, error) { return nil, fmt.Errorf("unused") },
			listFunc: func(appId string, currentPage, pageSize int) ([]map[string]interface{}, int, error) {
				return nil, 0, fmt.Errorf("unused")
			},
			describeFunc: func(changeOrderId string) (map[string]interface{}, error) {
				return map[string]interface{}{"Status": json.Number("10"), "SubStatus": json.Number("0")}, nil
			},
		}, t.TempDir())
		newPendingRecord(t, ctx, appId, "co-system-fail")
		d := newTestSaeDeployResourceData(t, appId)

		assert.Nil(t, ctx.gate(d))
		rec := parseSaeDeployRecoveryRecord(d.Get(saeDeployRecoveryAttrName).(string))
		assert.NotNil(t, rec)
		assert.True(t, rec.Failed)
	})

	t.Run("operator force clear drops the pending record", func(t *testing.T) {
		ctx := newTestSaeDeployRecoveryContext(&fakeSaeDeployRemote{
			submitFunc: func(req map[string]*string) (map[string]interface{}, error) { return nil, fmt.Errorf("unused") },
			listFunc: func(appId string, currentPage, pageSize int) ([]map[string]interface{}, int, error) {
				return nil, 0, fmt.Errorf("must not be called after a force clear")
			},
			describeFunc: func(changeOrderId string) (map[string]interface{}, error) {
				return nil, fmt.Errorf("must not be called after a force clear")
			},
		}, t.TempDir())
		newPendingRecord(t, ctx, appId, "co-force-cleared")
		d := newTestSaeDeployResourceData(t, appId)

		os.Setenv(saeDeployForceClearEnvVar, "true")
		defer os.Unsetenv(saeDeployForceClearEnvVar)
		assert.Nil(t, ctx.gate(d))
		assert.Equal(t, "", d.Get(saeDeployRecoveryAttrName).(string))
		assert.Nil(t, loadTestJournalRecord(t, ctx.journal.dir, ctx.accountId, appId))
	})
}

// A known change order id must be observed (tolerating transient NotFound
// reads) instead of being resubmitted.
func TestUnitSaeDeployRecoveryKnownChangeOrderObserved(t *testing.T) {
	appId := "app-known-co"
	journalDir := t.TempDir()

	describeCalls := 0
	remote := &fakeSaeDeployRemote{
		submitFunc: func(req map[string]*string) (map[string]interface{}, error) {
			return deployOkResponse("co-should-not-happen"), nil
		},
		listFunc: func(appId string, currentPage, pageSize int) ([]map[string]interface{}, int, error) {
			return nil, 0, fmt.Errorf("unused")
		},
		describeFunc: func(changeOrderId string) (map[string]interface{}, error) {
			describeCalls++
			if describeCalls == 1 {
				return nil, GetNotFoundErrorFromString("InvalidChangeOrder.NotFound: The current change order does not exist.")
			}
			return map[string]interface{}{"Status": json.Number("2"), "SubStatus": json.Number("0")}, nil
		},
	}
	ctx := newTestSaeDeployRecoveryContext(remote, journalDir)

	rec, err := newSaeDeployRecoveryRecord(appId, ctx.accountId, testSaeDeployRequest(appId))
	assert.Nil(t, err)
	rec.ChangeOrderId = "co-known"
	d := newTestSaeDeployResourceData(t, appId)
	assert.Nil(t, ctx.persistRecord(d, rec, true))

	err = ctx.execute(d, testSaeDeployRequest(appId))
	assert.Nil(t, err)
	assert.Equal(t, 0, remote.submitCalls, "a known change order must be observed, not resubmitted")
	assert.Equal(t, "", d.Get(saeDeployRecoveryAttrName).(string))
}

// The keyed digest must cover the COMPLETE request (secret-bearing fields
// included), must change with any request change, and must only be
// verifiable with the journal-held key. The composed change order
// description must keep the correlation token intact under truncation.
func TestUnitSaeDeployRecoveryDigestAndDesc(t *testing.T) {
	appId := "app-digest"
	base := testSaeDeployRequest(appId)
	key := []byte("0123456789abcdef0123456789abcdef")

	assert.Equal(t, saeDeployRequestDigest(key, base), saeDeployRequestDigest(key, testSaeDeployRequest(appId)), "identical requests must digest identically")

	secretChanged := testSaeDeployRequest(appId)
	secretChanged["Envs"] = StringPointer(`[{"name":"DB_PASSWORD","value":"0th3r-s3cr3t"}]`)
	secretChanged["OssAkSecret"] = StringPointer("other-oss-secret")
	secretChanged["JarStartOptions"] = StringPointer("-Dpassword=abc")
	assert.NotEqual(t, saeDeployRequestDigest(key, base), saeDeployRequestDigest(key, secretChanged), "secret-bearing fields must be covered by the digest")

	imageChanged := testSaeDeployRequest(appId)
	imageChanged["ImageUrl"] = StringPointer("registry-vpc.example.com/app:v2")
	assert.NotEqual(t, saeDeployRequestDigest(key, base), saeDeployRequestDigest(key, imageChanged))

	descChanged := testSaeDeployRequest(appId)
	descChanged["ChangeOrderDesc"] = StringPointer("some operator note")
	assert.Equal(t, saeDeployRequestDigest(key, base), saeDeployRequestDigest(key, descChanged), "the correlation description is metadata, not deployment identity")

	otherKey := []byte("fedcba9876543210fedcba9876543210")
	assert.NotEqual(t, saeDeployRequestDigest(key, base), saeDeployRequestDigest(otherKey, base), "the digest is keyed")

	digest := saeDeployRequestDigest(key, base)
	desc := composeSaeDeployChangeOrderDesc(digest, "11111111-2222-3333-4444-555555555555", strings.Repeat("user-note ", 30))
	assert.LessOrEqual(t, len(desc), saeDeployDescMaxLength)
	digest12, token, ok := parseSaeDeployChangeOrderDesc(desc)
	assert.True(t, ok, "the correlation token must survive truncation of the user suffix")
	assert.Equal(t, saeDeployDigestShort(digest), digest12)
	assert.Equal(t, "11111111-2222-3333-4444-555555555555", token)
	assert.NotContains(t, desc, "s3cr3t")

	_, _, ok = parseSaeDeployChangeOrderDesc("a description written by hand")
	assert.False(t, ok)
}

// Regression test for the reported bug: a for_each instance (e.g. release["green"])
// with image_url change must include the target ImageUrl in the actual submit payload.
// The recovery engine must not drop or override it.
func TestUnitSaeDeployRecoveryForEachImageUrlInPayload(t *testing.T) {
	appId := "app-for-each-green"
	remote := &fakeSaeDeployRemote{
		submitFunc: func(req map[string]*string) (map[string]interface{}, error) {
			return deployOkResponse("co-foreach-green"), nil
		},
		listFunc: func(appId string, currentPage, pageSize int) ([]map[string]interface{}, int, error) {
			return nil, 0, fmt.Errorf("unused")
		},
		describeFunc: func(changeOrderId string) (map[string]interface{}, error) {
			return map[string]interface{}{"Status": json.Number("2"), "SubStatus": json.Number("0")}, nil
		},
	}
	ctx := newTestSaeDeployRecoveryContext(remote, t.TempDir())
	d := newTestSaeDeployResourceData(t, appId)

	// Simulate for_each green instance with image_url change.
	req := testSaeDeployRequest(appId)
	req["ImageUrl"] = StringPointer("registry-vpc.example.com/app:v20260909-1400")

	assert.Nil(t, ctx.execute(d, req))

	// The submitted request must contain the target ImageUrl.
	assert.Equal(t, 1, remote.submitCalls)
	submitted := remote.submittedReqs[0]
	assert.Equal(t, "registry-vpc.example.com/app:v20260909-1400", *submitted["ImageUrl"],
		"ImageUrl must be present in the actual submit payload for for_each green instance")
}

func TestUnitSaeDeployRecoveryDigestMatches(t *testing.T) {
	appId := "app-digest"
	base := testSaeDeployRequest(appId)
	secretChanged := testSaeDeployRequest(appId)
	secretChanged["Envs"] = StringPointer(`[{"name":"DB_PASSWORD","value":"0th3r-s3cr3t"}]`)
	secretChanged["OssAkSecret"] = StringPointer("other-oss-secret")
	secretChanged["JarStartOptions"] = StringPointer("-Dpassword=abc")
	rec, err := newSaeDeployRecoveryRecord(appId, "123456789012", base)
	assert.Nil(t, err)
	assert.True(t, rec.digestMatches(base))
	assert.False(t, rec.digestMatches(secretChanged))
	stateRec := *rec
	stateRec.DigestKey = ""
	assert.False(t, stateRec.digestMatches(base))

	// persistRecord must journal the full record but strip the key from
	// the Terraform state copy.
	ctx := newTestSaeDeployRecoveryContext(&fakeSaeDeployRemote{}, t.TempDir())
	d := newTestSaeDeployResourceData(t, appId)
	assert.Nil(t, ctx.persistRecord(d, rec, true))
	assert.NotContains(t, d.Get(saeDeployRecoveryAttrName).(string), "digest_key", "the digest key must never reach Terraform state")
	journalRec := loadTestJournalRecord(t, ctx.journal.dir, ctx.accountId, appId)
	assert.NotNil(t, journalRec)
	assert.NotEmpty(t, journalRec.DigestKey, "the journal must keep the digest key")
}

// Documented change order status mapping: only 2 is success, 3/6/10 are
// terminal failures, everything else stays in-flight (fail-safe).
func TestUnitSaeDeployChangeOrderStatusClassification(t *testing.T) {
	assert.Equal(t, saeChangeOrderOutcomeSucceeded, classifySaeChangeOrderStatus("2"))
	for _, s := range []string{"3", "6", "10"} {
		assert.Equal(t, saeChangeOrderOutcomeFailed, classifySaeChangeOrderStatus(s), "documented terminal failure status %s", s)
	}
	for _, s := range []string{"0", "1", "8", "9", "11", "12", "", "42", "unknown"} {
		assert.Equal(t, saeChangeOrderOutcomeInFlight, classifySaeChangeOrderStatus(s), "status %q must not be treated as terminal", s)
	}
}

// The journal must round-trip records through fsync'd storage and fail
// closed on corrupt content.
func TestUnitSaeDeployRecoveryJournalRoundTrip(t *testing.T) {
	dir := t.TempDir()
	journal := &saeDeployJournal{dir: dir}
	rec, err := newSaeDeployRecoveryRecord("app-journal", "123456789012", testSaeDeployRequest("app-journal"))
	assert.Nil(t, err)
	rec.ChangeOrderId = "co-1"

	assert.Nil(t, journal.store(rec))
	assert.FileExists(t, journal.recordPath(rec.AccountId, rec.AppId))

	loaded, err := journal.load(rec.AccountId, rec.AppId)
	assert.Nil(t, err)
	assert.Equal(t, rec.Token, loaded.Token)
	assert.Equal(t, "co-1", loaded.ChangeOrderId)

	assert.Nil(t, journal.remove(rec.AccountId, rec.AppId))
	loaded, err = journal.load(rec.AccountId, rec.AppId)
	assert.Nil(t, err)
	assert.Nil(t, loaded)

	assert.Nil(t, os.MkdirAll(journal.dir, 0o755))
	assert.Nil(t, os.WriteFile(journal.recordPath(rec.AccountId, rec.AppId), []byte("{corrupt"), 0o644))
	_, err = journal.load(rec.AccountId, rec.AppId)
	assert.NotNil(t, err, "a corrupt journal must fail closed")

	// The journal record file name is scoped by account and application.
	assert.Equal(t, filepath.Join(dir, "123456789012-app-journal.json"), journal.recordPath("123456789012", "app-journal"))
}

// The operator force-clear switch drops the pending record but must STOP
// the whole update: no deploy is ever submitted while it is set, not even
// when refresh already dropped the record earlier in the same run.
func TestUnitSaeDeployRecoveryForceClearStopsUpdate(t *testing.T) {
	appId := "app-force-clear"

	newRemote := func() *fakeSaeDeployRemote {
		return &fakeSaeDeployRemote{
			submitFunc: func(req map[string]*string) (map[string]interface{}, error) {
				return deployOkResponse("co-should-not-happen"), nil
			},
			listFunc: func(appId string, currentPage, pageSize int) ([]map[string]interface{}, int, error) {
				return nil, 0, fmt.Errorf("must not be called after a force clear")
			},
			describeFunc: func(changeOrderId string) (map[string]interface{}, error) {
				return nil, fmt.Errorf("must not be called after a force clear")
			},
		}
	}

	t.Run("pending record dropped and update refused", func(t *testing.T) {
		remote := newRemote()
		ctx := newTestSaeDeployRecoveryContext(remote, t.TempDir())
		rec, err := newSaeDeployRecoveryRecord(appId, ctx.accountId, testSaeDeployRequest(appId))
		assert.Nil(t, err)
		d := newTestSaeDeployResourceData(t, appId)
		assert.Nil(t, ctx.persistRecord(d, rec, true))

		os.Setenv(saeDeployForceClearEnvVar, "true")
		defer os.Unsetenv(saeDeployForceClearEnvVar)
		err = ctx.execute(d, testSaeDeployRequest(appId))
		assert.NotNil(t, err, "force clear must stop the update with an explicit error")
		assert.Contains(t, err.Error(), saeDeployForceClearEnvVar)
		assert.Equal(t, 0, remote.submitCalls, "no deploy may be submitted while force clear is set")
		assert.Equal(t, "", d.Get(saeDeployRecoveryAttrName).(string), "the pending record must be dropped")
		assert.Nil(t, loadTestJournalRecord(t, ctx.journal.dir, ctx.accountId, appId))
	})

	t.Run("no record and update still refused", func(t *testing.T) {
		// Simulates a run in which refresh already dropped the record but
		// the variable is still set when the update path executes.
		remote := newRemote()
		ctx := newTestSaeDeployRecoveryContext(remote, t.TempDir())
		d := newTestSaeDeployResourceData(t, appId)

		os.Setenv(saeDeployForceClearEnvVar, "true")
		defer os.Unsetenv(saeDeployForceClearEnvVar)
		err := ctx.execute(d, testSaeDeployRequest(appId))
		assert.NotNil(t, err, "update must refuse to submit while force clear remains set")
		assert.Equal(t, 0, remote.submitCalls)
	})
}

// A state-only record (no local journal, e.g. another runner) has no
// digest key, so the skip-submission proof is impossible: after the
// pending change order demonstrably succeeded, exactly one deliberate
// fresh deploy is submitted instead of claiming an exact match.
func TestUnitSaeDeployRecoveryStateOnlyRecordCannotSkipSubmit(t *testing.T) {
	appId := "app-state-only"
	journalDir := t.TempDir() // stays empty: no journal record on this runner

	remote := &fakeSaeDeployRemote{
		submitFunc: func(req map[string]*string) (map[string]interface{}, error) {
			return deployOkResponse("co-new"), nil
		},
		listFunc: func(appId string, currentPage, pageSize int) ([]map[string]interface{}, int, error) {
			return nil, 0, fmt.Errorf("unused")
		},
		describeFunc: func(changeOrderId string) (map[string]interface{}, error) {
			return map[string]interface{}{"Status": json.Number("2"), "SubStatus": json.Number("0")}, nil
		},
	}
	ctx := newTestSaeDeployRecoveryContext(remote, journalDir)

	// Persist the record ONLY into state, with the digest key stripped the
	// way persistRecord strips it for the state copy.
	rec, err := newSaeDeployRecoveryRecord(appId, ctx.accountId, testSaeDeployRequest(appId))
	assert.Nil(t, err)
	rec.ChangeOrderId = "co-old"
	stateRec := *rec
	stateRec.DigestKey = ""
	d := newTestSaeDeployResourceData(t, appId)
	assert.Nil(t, persistSaeDeployRecoveryRecord(d, &stateRec, true))

	err = ctx.execute(d, testSaeDeployRequest(appId))
	assert.Nil(t, err)
	assert.Equal(t, 1, remote.submitCalls, "without the digest key no exact-match claim is possible; one deliberate fresh deploy follows a proven success")
	assert.Equal(t, "", d.Get(saeDeployRecoveryAttrName).(string))
}
