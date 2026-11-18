package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/version"
)

// BaselineMetaSchemaVersion is the version of the baseline sidecar format.
// It is bumped whenever the on-disk structure changes incompatibly.
const BaselineMetaSchemaVersion = 1

// BaselineMeta records provenance for a baseline report so incremental scans
// can detect corruption, schema mismatches and rule changes instead of
// silently treating an unknown baseline as empty.
type BaselineMeta struct {
	// SchemaVersion is the version of this sidecar format.
	SchemaVersion int `json:"schema_version"`

	// GitleaksVersion is the binary version that wrote the baseline.
	GitleaksVersion string `json:"gitleaks_version"`

	// RulesChecksum is a stable checksum of the effective rule set.
	RulesChecksum string `json:"rules_checksum"`

	// BaselinePath is the report file the metadata belongs to.
	BaselinePath string `json:"baseline_path"`
}

// RulesChecksum computes a stable checksum of the effective rule set. Only
// rule identity and the regex/keywords/path/entropy inputs that drive
// matching participate, so cosmetic changes elsewhere do not invalidate a
// baseline while any rule change does.
func RulesChecksum(cfg config.Config) string {
	ruleIDs := make([]string, 0, len(cfg.Rules))
	for ruleID := range cfg.Rules {
		ruleIDs = append(ruleIDs, ruleID)
	}
	sort.Strings(ruleIDs)

	hash := sha256.New()
	for _, ruleID := range ruleIDs {
		rule := cfg.Rules[ruleID]
		fmt.Fprintf(hash, "id=%s\n", rule.RuleID)
		if rule.Regex != nil {
			fmt.Fprintf(hash, "regex=%s\n", rule.Regex.String())
		}
		if rule.Path != nil {
			fmt.Fprintf(hash, "path=%s\n", rule.Path.String())
		}
		fmt.Fprintf(hash, "entropy=%v\n", rule.Entropy)
		fmt.Fprintf(hash, "secret_group=%d\n", rule.SecretGroup)

		keywords := append([]string(nil), rule.Keywords...)
		sort.Strings(keywords)
		for _, keyword := range keywords {
			fmt.Fprintf(hash, "keyword=%s\n", keyword)
		}

		tags := append([]string(nil), rule.Tags...)
		sort.Strings(tags)
		for _, tag := range tags {
			fmt.Fprintf(hash, "tag=%s\n", tag)
		}
		hash.Write([]byte{0})
	}

	return hex.EncodeToString(hash.Sum(nil))
}

// BaselineMetaPath returns the sidecar path for a baseline report.
func BaselineMetaPath(baselinePath string) string {
	return baselinePath + ".meta.json"
}

// WriteBaselineMeta writes the metadata sidecar next to the baseline report.
func WriteBaselineMeta(baselinePath string, cfg config.Config) error {
	meta := BaselineMeta{
		SchemaVersion:   BaselineMetaSchemaVersion,
		GitleaksVersion: version.Version,
		RulesChecksum:   RulesChecksum(cfg),
		BaselinePath:    filepath.Base(baselinePath),
	}

	bytes, err := json.MarshalIndent(meta, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(BaselineMetaPath(baselinePath), bytes, 0o600)
}

// LoadBaselineMeta reads and validates a baseline metadata sidecar.
//
// A corrupted file or an unsupported schema version returns an error so the
// caller can fail loudly instead of silently scanning with an empty baseline.
// A missing sidecar is reported with ok=false and a nil error: baselines
// produced by older gitleaks versions remain usable but trigger a warning.
func LoadBaselineMeta(baselinePath string) (meta BaselineMeta, ok bool, err error) {
	metaPath := BaselineMetaPath(baselinePath)
	bytes, readErr := os.ReadFile(metaPath)
	if readErr != nil {
		if os.IsNotExist(readErr) {
			return BaselineMeta{}, false, nil
		}
		return BaselineMeta{}, false, fmt.Errorf("could not read baseline metadata %s: %w", metaPath, readErr)
	}

	if err := json.Unmarshal(bytes, &meta); err != nil {
		return BaselineMeta{}, false, fmt.Errorf("baseline metadata %s is corrupted: %w", metaPath, err)
	}

	if meta.SchemaVersion != BaselineMetaSchemaVersion {
		return BaselineMeta{}, false, fmt.Errorf(
			"baseline metadata %s uses unsupported schema version %d (expected %d); regenerate the baseline",
			metaPath, meta.SchemaVersion, BaselineMetaSchemaVersion,
		)
	}

	return meta, true, nil
}
