package detect

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// adjudicationFilePerm mirrors the convention used for report files.
const adjudicationFilePerm = 0o600

// ErrAdjudicationFormat is returned when the adjudication path requests an
// unsupported format. The record is JSON only.
var ErrAdjudicationFormat = errors.New("adjudication record supports only the JSON format (use a .json path)")

// WriteAdjudicationReport renders and atomically writes the adjudication
// record. It either leaves a complete, valid file behind or fails without
// leaving a partial record: the JSON is encoded into memory first, then
// written via a temp file in the same directory and renamed into place.
func WriteAdjudicationReport(d *Detector) error {
	report, ok := d.FinalizeAdjudication()
	if !ok {
		return nil
	}
	path := d.AdjudicationPath
	if path == "" {
		return nil
	}
	if ext := filepath.Ext(path); ext != "" && ext != ".json" {
		return ErrAdjudicationFormat
	}

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetIndent("", " ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(report); err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, ".adjudication-*.json.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.Write(buf.Bytes()); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Chmod(tmpName, adjudicationFilePerm); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}
