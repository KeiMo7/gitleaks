package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zricethezav/gitleaks/v8/logging"
)

const (
	CycloneDXSpecVersion  = "1.5"
	CycloneDXSchemaURL    = "http://cyclonedx.org/schema/bom-1.5.schema.json"
	CycloneDXReportFormat = "cyclonedx"
	CycloneDXReportName   = CycloneDXReportFormat
)

const (
	cycloneDXUnknownValue = "unknown"
	cycloneDXRootName     = "gitleaks-scan"
	cycloneDXPathNS       = "gitleaks-path"
	cycloneDXComponentTyp = "data"
)

// CycloneDXProperty is an arbitrary key/value pair attached to a CycloneDX
// component or the BOM metadata.
type CycloneDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// CycloneDXComponent is the subset of the CycloneDX 1.5 component schema used
// by gitleaks. All fields required by this feature are always emitted.
type CycloneDXComponent struct {
	Type       string              `json:"type"`
	BOMRef     string              `json:"bom-ref"`
	Name       string              `json:"name"`
	Version    string              `json:"version"`
	PURL       string              `json:"purl"`
	Properties []CycloneDXProperty `json:"properties,omitempty"`
}

// CycloneDXMetadata contains the root scan component and report counters.
type CycloneDXMetadata struct {
	Component  CycloneDXComponent  `json:"component"`
	Properties []CycloneDXProperty `json:"properties,omitempty"`
}

// CycloneDXDependency describes direct children of a component. Transitive
// relationships are represented by following the dependency graph.
type CycloneDXDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

// CycloneDXBOM is exported for library users that need to inspect the same
// model produced by CycloneDXReporter. Write streams this model rather than
// marshaling it as one large value.
type CycloneDXBOM struct {
	Schema       string                `json:"$schema"`
	BOMFormat    string                `json:"bomFormat"`
	SpecVersion  string                `json:"specVersion"`
	Version      int                   `json:"version"`
	Metadata     CycloneDXMetadata     `json:"metadata"`
	Components   []CycloneDXComponent  `json:"components"`
	Dependencies []CycloneDXDependency `json:"dependencies"`
}

// CycloneDXReporter writes CycloneDX 1.5 JSON reports.
type CycloneDXReporter struct{}

// CycloneDxReporter is kept as an alias for callers using the common Go
// initialism spelling.
type CycloneDxReporter = CycloneDXReporter

var _ Reporter = (*CycloneDXReporter)(nil)

// NewCycloneDXReporter creates a stateless CycloneDX reporter. Instances are
// safe to reuse and call concurrently.
func NewCycloneDXReporter() *CycloneDXReporter {
	return &CycloneDXReporter{}
}

// NewCycloneDxReporter is an alias for callers using the common Go initialism
// spelling.
func NewCycloneDxReporter() *CycloneDxReporter {
	return NewCycloneDXReporter()
}

// Write builds the deterministic dependency graph and streams each component
// to w as soon as it has been mapped and validated.
func (r *CycloneDXReporter) Write(w io.WriteCloser, findings []Finding) (err error) {
	logger := logging.With().Str("format", CycloneDXReportFormat).Logger()
	logger.Debug().Int("findings", len(findings)).Msg("cyclonedx report: enter")
	defer func() {
		if err != nil {
			logger.Error().Err(err).Msg("cyclonedx report: failed")
			return
		}
		logger.Debug().Msg("cyclonedx report: exit")
	}()

	bom, err := BuildCycloneDXBOM(findings)
	if err != nil {
		return fmt.Errorf("build cyclonedx report: %w", err)
	}
	if err = ValidateCycloneDXBOM(bom); err != nil {
		return fmt.Errorf("validate cyclonedx report: %w", err)
	}

	if err = writeCycloneDXBOM(w, bom); err != nil {
		return fmt.Errorf("write cyclonedx report: %w", err)
	}
	return nil
}

// BuildCycloneDXBOM maps findings to a deterministic CycloneDX model. It is
// exported so callers can validate or inspect the model before writing it.
func BuildCycloneDXBOM(findings []Finding) (*CycloneDXBOM, error) {
	state := newCycloneDXBuildState(findings)
	return state.build()
}

// ValidateCycloneDXBOM performs the component-level checks needed to produce a
// useful error before a partial report is emitted. Full schema validation is
// covered by the test suite using the official CycloneDX schema.
func ValidateCycloneDXBOM(bom *CycloneDXBOM) error {
	if bom == nil {
		return fmt.Errorf("component %q: BOM is nil", cycloneDXUnknownValue)
	}

	refs := make(map[string]string, len(bom.Components)+1)
	rootRef := bom.Metadata.Component.BOMRef
	if err := validateCycloneDXComponent(bom.Metadata.Component); err != nil {
		return err
	}
	refs[rootRef] = bom.Metadata.Component.Name

	for _, component := range bom.Components {
		if err := validateCycloneDXComponent(component); err != nil {
			return err
		}
		if existing, ok := refs[component.BOMRef]; ok {
			return fmt.Errorf(
				"component %q (%s): duplicate bom-ref also used by %q",
				component.Name,
				component.PURL,
				existing,
			)
		}
		refs[component.BOMRef] = component.Name
	}

	for _, dependency := range bom.Dependencies {
		if _, ok := refs[dependency.Ref]; !ok {
			return fmt.Errorf("component %q: dependency references unknown bom-ref %q", dependency.Ref, dependency.Ref)
		}
		for _, child := range dependency.DependsOn {
			if _, ok := refs[child]; !ok {
				return fmt.Errorf(
					"component %q: dependency references unknown child bom-ref %q",
					refs[dependency.Ref],
					child,
				)
			}
		}
	}

	return nil
}

func validateCycloneDXComponent(component CycloneDXComponent) error {
	if component.Name == "" {
		return fmt.Errorf("component %q: missing name", cycloneDXUnknownValue)
	}
	if component.Version == "" {
		return fmt.Errorf("component %q: missing version", component.Name)
	}
	if component.PURL == "" {
		return fmt.Errorf("component %q: missing purl", component.Name)
	}
	if component.BOMRef == "" {
		return fmt.Errorf("component %q: missing bom-ref", component.Name)
	}
	switch component.Type {
	case "application", "framework", "library", "container", "platform",
		"operating-system", "device", "device-driver", "firmware", "file",
		"machine-learning-model", "data":
	default:
		return fmt.Errorf("component %q: unsupported type %q", component.Name, component.Type)
	}
	return nil
}

func writeCycloneDXBOM(w io.Writer, bom *CycloneDXBOM) error {
	write := func(value string) error {
		_, err := io.WriteString(w, value)
		return err
	}

	header := fmt.Sprintf(
		`{"$schema":%q,"bomFormat":"CycloneDX","specVersion":%q,"version":%d,"metadata":`,
		bom.Schema,
		bom.SpecVersion,
		bom.Version,
	)
	if err := write(header); err != nil {
		return err
	}
	if err := writeCycloneDXValue(w, bom.Metadata, "metadata"); err != nil {
		return err
	}
	if err := write(`,"components":[`); err != nil {
		return err
	}
	for i, component := range bom.Components {
		if i > 0 {
			if err := write(","); err != nil {
				return err
			}
		}
		if err := writeCycloneDXValue(w, component, component.Name); err != nil {
			return fmt.Errorf("component %q (%s): %w", component.Name, component.PURL, err)
		}
	}
	if err := write(`],"dependencies":[`); err != nil {
		return err
	}
	for i, dependency := range bom.Dependencies {
		if i > 0 {
			if err := write(","); err != nil {
				return err
			}
		}
		if err := writeCycloneDXValue(w, dependency, dependency.Ref); err != nil {
			return fmt.Errorf("dependency %q: %w", dependency.Ref, err)
		}
	}
	return write("]}\n")
}

func writeCycloneDXValue(w io.Writer, value any, componentName string) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("component %q: marshal: %w", componentName, err)
	}
	if _, err = w.Write(encoded); err != nil {
		return fmt.Errorf("component %q: write: %w", componentName, err)
	}
	return nil
}

type cycloneDXBuildState struct {
	findings []Finding

	missingName    int
	missingVersion int
	missingSource  int

	grouped map[string][]cycloneDXOccurrence
}

type cycloneDXOccurrence struct {
	finding     Finding
	secretID    string
	name        string
	version     string
	source      string
	sourceKnown bool
}

type cycloneDXComponentKey struct {
	name    string
	version string
	purl    string
}

type cycloneDXComponentAccumulator struct {
	component       CycloneDXComponent
	occurrenceCount int
	secretIDs       map[string]struct{}
	first           cycloneDXOccurrence
}

type cycloneDXPathComponent struct {
	component CycloneDXComponent
}

func newCycloneDXBuildState(findings []Finding) *cycloneDXBuildState {
	return &cycloneDXBuildState{
		findings: findings,
		grouped:  make(map[string][]cycloneDXOccurrence),
	}
}

func (s *cycloneDXBuildState) build() (*CycloneDXBOM, error) {
	root := CycloneDXComponent{
		Type:    "application",
		BOMRef:  buildPURL("", cycloneDXRootName, cycloneDXUnknownValue),
		Name:    cycloneDXRootName,
		Version: cycloneDXUnknownValue,
		PURL:    buildPURL("", cycloneDXRootName, cycloneDXUnknownValue),
		Properties: []CycloneDXProperty{
			{Name: "gitleaks:dependency-model", Value: "source-path-hierarchy"},
		},
	}

	for _, finding := range s.findings {
		occurrence := s.occurrenceFromFinding(finding)
		if occurrence.name == cycloneDXUnknownValue {
			s.missingName++
		}
		if occurrence.version == cycloneDXUnknownValue {
			s.missingVersion++
		}
		if !occurrence.sourceKnown {
			s.missingSource++
		}
		identity := occurrence.secretID + "\x00" + occurrence.name
		s.grouped[identity] = append(s.grouped[identity], occurrence)
	}

	identityKeys := make([]string, 0, len(s.grouped))
	for identity := range s.grouped {
		identityKeys = append(identityKeys, identity)
	}
	sort.Strings(identityKeys)

	accumulators := make(map[cycloneDXComponentKey]*cycloneDXComponentAccumulator)
	for _, identity := range identityKeys {
		occurrences := s.grouped[identity]
		sort.Slice(occurrences, func(i, j int) bool {
			return cycloneDXOccurrenceLess(occurrences[i], occurrences[j])
		})
		canonical := occurrences[0]
		key := cycloneDXComponentKey{
			name:    canonical.name,
			version: canonical.version,
			purl:    buildPURL(canonical.sourceNamespace(), canonical.name, canonical.version),
		}
		accumulator, ok := accumulators[key]
		if !ok {
			accumulator = &cycloneDXComponentAccumulator{
				component: CycloneDXComponent{
					Type:    cycloneDXComponentTyp,
					BOMRef:  key.purl,
					Name:    key.name,
					Version: key.version,
					PURL:    key.purl,
				},
				secretIDs: make(map[string]struct{}),
				first:     canonical,
			}
			accumulators[key] = accumulator
		}
		for _, occurrence := range occurrences {
			accumulator.occurrenceCount++
			accumulator.secretIDs[occurrence.secretID] = struct{}{}
			if !cycloneDXOccurrenceLess(occurrence, accumulator.first) {
				continue
			}
			accumulator.first = occurrence
		}
	}

	keys := make([]cycloneDXComponentKey, 0, len(accumulators))
	for key := range accumulators {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].name != keys[j].name {
			return keys[i].name < keys[j].name
		}
		if keys[i].version != keys[j].version {
			return keys[i].version < keys[j].version
		}
		return keys[i].purl < keys[j].purl
	})

	dependencies := newCycloneDXDependencyGraph(root.BOMRef)
	pathComponents := make(map[string]cycloneDXPathComponent)
	components := make([]CycloneDXComponent, 0, len(keys))
	for _, key := range keys {
		accumulator := accumulators[key]
		component := accumulator.component
		component.Properties = s.componentProperties(accumulator)
		components = append(components, component)

		if !accumulator.first.sourceKnown {
			dependencies.addEdge(root.BOMRef, component.BOMRef)
			continue
		}
		sourceRef := ensureCycloneDXPathComponents(dependencies, pathComponents, root.BOMRef, accumulator.first.source)
		dependencies.addEdge(sourceRef, component.BOMRef)
	}

	for _, pathComponent := range pathComponents {
		components = append(components, pathComponent.component)
	}
	sort.Slice(components, func(i, j int) bool {
		if components[i].Name != components[j].Name {
			return components[i].Name < components[j].Name
		}
		if components[i].Version != components[j].Version {
			return components[i].Version < components[j].Version
		}
		return components[i].PURL < components[j].PURL
	})

	metadataProperties := []CycloneDXProperty{
		{Name: "gitleaks:format", Value: CycloneDXReportFormat},
		{Name: "gitleaks:spec-version", Value: CycloneDXSpecVersion},
		{Name: "gitleaks:finding-count", Value: strconv.Itoa(len(s.findings))},
		{Name: "gitleaks:component-count", Value: strconv.Itoa(len(components))},
		{Name: "gitleaks:dependency-count", Value: strconv.Itoa(len(dependencies.list()))},
		{Name: "gitleaks:missing-name", Value: strconv.Itoa(s.missingName)},
		{Name: "gitleaks:missing-version", Value: strconv.Itoa(s.missingVersion)},
		{Name: "gitleaks:missing-source", Value: strconv.Itoa(s.missingSource)},
		{Name: "gitleaks:missing-metadata-total", Value: strconv.Itoa(s.missingName + s.missingVersion + s.missingSource)},
	}

	return &CycloneDXBOM{
		Schema:      CycloneDXSchemaURL,
		BOMFormat:   "CycloneDX",
		SpecVersion: CycloneDXSpecVersion,
		Version:     1,
		Metadata: CycloneDXMetadata{
			Component:  root,
			Properties: metadataProperties,
		},
		Components:   components,
		Dependencies: dependencies.list(),
	}, nil
}

func (s *cycloneDXBuildState) occurrenceFromFinding(finding Finding) cycloneDXOccurrence {
	name := strings.TrimSpace(finding.RuleID)
	if name == "" {
		name = cycloneDXUnknownValue
	}
	version := strings.TrimSpace(finding.Commit)
	if version == "" {
		version = cycloneDXUnknownValue
	}
	source, sourceKnown := cleanCycloneDXSource(finding)

	return cycloneDXOccurrence{
		finding:     finding,
		secretID:    cycloneDXSecretID(finding),
		name:        name,
		version:     version,
		source:      source,
		sourceKnown: sourceKnown,
	}
}

func (s *cycloneDXBuildState) componentProperties(accumulator *cycloneDXComponentAccumulator) []CycloneDXProperty {
	first := accumulator.first
	properties := []CycloneDXProperty{
		{Name: "gitleaks:occurrence-count", Value: strconv.Itoa(accumulator.occurrenceCount)},
		{Name: "gitleaks:first-introduced-commit", Value: first.version},
	}
	if date := strings.TrimSpace(first.finding.Date); date != "" {
		properties = append(properties, CycloneDXProperty{
			Name:  "gitleaks:first-introduced-date",
			Value: date,
		})
	}
	if first.sourceKnown {
		properties = append(properties, CycloneDXProperty{Name: "gitleaks:source", Value: first.source})
	}

	missing := make([]string, 0, 3)
	if first.name == cycloneDXUnknownValue {
		missing = append(missing, "name")
	}
	if first.version == cycloneDXUnknownValue {
		missing = append(missing, "version")
	}
	if !first.sourceKnown {
		missing = append(missing, "source")
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		properties = append(properties, CycloneDXProperty{
			Name:  "gitleaks:missing-metadata",
			Value: strings.Join(missing, ","),
		})
	}

	secretIDs := make([]string, 0, len(accumulator.secretIDs))
	for secretID := range accumulator.secretIDs {
		secretIDs = append(secretIDs, secretID)
	}
	sort.Strings(secretIDs)
	for _, secretID := range secretIDs {
		properties = append(properties, CycloneDXProperty{
			Name:  "gitleaks:secret-sha256",
			Value: secretID,
		})
	}
	sort.Slice(properties, func(i, j int) bool {
		if properties[i].Name != properties[j].Name {
			return properties[i].Name < properties[j].Name
		}
		return properties[i].Value < properties[j].Value
	})
	return properties
}

func cleanCycloneDXSource(finding Finding) (string, bool) {
	source := strings.TrimSpace(finding.File)
	if source == "" {
		source = strings.TrimSpace(finding.SymlinkFile)
	}
	if source == "" {
		return cycloneDXUnknownValue, false
	}

	source = strings.ReplaceAll(source, "\\", "/")
	source = path.Clean(source)
	source = strings.TrimPrefix(source, "./")
	source = strings.TrimLeft(source, "/")
	if source == "" || source == "." {
		return cycloneDXUnknownValue, false
	}
	return source, true
}

func (o cycloneDXOccurrence) sourceNamespace() string {
	if !o.sourceKnown {
		return cycloneDXUnknownValue
	}
	return o.source
}

func cycloneDXSecretID(finding Finding) string {
	identity := strings.TrimSpace(finding.Secret)
	if identity == "" {
		identity = strings.Join([]string{
			finding.Fingerprint,
			finding.Match,
			finding.File,
			strconv.Itoa(finding.StartLine),
		}, "\x00")
	}
	sum := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(sum[:])
}

func cycloneDXOccurrenceLess(a, b cycloneDXOccurrence) bool {
	aTime, aOK := cycloneDXFindingTime(a.finding)
	bTime, bOK := cycloneDXFindingTime(b.finding)
	switch {
	case aOK && bOK && !aTime.Equal(bTime):
		return aTime.Before(bTime)
	case aOK != bOK:
		return aOK
	}

	if comparison := strings.Compare(a.version, b.version); comparison != 0 {
		return comparison < 0
	}
	if comparison := strings.Compare(a.source, b.source); comparison != 0 {
		return comparison < 0
	}
	if comparison := strings.Compare(a.finding.Fingerprint, b.finding.Fingerprint); comparison != 0 {
		return comparison < 0
	}
	if a.finding.StartLine != b.finding.StartLine {
		return a.finding.StartLine < b.finding.StartLine
	}
	return strings.Compare(a.secretID, b.secretID) < 0
}

func cycloneDXFindingTime(finding Finding) (time.Time, bool) {
	value := strings.TrimSpace(finding.Date)
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Year() <= 1 {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

func buildPURL(namespace, name, version string) string {
	segments := make([]string, 0, 4)
	segments = append(segments, "pkg:generic")
	namespace = strings.Trim(namespace, "/")
	if namespace != "" {
		for _, segment := range strings.Split(namespace, "/") {
			if segment != "" {
				segments = append(segments, escapePURLSegment(segment))
			}
		}
	}
	segments = append(segments, escapePURLSegment(name))
	return strings.Join(segments, "/") + "@" + escapePURLSegment(version)
}

func escapePURLSegment(value string) string {
	const hexDigits = "0123456789ABCDEF"
	var builder strings.Builder
	builder.Grow(len(value))
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~':
			builder.WriteByte(c)
		default:
			builder.WriteByte('%')
			builder.WriteByte(hexDigits[c>>4])
			builder.WriteByte(hexDigits[c&0x0f])
		}
	}
	return builder.String()
}

type cycloneDXDependencyGraph struct {
	nodes map[string]map[string]struct{}
}

func newCycloneDXDependencyGraph(rootRef string) *cycloneDXDependencyGraph {
	return &cycloneDXDependencyGraph{
		nodes: map[string]map[string]struct{}{
			rootRef: {},
		},
	}
}

func (g *cycloneDXDependencyGraph) addEdge(parent, child string) {
	if g.nodes[parent] == nil {
		g.nodes[parent] = make(map[string]struct{})
	}
	if g.nodes[child] == nil {
		g.nodes[child] = make(map[string]struct{})
	}
	g.nodes[parent][child] = struct{}{}
}

func (g *cycloneDXDependencyGraph) list() []CycloneDXDependency {
	refs := make([]string, 0, len(g.nodes))
	for ref := range g.nodes {
		refs = append(refs, ref)
	}
	sort.Strings(refs)

	dependencies := make([]CycloneDXDependency, 0, len(refs))
	for _, ref := range refs {
		children := make([]string, 0, len(g.nodes[ref]))
		for child := range g.nodes[ref] {
			children = append(children, child)
		}
		sort.Strings(children)
		dependencies = append(dependencies, CycloneDXDependency{
			Ref:       ref,
			DependsOn: children,
		})
	}
	return dependencies
}

func ensureCycloneDXPathComponents(
	graph *cycloneDXDependencyGraph,
	components map[string]cycloneDXPathComponent,
	rootRef string,
	source string,
) string {
	source = strings.Trim(source, "/")
	if source == "" {
		return ""
	}

	parts := strings.Split(source, "/")
	parent := rootRef
	for i := range parts {
		current := strings.Join(parts[:i+1], "/")
		component, exists := components[current]
		if !exists {
			kind := "directory"
			if i == len(parts)-1 {
				kind = "file"
			}
			purl := buildCycloneDXPathPURL(current)
			component = cycloneDXPathComponent{
				component: CycloneDXComponent{
					Type:    "file",
					BOMRef:  purl,
					Name:    path.Base(current),
					Version: cycloneDXUnknownValue,
					PURL:    purl,
					Properties: []CycloneDXProperty{
						{Name: "gitleaks:kind", Value: kind},
						{Name: "gitleaks:source", Value: current},
					},
				},
			}
			components[current] = component
			graph.addEdge(parent, component.component.BOMRef)
		}
		parent = component.component.BOMRef
	}
	return parent
}

func buildCycloneDXPathPURL(source string) string {
	dir := path.Dir(source)
	namespace := cycloneDXPathNS
	if dir != "." {
		namespace += "/" + dir
	}
	return buildPURL(namespace, path.Base(source), cycloneDXUnknownValue)
}
