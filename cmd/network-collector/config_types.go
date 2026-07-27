package main

import (
	"bufio"
	"io"
	"sync"
	"time"

	"github.com/gwoodwa1/network-collector/pkg/credentials"
	"github.com/gwoodwa1/network-collector/pkg/drivers/ssh"
	"github.com/gwoodwa1/network-collector/pkg/orchestrator"
	"github.com/gwoodwa1/network-collector/pkg/validation"
)

type RetryConfig struct {
	IntervalSeconds int  `mapstructure:"interval_seconds" yaml:"interval_seconds"`
	MaxAttempts     int  `mapstructure:"max_attempts" yaml:"max_attempts"`
	UntilPass       bool `mapstructure:"until_pass" yaml:"until_pass"`
}

type SSHProbeConfig struct {
	Port            int `mapstructure:"port" yaml:"port"`
	IntervalSeconds int `mapstructure:"interval_seconds" yaml:"interval_seconds"`
	MaxAttempts     int `mapstructure:"max_attempts" yaml:"max_attempts"`
	TimeoutSeconds  int `mapstructure:"timeout_seconds" yaml:"timeout_seconds"`
	PostWaitSeconds int `mapstructure:"post_wait_seconds" yaml:"post_wait_seconds"`
}

type ValidationActionConfig struct {
	Action  string            `mapstructure:"action" yaml:"action"`
	Command string            `mapstructure:"cmd" yaml:"cmd"`
	Message string            `mapstructure:"message" yaml:"message"`
	Steps   []StepConfig      `mapstructure:"steps" yaml:"steps"`
	Output  *StepOutputConfig `mapstructure:"output" yaml:"output"`
}

type StepConfig struct {
	Name           string                  `mapstructure:"name" yaml:"name"`
	Message        string                  `mapstructure:"message" yaml:"message"`
	Command        string                  `mapstructure:"cmd" yaml:"cmd"`
	Parser         string                  `mapstructure:"parser" yaml:"parser"`
	Enrich         *EnrichmentConfig       `mapstructure:"enrich" yaml:"enrich"`
	WaitSeconds    int                     `mapstructure:"wait_seconds" yaml:"wait_seconds"`
	ReturnToPrompt *bool                   `mapstructure:"return_to_prompt" yaml:"return_to_prompt"`
	SSHProbe       *SSHProbeConfig         `mapstructure:"ssh_probe" yaml:"ssh_probe"`
	RemovedLocal   interface{}             `mapstructure:"local" yaml:"local"`
	Validation     *ValidationConfig       `mapstructure:"validation" yaml:"validation"`
	Validations    []ValidationConfig      `mapstructure:"validations" yaml:"validations"`
	Retry          *RetryConfig            `mapstructure:"retry" yaml:"retry"`
	Register       string                  `mapstructure:"register" yaml:"register"`
	OnPass         *ValidationActionConfig `mapstructure:"on_pass" yaml:"on_pass"`
	OnFail         *ValidationActionConfig `mapstructure:"on_fail" yaml:"on_fail"`
	Output         *StepOutputConfig       `mapstructure:"output" yaml:"output"`
	Repeat         *RepeatConfig           `mapstructure:"repeat" yaml:"repeat"`
	When           *WhenConfig             `mapstructure:"when" yaml:"when"`
	Foreach        *ForeachConfig          `mapstructure:"foreach" yaml:"foreach"`
	Use            string                  `mapstructure:"use" yaml:"use"`
	With           map[string]interface{}  `mapstructure:"with" yaml:"with"`
	Block          *BlockConfig            `mapstructure:"block" yaml:"block"`
	Approval       *ApprovalConfig         `mapstructure:"approval" yaml:"approval"`
	Parallel       *ParallelConfig         `mapstructure:"parallel" yaml:"parallel"`
	Facts          *FactsConfig            `mapstructure:"facts" yaml:"facts"`
	Drift          *DriftConfig            `mapstructure:"drift" yaml:"drift"`
	GNMISubscribe  *GNMISubscribeConfig    `mapstructure:"gnmi_subscribe" yaml:"gnmi_subscribe"`
	NETCONF        *NETCONFStepConfig      `mapstructure:"netconf" yaml:"netconf"`
	Ensure         *EnsureConfig           `mapstructure:"ensure" yaml:"ensure"`
}

type EnsureConfig struct {
	Resource          string                 `mapstructure:"resource" yaml:"resource"`
	Name              string                 `mapstructure:"name" yaml:"name"`
	Prefix            string                 `mapstructure:"prefix" yaml:"prefix"`
	NextHop           string                 `mapstructure:"next_hop" yaml:"next_hop"`
	VRF               string                 `mapstructure:"vrf" yaml:"vrf"`
	State             string                 `mapstructure:"state" yaml:"state"`
	RequireState      string                 `mapstructure:"require_state" yaml:"require_state"`
	Description       *string                `mapstructure:"description" yaml:"description"`
	Transport         string                 `mapstructure:"transport" yaml:"transport"`
	Target            string                 `mapstructure:"target" yaml:"target"`
	RollbackOnFailure bool                   `mapstructure:"rollback_on_failure" yaml:"rollback_on_failure"`
	Attributes        EnsureAttributesConfig `mapstructure:"attributes" yaml:"attributes"`
	Cascade           bool                   `mapstructure:"cascade" yaml:"cascade"`
}

type EnsureAttributesConfig struct {
	RouteDistinguisher string   `mapstructure:"route_distinguisher" yaml:"route_distinguisher"`
	ImportRouteTargets []string `mapstructure:"import_route_targets" yaml:"import_route_targets"`
	ExportRouteTargets []string `mapstructure:"export_route_targets" yaml:"export_route_targets"`
}

type NETCONFStepConfig struct {
	Operation             string `mapstructure:"operation" yaml:"operation"`
	Target                string `mapstructure:"target" yaml:"target"`
	Source                string `mapstructure:"source" yaml:"source"`
	Payload               string `mapstructure:"payload" yaml:"payload"`
	PayloadFile           string `mapstructure:"payload_file" yaml:"payload_file"`
	Confirmed             bool   `mapstructure:"confirmed" yaml:"confirmed"`
	ConfirmTimeoutSeconds int    `mapstructure:"confirm_timeout_seconds" yaml:"confirm_timeout_seconds"`
	Persist               string `mapstructure:"persist" yaml:"persist"`
	PersistID             string `mapstructure:"persist_id" yaml:"persist_id"`
}

type EnrichmentConfig struct {
	Engine         string                 `mapstructure:"engine" yaml:"engine"`
	Expression     string                 `mapstructure:"expression" yaml:"expression"`
	ExpressionFile string                 `mapstructure:"expression_file" yaml:"expression_file"`
	Variables      map[string]interface{} `mapstructure:"variables" yaml:"variables"`
	TimeoutSeconds int                    `mapstructure:"timeout_seconds" yaml:"timeout_seconds"`
	MaxOutputBytes int                    `mapstructure:"max_output_bytes" yaml:"max_output_bytes"`
}

type GNMISubscribeConfig struct {
	Paths                 []string            `mapstructure:"paths" yaml:"paths"`
	Port                  int                 `mapstructure:"port" yaml:"port"`
	Mode                  string              `mapstructure:"mode" yaml:"mode"`
	StreamMode            string              `mapstructure:"stream_mode" yaml:"stream_mode"`
	SampleIntervalSeconds int                 `mapstructure:"sample_interval_seconds" yaml:"sample_interval_seconds"`
	DurationSeconds       int                 `mapstructure:"duration_seconds" yaml:"duration_seconds"`
	MaxUpdates            int                 `mapstructure:"max_updates" yaml:"max_updates"`
	SkipTLS               bool                `mapstructure:"skip_tls" yaml:"skip_tls"`
	TimeoutSeconds        int                 `mapstructure:"timeout_seconds" yaml:"timeout_seconds"`
	Triggers              []GNMITriggerConfig `mapstructure:"triggers" yaml:"triggers"`
}

type GNMITriggerConfig struct {
	Name            string       `mapstructure:"name" yaml:"name"`
	Event           string       `mapstructure:"event" yaml:"event"`
	Path            string       `mapstructure:"path" yaml:"path"`
	PathRegex       string       `mapstructure:"path_regex" yaml:"path_regex"`
	Value           string       `mapstructure:"value" yaml:"value"`
	ValueNot        string       `mapstructure:"value_not" yaml:"value_not"`
	ValueRegex      string       `mapstructure:"value_regex" yaml:"value_regex"`
	IncludeInitial  bool         `mapstructure:"include_initial" yaml:"include_initial"`
	Once            bool         `mapstructure:"once" yaml:"once"`
	Condition       string       `mapstructure:"condition" yaml:"condition"`
	Threshold       *float64     `mapstructure:"threshold" yaml:"threshold"`
	CounterRate     bool         `mapstructure:"counter_rate" yaml:"counter_rate"`
	BaselineSamples int          `mapstructure:"baseline_samples" yaml:"baseline_samples"`
	MaxDropPercent  float64      `mapstructure:"max_drop_percent" yaml:"max_drop_percent"`
	MaxDrop         *float64     `mapstructure:"max_drop" yaml:"max_drop"`
	Fail            bool         `mapstructure:"fail" yaml:"fail"`
	Steps           []StepConfig `mapstructure:"steps" yaml:"steps"`
}

type GNMIConnectionConfig struct {
	Port           int    `mapstructure:"port" yaml:"port"`
	Insecure       *bool  `mapstructure:"insecure" yaml:"insecure"`
	SkipVerify     *bool  `mapstructure:"skip_verify" yaml:"skip_verify"`
	CAFile         string `mapstructure:"ca_file" yaml:"ca_file"`
	CertFile       string `mapstructure:"cert_file" yaml:"cert_file"`
	KeyFile        string `mapstructure:"key_file" yaml:"key_file"`
	ServerName     string `mapstructure:"server_name" yaml:"server_name"`
	TimeoutSeconds int    `mapstructure:"timeout_seconds" yaml:"timeout_seconds"`
}

type DriftConfig struct {
	Baseline       string   `mapstructure:"baseline" yaml:"baseline"`
	Ignore         []string `mapstructure:"ignore" yaml:"ignore"`
	FailOnChange   bool     `mapstructure:"fail_on_change" yaml:"fail_on_change"`
	UpdateBaseline bool     `mapstructure:"update_baseline" yaml:"update_baseline"`
}

type FactsConfig struct {
	Format     string   `mapstructure:"format" yaml:"format"`
	Subsets    []string `mapstructure:"subsets" yaml:"subsets"`
	Transports []string `mapstructure:"transports" yaml:"transports"`
}

type ApprovalConfig struct {
	Message        string `mapstructure:"message" yaml:"message"`
	TimeoutSeconds int    `mapstructure:"timeout_seconds" yaml:"timeout_seconds"`
}

type ParallelConfig struct {
	MaxParallel int          `mapstructure:"max_parallel" yaml:"max_parallel"`
	Steps       []StepConfig `mapstructure:"steps" yaml:"steps"`
}

type WhenConfig struct {
	Variable     string      `mapstructure:"variable" yaml:"variable"`
	Condition    string      `mapstructure:"condition" yaml:"condition"`
	Expected     interface{} `mapstructure:"expected" yaml:"expected"`
	ExpectedType string      `mapstructure:"expected_type" yaml:"expected_type"`
}

type ForeachConfig struct {
	Items         []interface{} `mapstructure:"items" yaml:"items"`
	From          string        `mapstructure:"from" yaml:"from"`
	Item          string        `mapstructure:"item" yaml:"item"`
	Index         string        `mapstructure:"index" yaml:"index"`
	StopOnFailure *bool         `mapstructure:"stop_on_failure" yaml:"stop_on_failure"`
	Steps         []StepConfig  `mapstructure:"steps" yaml:"steps"`
}

type BlockConfig struct {
	Steps    []StepConfig `mapstructure:"steps" yaml:"steps"`
	Rescue   []StepConfig `mapstructure:"rescue" yaml:"rescue"`
	Rollback []StepConfig `mapstructure:"rollback" yaml:"rollback"`
	Always   []StepConfig `mapstructure:"always" yaml:"always"`
}

type WorkflowConfig struct {
	Parameters []string     `mapstructure:"parameters" yaml:"parameters"`
	Steps      []StepConfig `mapstructure:"steps" yaml:"steps"`
}

type RepeatConfig struct {
	Count           int          `mapstructure:"count" yaml:"count"`
	IntervalSeconds int          `mapstructure:"interval_seconds" yaml:"interval_seconds"`
	StopOnFailure   *bool        `mapstructure:"stop_on_failure" yaml:"stop_on_failure"`
	Steps           []StepConfig `mapstructure:"steps" yaml:"steps"`
}

type DeviceConfig struct {
	Hostname          string                 `mapstructure:"hostname" yaml:"hostname"`
	IP                string                 `mapstructure:"ip" yaml:"ip"`
	Host              string                 `mapstructure:"host" yaml:"host"`
	Hosts             []string               `mapstructure:"hosts" yaml:"hosts"`
	Group             string                 `mapstructure:"group" yaml:"group"`
	Groups            []string               `mapstructure:"groups" yaml:"groups"`
	Type              string                 `mapstructure:"type" yaml:"type"`
	Timeout           int                    `mapstructure:"timeout" yaml:"timeout"`
	OperationTimeout  int                    `mapstructure:"operation_timeout" yaml:"operation_timeout"`
	Steps             []StepConfig           `mapstructure:"steps" yaml:"steps"`
	Command           string                 `mapstructure:"cmd" yaml:"cmd"`
	Parser            string                 `mapstructure:"parser" yaml:"parser"`
	Validation        *ValidationConfig      `mapstructure:"validation" yaml:"validation"`
	Validations       []ValidationConfig     `mapstructure:"validations" yaml:"validations"`
	SSHSecurity       *SSHSecurityConfig     `mapstructure:"ssh_security" yaml:"ssh_security"`
	GNMI              *GNMIConnectionConfig  `mapstructure:"gnmi" yaml:"gnmi"`
	Labels            map[string]string      `mapstructure:"labels" yaml:"labels"`
	CredentialProfile string                 `mapstructure:"credential_profile" yaml:"credential_profile"`
	InventoryVars     map[string]interface{} `mapstructure:"-" yaml:"-"`
}

type SSHSecurityConfig struct {
	Profile        string `mapstructure:"profile" yaml:"profile"`
	HostKeyPolicy  string `mapstructure:"host_key_policy" yaml:"host_key_policy"`
	KnownHostsFile string `mapstructure:"known_hosts_file" yaml:"known_hosts_file"`
}

type ValidationConfig struct {
	Extractor    string      `mapstructure:"extractor" yaml:"extractor"`
	Pattern      string      `mapstructure:"pattern" yaml:"pattern"`
	JSONPath     string      `mapstructure:"json_path" yaml:"json_path"`
	Condition    string      `mapstructure:"condition" yaml:"condition"`
	Expected     interface{} `mapstructure:"expected" yaml:"expected"`
	ExpectedType string      `mapstructure:"expected_type" yaml:"expected_type"`
}

type Config struct {
	Imports           []string                  `mapstructure:"imports" yaml:"imports"`
	NamePlaybook      string                    `mapstructure:"name_playbook" yaml:"name_playbook"`
	InventoryFile     string                    `mapstructure:"inventory_file" yaml:"inventory_file"`
	ParsersFile       string                    `mapstructure:"parsers_file" yaml:"parsers_file"`
	Execution         ExecutionConfig           `mapstructure:"execution" yaml:"execution"`
	Output            OutputConfig              `mapstructure:"output" yaml:"output"`
	Report            ReportConfig              `mapstructure:"report" yaml:"report"`
	SSH               []DeviceConfig            `mapstructure:"ssh" yaml:"ssh"`
	NETCONF           []DeviceConfig            `mapstructure:"netconf" yaml:"netconf"`
	RemovedLocalSteps interface{}               `mapstructure:"local_steps" yaml:"local_steps"`
	Workflows         map[string]WorkflowConfig `mapstructure:"workflows" yaml:"workflows"`
	Schedule          ScheduleConfig            `mapstructure:"schedule" yaml:"schedule"`
	Vars              map[string]interface{}    `mapstructure:"vars" yaml:"vars"`
	SSHSecurity       SSHSecurityConfig         `mapstructure:"ssh_security" yaml:"ssh_security"`
	Facts             FactsDefaultsConfig       `mapstructure:"facts" yaml:"facts"`
	Credentials       CredentialProviderConfig  `mapstructure:"credentials" yaml:"credentials"`
	baseDir           string
	checkMode         bool
}

type ReportConfig struct {
	Enabled         bool   `mapstructure:"enabled" yaml:"enabled"`
	Format          string `mapstructure:"format" yaml:"format"`
	Template        string `mapstructure:"template" yaml:"template"`
	Output          string `mapstructure:"output" yaml:"output"`
	Title           string `mapstructure:"title" yaml:"title"`
	ChangeReference string `mapstructure:"change_reference" yaml:"change_reference"`
	LogoFolder      string `mapstructure:"logo_folder" yaml:"logo_folder"`
	HeaderLogo      string `mapstructure:"header_logo" yaml:"header_logo"`
	FooterLogo      string `mapstructure:"footer_logo" yaml:"footer_logo"`
}

type CredentialProviderConfig struct {
	Provider       string                        `mapstructure:"provider" yaml:"provider"`
	File           string                        `mapstructure:"file" yaml:"file"`
	RemovedCommand interface{}                   `mapstructure:"command" yaml:"command"`
	TimeoutSeconds int                           `mapstructure:"timeout_seconds" yaml:"timeout_seconds"`
	RSAToken       bool                          `mapstructure:"rsa_token" yaml:"rsa_token"`
	Hashicorp      credentials.HashicorpConfig   `mapstructure:"hashicorp" yaml:"hashicorp"`
	OnePassword    credentials.OnePasswordConfig `mapstructure:"onepassword" yaml:"onepassword"`
	CyberArk       credentials.CyberArkConfig    `mapstructure:"cyberark" yaml:"cyberark"`
}

type FactsDefaultsConfig struct {
	DefaultFormat     string   `mapstructure:"default_format" yaml:"default_format"`
	DefaultSubsets    []string `mapstructure:"default_subsets" yaml:"default_subsets"`
	DefaultTransports []string `mapstructure:"default_transports" yaml:"default_transports"`
}

type ScheduleConfig struct {
	Count           int `mapstructure:"count" yaml:"count"`
	IntervalSeconds int `mapstructure:"interval_seconds" yaml:"interval_seconds"`
}

type OutputConfig struct {
	Directory   string            `mapstructure:"directory" yaml:"directory"`
	SaveRaw     bool              `mapstructure:"save_raw" yaml:"save_raw"`
	SaveParsed  bool              `mapstructure:"save_parsed" yaml:"save_parsed"`
	SummaryFile string            `mapstructure:"summary_file" yaml:"summary_file"`
	EventsFile  string            `mapstructure:"events_file" yaml:"events_file"`
	EventSinks  []EventSinkConfig `mapstructure:"event_sinks" yaml:"event_sinks"`
}

type EventSinkConfig struct {
	Type           string            `mapstructure:"type" yaml:"type"`
	URL            string            `mapstructure:"url" yaml:"url"`
	Headers        map[string]string `mapstructure:"headers" yaml:"headers"`
	HMACSecretEnv  string            `mapstructure:"hmac_secret_env" yaml:"hmac_secret_env"`
	Network        string            `mapstructure:"network" yaml:"network"`
	Address        string            `mapstructure:"address" yaml:"address"`
	AppName        string            `mapstructure:"app_name" yaml:"app_name"`
	TimeoutSeconds int               `mapstructure:"timeout_seconds" yaml:"timeout_seconds"`
	QueueSize      int               `mapstructure:"queue_size" yaml:"queue_size"`
}

type StepOutputConfig struct {
	SaveRaw    *bool `mapstructure:"save_raw" yaml:"save_raw"`
	SaveParsed *bool `mapstructure:"save_parsed" yaml:"save_parsed"`
}

type ExecutionConfig struct {
	MaxParallel          int `mapstructure:"max_parallel" yaml:"max_parallel"`
	StartIntervalSeconds int `mapstructure:"start_interval_seconds" yaml:"start_interval_seconds"`
	CanaryCount          int `mapstructure:"canary_count" yaml:"canary_count"`
	FailureThreshold     int `mapstructure:"failure_threshold" yaml:"failure_threshold"`
}

type InventoryHostConfig struct {
	Name              string                 `yaml:"name"`
	Hostname          string                 `yaml:"hostname"`
	IP                string                 `yaml:"ip"`
	Address           string                 `yaml:"address"`
	Type              string                 `yaml:"type"`
	Timeout           int                    `yaml:"timeout"`
	OperationTimeout  int                    `yaml:"operation_timeout"`
	SSHSecurity       *SSHSecurityConfig     `yaml:"ssh_security"`
	GNMI              *GNMIConnectionConfig  `yaml:"gnmi"`
	Labels            map[string]string      `yaml:"labels"`
	CredentialProfile string                 `yaml:"credential_profile"`
	Vars              map[string]interface{} `yaml:"vars"`
}

type InventoryGroupConfig struct {
	Hosts []string `yaml:"hosts"`
}

type InventoryConfig struct {
	Hosts   []InventoryHostConfig           `yaml:"hosts"`
	Groups  map[string]InventoryGroupConfig `yaml:"groups"`
	baseDir string
}

type ParserFieldConfig struct {
	Pattern  string `yaml:"pattern"`
	Group    int    `yaml:"group"`
	Repeated bool   `yaml:"repeated"`
	Type     string `yaml:"type"`
}

type ParserModuleConfig struct {
	Type     string                       `yaml:"type"`
	Pattern  string                       `yaml:"pattern"`
	Template string                       `yaml:"template"`
	Root     string                       `yaml:"root"`
	Fields   map[string]ParserFieldConfig `yaml:"fields"`
	baseDir  string
}

type ParsersConfig struct {
	Parsers map[string]ParserModuleConfig `yaml:"parsers"`
}

type deviceValidation struct {
	Hostname  string                      `json:"hostname"`
	IP        string                      `json:"ip"`
	Result    validation.ValidationResult `json:"result"`
	Recovered bool                        `json:"recovered,omitempty"`
}

type deviceRunResult struct {
	index      int
	hostname   string
	ip         string
	aggregated []deviceValidation
	artifacts  []outputArtifact
	failed     bool
	duration   time.Duration
}

type outputArtifact struct {
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
	Step     string `json:"step"`
	Attempt  int    `json:"attempt"`
	Kind     string `json:"kind"`
	Path     string `json:"path"`
}

type runSummary struct {
	RunID       string             `json:"run_id"`
	Playbook    string             `json:"playbook,omitempty"`
	StartedAt   time.Time          `json:"started_at"`
	CompletedAt time.Time          `json:"completed_at"`
	Failed      bool               `json:"failed"`
	Validations []deviceValidation `json:"validations"`
	Artifacts   []outputArtifact   `json:"artifacts"`
	Devices     []deviceOutcome    `json:"devices,omitempty"`
}

type deviceOutcome = orchestrator.DeviceOutcome

type deviceVariableState struct {
	mu        sync.Mutex
	cond      *sync.Cond
	variables map[string]string
	order     []int
	next      int
}

var failureLogMu sync.Mutex

// version is replaced at release build time with the Git tag.
var version = "dev"

type stepExecutionContext struct {
	hostname       string
	ip             string
	deviceType     string
	username       string
	password       string
	opts           []ssh.Option
	jsonOut        bool
	sessionLog     io.Writer
	failureLog     string
	variables      map[string]string
	aggregated     *[]deviceValidation
	runFailed      *bool
	parsers        map[string]ParserModuleConfig
	configBaseDir  string
	output         OutputConfig
	runDir         string
	deviceIndex    int
	artifacts      *[]outputArtifact
	artifactSeq    int
	workflows      map[string]WorkflowConfig
	approveAll     bool
	approvalInput  *approvalInput
	approvalWriter io.Writer
	artifactPrefix string
	factsDefaults  FactsDefaultsConfig
	events         *eventDispatcher
	reauthenticate func() (string, string, error)
	netconf        netconfStepExecutor
	sshCommand     sshEnsureCommandExecutor
	sshEnsure      sshEnsureCommandExecutor
	gnmi           *GNMIConnectionConfig
	checkMode      bool
	reportEnabled  bool
}

type approvalAnswer struct {
	text string
	err  error
}
type approvalInput struct {
	mu      sync.Mutex
	scanner *bufio.Scanner
	expired bool
}
