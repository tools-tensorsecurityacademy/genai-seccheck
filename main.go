package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type VulnerabilityType string

const (
	SQLInjection     VulnerabilityType = "SQL_INJECTION"
	XSS              VulnerabilityType = "CROSS_SITE_SCRIPTING"
	CommandInjection VulnerabilityType = "COMMAND_INJECTION"
	PromptInjection  VulnerabilityType = "PROMPT_INJECTION"
	DataPoisoning    VulnerabilityType = "DATA_POISONING"
	ModelManipulation VulnerabilityType = "MODEL_MANIPULATION"
	AIGeneratedMalware VulnerabilityType = "AI_GENERATED_MALWARE"
	HardcodedSecret  VulnerabilityType = "HARDCODED_SECRET"
	InsecureDeserialization VulnerabilityType = "INSECURE_DESERIALIZATION"
)

type Severity string

const (
	Low      Severity = "LOW"
	Medium   Severity = "MEDIUM"
	High     Severity = "HIGH"
	Critical Severity = "CRITICAL"
)

type Vulnerability struct {
	Type        VulnerabilityType `json:"type"`
	Severity    Severity          `json:"severity"`
	File        string            `json:"file"`
	Line        int               `json:"line"`
	Message     string            `json:"message"`
	Description string            `json:"description"`
	CodeSnippet string            `json:"code_snippet"`
	IsGenAI     bool              `json:"is_genai"`
	Confidence  float64           `json:"confidence"`
}

type ScanResult struct {
	Path           string           `json:"path"`
	Total          int              `json:"total"`
	Traditional    int              `json:"traditional"`
	GenAI          int              `json:"genai"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// SIMPLER PATTERNS - More likely to match
var traditionalPatterns = map[VulnerabilityType]*regexp.Regexp{
	SQLInjection:     regexp.MustCompile(`(?i)SELECT.*['"]\s*[+].*['"]`),
	XSS:              regexp.MustCompile(`(?i)\.innerHTML\s*=`),
	CommandInjection: regexp.MustCompile(`(?i)os\.system\(`),
	HardcodedSecret:  regexp.MustCompile(`(?i)(api.?key|secret|password|token)\s*=\s*['"][^'"]+['"]`),
}

var genaiPatterns = map[VulnerabilityType]*regexp.Regexp{
	PromptInjection:    regexp.MustCompile(`(?i)prompt.*=.*f["']`),
	DataPoisoning:      regexp.MustCompile(`(?i)train.*\(`),
	ModelManipulation:  regexp.MustCompile(`(?i)pickle\.dump`),
	AIGeneratedMalware: regexp.MustCompile(`(?i)generate.*code`),
	InsecureDeserialization: regexp.MustCompile(`(?i)pickle\.load`),
}

type Scanner struct{ Path string }

func NewScanner(path string) *Scanner { return &Scanner{Path: path} }

func (s *Scanner) Scan() *ScanResult {
	result := &ScanResult{Path: s.Path}
	
	filepath.Walk(s.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() { 
			return nil 
		}
		
		if !isSourceFile(path) { 
			return nil 
		}
		
		if isBinaryFile(path) {
			return nil
		}
		
		vulns := s.scanFile(path)
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
		
		return nil
	})
	
	// Calculate totals
	result.Total = len(result.Vulnerabilities)
	for _, v := range result.Vulnerabilities {
		if v.IsGenAI { 
			result.GenAI++ 
		} else { 
			result.Traditional++ 
		}
	}
	
	return result
}

func (s *Scanner) scanFile(filePath string) []Vulnerability {
	var vulns []Vulnerability
	
	file, err := os.Open(filePath)
	if err != nil { 
		return vulns 
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	lineNum := 0
	
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		
		// Skip empty lines and comments
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		
		// Check traditional vulnerabilities
		for vulnType, pattern := range traditionalPatterns {
			if pattern.MatchString(line) {
				vulns = append(vulns, createVuln(vulnType, filePath, lineNum, line, false))
			}
		}
		
		// Check GenAI vulnerabilities (OUR NOVEL CONTRIBUTION)
		for vulnType, pattern := range genaiPatterns {
			if pattern.MatchString(line) {
				vulns = append(vulns, createVuln(vulnType, filePath, lineNum, line, true))
			}
		}
		
		// SIMPLE HEURISTIC CHECKS - More reliable
		if strings.Contains(line, "f\"SELECT") {
			vulns = append(vulns, createVuln(SQLInjection, filePath, lineNum, line, false))
		}
		
		if strings.Contains(line, "f\"<div>") || strings.Contains(line, "innerHTML = ") {
			vulns = append(vulns, createVuln(XSS, filePath, lineNum, line, false))
		}
		
		if strings.Contains(line, "os.system(") && strings.Contains(line, "{") {
			vulns = append(vulns, createVuln(CommandInjection, filePath, lineNum, line, false))
		}
		
		if strings.Contains(line, "subprocess.run(") && strings.Contains(line, "{") {
			vulns = append(vulns, createVuln(CommandInjection, filePath, lineNum, line, false))
		}
		
		if (strings.Contains(line, "API_KEY") || strings.Contains(line, "api_key")) && strings.Contains(line, "=") && strings.Contains(line, "\"") {
			vulns = append(vulns, createVuln(HardcodedSecret, filePath, lineNum, line, false))
		}
		
		if strings.Contains(line, "f\"\"\"") && strings.Contains(line, "{") {
			vulns = append(vulns, createVuln(PromptInjection, filePath, lineNum, line, true))
		}
		
		if strings.Contains(line, "f\"Translate") || strings.Contains(line, "f\"Hello") {
			vulns = append(vulns, createVuln(PromptInjection, filePath, lineNum, line, true))
		}
		
		if strings.Contains(line, "model.train(") || strings.Contains(line, "model.fit(") {
			vulns = append(vulns, createVuln(DataPoisoning, filePath, lineNum, line, true))
		}
		
		if strings.Contains(line, "pickle.dump") {
			vulns = append(vulns, createVuln(ModelManipulation, filePath, lineNum, line, true))
		}
		
		if strings.Contains(line, "pickle.load") {
			vulns = append(vulns, createVuln(InsecureDeserialization, filePath, lineNum, line, true))
		}
		
		if strings.Contains(line, "generate.*code") || strings.Contains(line, "create.*script") {
			vulns = append(vulns, createVuln(AIGeneratedMalware, filePath, lineNum, line, true))
		}
	}
	
	return vulns
}

func createVuln(t VulnerabilityType, f string, l int, c string, ai bool) Vulnerability {
	v := Vulnerability{
		Type:        t,
		File:        f,
		Line:        l,
		CodeSnippet: strings.TrimSpace(c),
		IsGenAI:     ai,
		Confidence:  0.85,
	}
	
	switch t {
	case SQLInjection: 
		v.Severity = High
		v.Message = "SQL Injection vulnerability"
		v.Description = "User input concatenated into SQL query"
	case XSS: 
		v.Severity = Medium
		v.Message = "Cross-Site Scripting vulnerability"
		v.Description = "Unsanitized user input in HTML output"
	case CommandInjection: 
		v.Severity = High
		v.Message = "Command Injection vulnerability"
		v.Description = "User input in system commands"
	case HardcodedSecret:
		v.Severity = Critical
		v.Message = "Hardcoded secret found"
		v.Description = "API key, password, or token exposed in source code"
	case PromptInjection: 
		v.Severity = Critical
		v.Message = "Prompt Injection vulnerability"
		v.Description = "User input concatenated with LLM prompts"
		v.IsGenAI = true
	case DataPoisoning: 
		v.Severity = Critical
		v.Message = "Data Poisoning risk"
		v.Description = "Untrusted data used for model training"
		v.IsGenAI = true
	case ModelManipulation: 
		v.Severity = High
		v.Message = "Model Manipulation vulnerability"
		v.Description = "Model parameters exposed to user input"
		v.IsGenAI = true
	case AIGeneratedMalware: 
		v.Severity = Critical
		v.Message = "AI-Generated Malware risk"
		v.Description = "User input controls generated code"
		v.IsGenAI = true
	case InsecureDeserialization:
		v.Severity = Critical
		v.Message = "Insecure Deserialization"
		v.Description = "Loading untrusted pickle data"
		v.IsGenAI = true
	}
	
	return v
}

func isSourceFile(p string) bool {
	e := strings.ToLower(filepath.Ext(p))
	sourceExts := []string{".py", ".js", ".ts", ".java", ".go", ".cpp", ".c", ".rs", ".php", ".rb", ".txt"}
	for _, ext := range sourceExts {
		if e == ext { 
			return true 
		}
	}
	return false
}

func isBinaryFile(p string) bool {
	file, err := os.Open(p)
	if err != nil {
		return false
	}
	defer file.Close()
	
	buffer := make([]byte, 512)
	n, _ := file.Read(buffer)
	
	for i := 0; i < n; i++ {
		if buffer[i] == 0 {
			return true
		}
	}
	
	return false
}

func main() {
	var path string
	var jsonOut bool
	var verbose bool
	
	flag.StringVar(&path, "path", ".", "Path to scan")
	flag.BoolVar(&jsonOut, "json", false, "JSON output")
	flag.BoolVar(&verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&verbose, "v", false, "Verbose output (shorthand)")
	flag.Parse()
	
	if _, err := os.Stat(path); os.IsNotExist(err) {
		fmt.Printf("❌ Error: %s not found\n", path)
		os.Exit(1)
	}
	
	fmt.Println("🔍 GenAI-SecCheck - AI Security Scanner")
	fmt.Println("========================================")
	fmt.Printf("📁 Scanning: %s\n\n", path)
	
	start := time.Now()
	result := NewScanner(path).Scan()
	elapsed := time.Since(start)
	
	if jsonOut {
		j, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(j))
	} else {
		if len(result.Vulnerabilities) > 0 {
			fmt.Printf("📊 Found %d vulnerabilities (%d traditional, %d GenAI):\n", 
				result.Total, result.Traditional, result.GenAI)
			fmt.Println(strings.Repeat("─", 70))
			
			for i, v := range result.Vulnerabilities {
				ai := ""
				if v.IsGenAI {
					ai = "🤖 "
				}
				
				color := "⚪"
				switch v.Severity {
				case Critical: color = "🔴"
				case High: color = "🟠"
				case Medium: color = "🟡"
				case Low: color = "🟢"
				}
				
				fmt.Printf("\n%d. %s[%s] %s%s\n", i+1, color, v.Severity, ai, v.Type)
				fmt.Printf("   📍 %s:%d\n", v.File, v.Line)
				fmt.Printf("   📝 %s\n", v.Message)
				
				// Show code snippet
				if len(v.CodeSnippet) > 80 {
					fmt.Printf("   💻 %.80s...\n", v.CodeSnippet)
				} else {
					fmt.Printf("   💻 %s\n", v.CodeSnippet)
				}
			}
			
			fmt.Printf("\n⏱️  Scan completed in %v\n", elapsed)
			
			// Summary by type
			fmt.Println("\n" + strings.Repeat("═", 50))
			fmt.Println("📈 SUMMARY BY TYPE")
			fmt.Println(strings.Repeat("─", 50))
			
			typeCounts := make(map[VulnerabilityType]int)
			for _, v := range result.Vulnerabilities {
				typeCounts[v.Type]++
			}
			
			for vulnType, count := range typeCounts {
				aiMark := ""
				if isGenAIVulnerability(vulnType) {
					aiMark = "🤖 "
				}
				fmt.Printf("  %s%s: %d\n", aiMark, vulnType, count)
			}
			
		} else {
			fmt.Println("✅ No vulnerabilities found!")
			fmt.Printf("⏱️  Scan completed in %v\n", elapsed)
		}
	}
	
	// Exit code based on findings
	hasCritical := false
	for _, v := range result.Vulnerabilities {
		if v.Severity == Critical {
			hasCritical = true
			break
		}
	}
	
	if hasCritical {
		fmt.Println("\n❌ CRITICAL vulnerabilities found!")
		os.Exit(1)
	} else if result.Total > 0 {
		fmt.Println("\n⚠️  Vulnerabilities found (check above)")
		os.Exit(0)
	} else {
		os.Exit(0)
	}
}

func isGenAIVulnerability(vulnType VulnerabilityType) bool {
	genaiTypes := []VulnerabilityType{
		PromptInjection,
		DataPoisoning,
		ModelManipulation,
		AIGeneratedMalware,
		InsecureDeserialization,
	}
	for _, t := range genaiTypes {
		if t == vulnType {
			return true
		}
	}
	return false
}
