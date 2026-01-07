# GenAI-SecCheck 🤖

**Hybrid Security Scanner for AI-Integrated Software Development**

## 🎯 What is This?

A security scanner that detects **BOTH** traditional vulnerabilities (SQLi, XSS, etc.) AND **GenAI-specific vulnerabilities** (Prompt Injection, Data Poisoning, etc.) that existing tools miss.

## 🚀 Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/genai-seccheck
cd genai-seccheck

# 2. Build the scanner
go build -o genai-seccheck

# 3. Scan a directory
./genai-seccheck -path ./examples

# 4. Output JSON
./genai-seccheck -path . -json
