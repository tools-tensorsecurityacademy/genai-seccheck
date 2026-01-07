# Test file for GenAI-SecCheck

# SQL Injection (should be detected)
query = f"SELECT * FROM users WHERE name = '{user_input}'"

# XSS (should be detected)
html = f"<div>{user_comment}</div>"

# Command Injection (should be detected)
import os
os.system(f"echo {user_command}")

# Hardcoded Secret (should be detected)
API_KEY = "sk-live-1234567890abcdef"

# Prompt Injection - GenAI specific (should be detected)
prompt = f"Translate this: {user_text}"

# Data Poisoning - GenAI specific (should be detected)
model.train(user_data)

# Insecure Deserialization - GenAI specific (should be detected)
import pickle
data = pickle.load(untrusted_file)

# AI Generated Malware - GenAI specific (should be detected)
code = f"""
print("Generated: {user_request}")
"""
