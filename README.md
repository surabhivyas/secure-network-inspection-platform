# Secure Network Inspection Platform

Security-focused traffic inspection platform built in C++ and Python for IOC detection, DLP inspection, threat scoring, and REST API integration.

## Quick Summary

A security-focused network inspection platform built in C++ and Python that performs:

- IOC Detection (Indicators of Compromise)
- Data Loss Prevention (DLP) Inspection
- Risk-Based Threat Scoring
- Malicious IP and Domain Detection
- Rule-Based Traffic Analysis
- REST API Integration
- JSON Report Generation

## Architecture

![Architecture Diagram](Architecture.jpeg)

## Key Capabilities

- IOC (Indicator of Compromise) Detection
- Malicious Domain Identification
- Malicious IP Detection
- DLP Inspection
- Risk Scoring
- REST API Integration
- JSON Report Generation

## Technology Stack

- C++
- Python
- Linux
- REST APIs

## Build and Run

### Prerequisites

- Linux
- GCC/G++ with C++17 support
- Python 3
- Flask

### Build the Network Inspection Engine

```bash
cd src
g++ -std=c++17 -pthread main.cpp rule_engine.cpp -o inspection_engine
```

### Run the Inspection Engine

```bash
./inspection_engine
```

### Install API Dependencies

```bash
pip install flask
```

### Start the REST API

```bash
cd api
python3 app.py
```

The API starts on:

```text
http://localhost:5000
```

### API Endpoints

#### Health Check

```http
GET /health
```

Example Response:

```json
{
"status": "ok"
}
```

#### Run Inspection

```http
POST /run-inspection
```

Triggers the C++ inspection engine and returns generated security findings from `inspection_results.json`.

### Project Workflow

```text
Traffic Sources
↓
Network Inspection Engine (C++)
↓
IOC Detection / Rule Analysis / DLP Inspection
↓
Risk Scoring Module (Python)
↓
REST API Layer (Flask)
↓
JSON Security Findings
```


## Project Structure

- `src/`  - Core inspection engine
- `api/`  - REST API layer
- `ai/`   - Risk scoring module
- `data/` - IOC and traffic datasets

## Sample Detection Categories

- Malicious IP detection
- Malicious domain detection
- Data exfiltration indicators
- Suspicious traffic patterns

## Future Enhancements

- Real-time packet capture
- Threat intelligence integration
- SIEM integration
- Dashboard visualization
- Machine learning anomaly detection

## Disclaimer

This project was created for learning and portfolio purposes and does not contain proprietary code from any employer.
