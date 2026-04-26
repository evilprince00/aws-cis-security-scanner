# ☁️ AWS CIS Security Scanner (Python)

A modular, extensible Python-based security scanner for identifying cloud misconfigurations in AWS environments using the CIS AWS Foundations Benchmark.

---

## 🚀 Overview

This project is a **from-scratch implementation of a cloud security scanner**, designed to:

* Detect real-world misconfigurations across AWS services
* Follow CIS benchmark guidelines (IAM, S3, EC2)
* Provide structured, audit-ready output
* Scale into multi-region and advanced security analysis

Unlike basic scripts, this tool is built with a **modular scanning engine + reusable data layers**, making it closer to real-world security tooling.

---

## 🧠 Key Features

### 🔐 IAM Security Checks (CIS 1.x)

* Root account usage & MFA enforcement
* Root access key detection
* IAM user MFA validation
* Password policy validation

---

### 🪣 S3 Security Checks (CIS 2.x)

* Public bucket exposure detection
* Public write access detection
* Bucket policy restriction validation
* Server access logging enforcement

---

### 🌐 EC2 Security Checks (CIS 4.x + Enhancements)

* SSH (22) exposure to the internet
* RDP (3389) exposure detection
* Unrestricted port access detection
* IMDSv2 enforcement (metadata security)
* EBS encryption validation
* Public IP exposure analysis

---

## ⚙️ Architecture

```
aws_cis_scanner/
│
├── core/
│   ├── aws_session.py      # Role assumption + session handling
│   ├── ec2_cache.py        # Multi-region EC2 data layer
│   └── report.py           # Output formatting
│
├── modules/
│   ├── iam.py              # CIS 1.x checks
│   ├── s3.py               # CIS 2.x checks
│   └── ec2.py              # CIS 4.x + enhancements
│
├── engine.py               # Scan execution engine
├── main.py                 # Entry point
└── results/
    └── scan.json           # Output report
```

---

## 🧱 Design Highlights

* ✅ Modular control-based architecture
* ✅ Multi-region EC2 scanning
* ✅ Shared data caching (performance optimized)
* ✅ Deduplicated findings
* ✅ Structured output for reporting & automation

---

## 🧪 How It Works

1. Assume IAM role using AWS STS
2. Initialize scan engine
3. Load service-specific data (IAM, S3, EC2)
4. Execute CIS controls
5. Generate structured results

---

## 🔧 Setup & Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/aws-cis-scanner.git
cd aws-cis-scanner
```

### 2. Install dependencies

```bash
pip install boto3
```

### 3. Configure AWS credentials

```bash
aws configure
```

Ensure your IAM user can assume the scanner role.

---

## ▶️ Usage

Update your role ARN in `main.py`:

```python
ROLE_ARN = "arn:aws:iam::YOUR_ACCOUNT_ID:role/CisScannerRole"
```

Run the scanner:

```bash
python main.py
```

---

## 📊 Sample Output

<img width="1366" height="663" alt="image" src="https://github.com/user-attachments/assets/89727e4c-0cdc-48df-9017-9f9495e23c02" />

```json
{
  "control": "CIS 4.1",
  "status": "FAIL",
  "severity": "CRITICAL",
  "non_compliant_sgs": [
    {
      "GroupId": "sg-12345",
      "Region": "ap-south-1"
    }
  ]
}
```

---

## 🎯 Future Enhancements

* 🔥 Attack Path Correlation Engine (multi-signal risk detection)
* 📦 JSON/CSV export improvements
* ☁️ Multi-account scanning support
* ⚡ Parallel execution for faster scans
* 📊 Dashboard / visualization layer

---

## ⚠️ Disclaimer

This tool is intended for **security auditing and educational purposes only**.
Use responsibly on infrastructure you own or have permission to assess.

---

## 🤝 Contributing

Contributions are welcome! Feel free to:

* Add new CIS controls
* Improve detection logic
* Optimize performance

---

## 📌 Author

Built with a focus on **real-world cloud security engineering**, not just theory.

---

## ⭐ If you found this useful

Give it a star ⭐ — it helps others discover the project!
