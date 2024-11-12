# 🛠️ **scrypte: Lightweight Web Vulnerability Scanner**

![Banners](https://github.com/ramenaru/scrypte/blob/main/misc/images/banner.png) 

**scrypte** is a lightweight tool for detecting web vulnerabilities. Focuses on providing essential scanning capabilities in a clean, easy-to-use CLI tool. Perfect for security researchers, developers, and anyone looking to secure their web applications.

---
## 🌟 **Current Version**

>  **v1.0.0** – [See Release Notes](https://github.com/ramenaru/scrypte/releases)

## 📥 **Installation**

### Prerequisites

-  **Python**: 3.6 or higher

-  **Pip**: Ensure `pip` is installed for dependency management

-  **Terminal**: Any command-line interface on your operating system

### Installation Steps

1.  **Clone the Repository**:

```bash
git clone https://github.com/ramenaru/scrypte.git
cd scrypte
```

2.  **Install Dependencies**:

```bash
pip install -r requirements.txt
```

## 🧑‍💻 **Usage**

Launch scrypte from the command line with:

```bash
python  -m  src.main
```
Follow the interactive prompts to select the type of scan you wish to run:

### Available Scan Options

1.  **Header Scan** – Checks for secure headers (e.g., Content-Security-Policy, HSTS).

2.  **XSS Scan** – Tests for cross-site scripting vulnerabilities.

3.  **SQL Injection Scan** – Detects potential SQL injection points.

4.  **TLS/SSL Security Scan** – Verifies SSL/TLS setup.

5.  **Directory & File Enumeration** – Scans for exposed files and directories.

6.  **Run All Scans** – Executes all available scans in a single command.
---
## 📊 **Output & Report**

Each scan generates a JSON report in the `reports/` directory, detailing all vulnerabilities, their severity, and recommended actions. Reports can be used for later analysis or integration into reporting workflows.

Example Report:

```json
{

"url": "https://example.com",

"vulnerabilities": [

{

"issue": "Outdated Apache server",

"severity": "high",

"description": "Server version Apache/2.4.1 detected.",

"recommendation": "Update Apache to the latest version."

}

]

}
```

## 🏷️ **Release and Launcher Setup**

### Versioning & Release Notes

- Check for the latest version of scrypte on the [Releases Page](https://github.com/ramenaru/scrypte/releases).

- For version updates, scrypte checks for updates on GitHub to ensure you're always using the latest release.

  

### Creating a Standalone Executable

  

To package scrypte as a standalone executable for distribution:

  

1.  **Install PyInstaller**:

```bash
pip install pyinstaller
```

  

2.  **Build the Executable**:

```bash
pyinstaller --onefile src/main.py --name scrypte
```

  

3.  **Run the Executable**:

Navigate to the `dist` directory and execute:

```bash
./dist/scrypte
```
---

## ⚙️ **Configuration**

The following files contain customizable configurations:

-  **`src/utils.py`**: Define common paths, subdomains, and extensions for scanning.

-  **`requirements.txt`**: Manage dependencies for additional functionality.

---

## 🌐 **Extending scrypte**

scrypte is designed with extensibility in mind, making it easy to add new scan types.

1.  **Create a New Scan Module**: Add a new Python file in the `scanner/` directory.

2.  **Define Your Scan**: Implement your scan class by inheriting from `BaseScan`.

3.  **Register the Scan**: Register your new scan in `scanner/__init__.py` for it to appear in the options.

Example:

```python
# scanner/my_custom_scan.py

from .base_scan import BaseScan

class  MyCustomScan(BaseScan):

def  run(self):

# Custom scan logic here

pass
```

---

## 📚 **Essentials Project Structure**

| Directory / File          | Description                                                                                          |
|---------------------------|------------------------------------------------------------------------------------------------------|
| **`logs/`**               | Contains log files for error tracking and debugging.                                                 |
| **`reports/`**            | Stores generated JSON reports from scans.                                                            |
| **`src/`**                | Main directory containing all source code files and modules.                                         |
| ├── **`report/`**         | Contains report generation modules.                                                                  |
| │   ├── `report_generator.py` | Generates JSON reports based on scan results.                                                  |
| ├── **`scanner/`**        | Contains modules for each type of scan (XSS, SQL Injection, TLS, Directory, etc.).                  |
| │   ├── `base_scan.py`    | Defines a base class for all scans to inherit common functionality.                                  |
| │   ├── `directory_scan.py` | Scans for exposed directories and files.                                                          |
| │   ├── `header_scan.py`  | Checks HTTP headers for security policies and configurations.                                        |
| │   ├── `sql_injection_scan.py` | Tests for SQL Injection vulnerabilities.                                                    |
| │   └── `xss_scan.py`     | Scans for Cross-Site Scripting (XSS) vulnerabilities.                                               |
| ├── **`cli.py`**          | Handles user interaction and command-line interface.                                                |
| ├── **`config.py`**       | Configuration settings for user-agent strings and request headers.                                   |
| ├── **`main.py`**         | Main entry point for the application, coordinating scan execution.                                  |
| └── **`utils.py`**        | Contains helper functions and utilities used across different modules.                               |

---

## 🤝 **Contributing**

We welcome contributions! To contribute:

1. **Fork the Repository**
2. **Clone Your Fork**:
   ```bash
   git clone https://github.com/ramenaru/scrypte.git
   ```
3. **Create a New Branch**:
   ```bash
   git checkout -b feature/your-feature
   ```
4. **Submit a Pull Request**: Make sure to describe your changes in detail.
---

## 📜 🔒 **License & Security**

Distributed under the GPL-3.0 See [LICENSE](LICENSE) for more information.

Learn more about my security report. See [SECURITY](SECURITY.md) for more information.

---
## 📢 **Contact**

For questions or feedback, please reach out:

- **GitHub**: [@ramenaru](https://github.com/ramenaru)
- **Email**: inbox@ramenaru.me

---

Thank you for using **Scrypte**! With Scrypte, you’re one step closer to securing the web, one scan at a time. 🔒✨
