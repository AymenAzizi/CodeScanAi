![GitHub](https://img.shields.io/github/license/AymenAzizi/SecFixAI)

# SecFixAI

SecFixAI is a powerful security scanning tool that utilizes various AI models to analyze your codebase for security vulnerabilities and bad development practices. It can detect potential security issues, generate fixes, validate them, and create pull requests with the fixes. SecFixAI leverages advanced LLM models to provide intelligent suggestions on improving your codebase's security against external attacks, unauthorized access, and other security threats.

The currently supported AI models include:

- OpenAI
- Google Gemini
- Hugging Face (free option)
- Custom self-hosted AI servers

SecFixAI is designed for seamless integration into CI/CD pipelines like GitHub Actions, and can also be used via a simple CLI command locally. The goal is to help developers automatically detect and fix potential security issues throughout the development process.

## Features

- **Flexible Scanning Options:**
  - **Full Directory Scans:** Perform comprehensive security analysis by scanning all files within a directory.
  - **Changes Only Scan:** Scan only files that have changed since the last scan.
  - **PR-Specific Scans:** Focus on files modified in a specific pull request to optimize scanning, reduce overhead, and ensure new code changes meet security standards.

- **Support for Multiple AI Models:**

  SecFixAI supports a range of AI models including OpenAI, Google Gemini, Hugging Face, and self-hosted models. Based on user demands, support for other popular AI models like Claude and Grok can be added.

- **Advanced SAST/SCA/DAST Integration:**

  - **Multi-language Support**: Detects vulnerabilities in JavaScript, Python, Java, PHP, Ruby, and Go.
  - **Context-aware Scanning**: Reduces false positives through intelligent context analysis.
  - **Software Composition Analysis (SCA)**: Identifies vulnerable dependencies in package managers.
  - **Dynamic Application Security Testing (DAST)**: Scans web applications for runtime vulnerabilities.
  - **Real-time Vulnerability Database**: Connects to the National Vulnerability Database (NVD) for up-to-date information.
  - Provides detailed vulnerability reports with severity, location, and description.

- **Enhanced AI-Powered Fix Generation:**

  - Automatically generates fixes for detected vulnerabilities across multiple languages.
  - Uses AI to create context-aware code fixes that maintain functionality.
  - Language-specific fix generation for more accurate and effective solutions.
  - Improved error handling with automatic retries for more reliable fix generation.

- **Validation System:**

  - Validates generated fixes by re-scanning the code.
  - Ensures that fixes actually resolve the vulnerabilities.

- **Auto-PR Creation:**

  - Automatically creates pull requests with fixes for vulnerabilities.
  - Includes detailed descriptions of the vulnerabilities and fixes.

- **Advanced Security Metrics Dashboard:**

  - Interactive visualization with charts and graphs.
  - Tracks vulnerability metrics over time.
  - Shows fix success rates and project security health.
  - Breakdown by language, severity, and vulnerability type.
  - Historical trend analysis for security posture evaluation.

- **Comprehensive CI/CD Integration:**

  - Ready-to-use configurations for GitHub Actions, Jenkins, and GitLab CI.
  - Seamlessly integrate the CLI tool into CI/CD pipelines for automated security vulnerability scanning on every pull request.
  - Supports targeted scans on specific branches or changes within a repository.
  - Automated PR comments with vulnerability summaries.
  - HTML and JSON report generation for integration with security dashboards.

## Getting Started

### Prerequisites

- Python 3.10 or higher
- API keys for the supported AI models:
  - OpenAI API key, OR
  - Gemini API key, OR
  - Hugging Face token (optional for some free models), OR
  - Access to a custom AI server (host, port, and optional token)
- Set an environment variable for your API key(s).

```bash
export OPENAI_API_KEY = 'your_openai_api_key'

export GEMINI_API_KEY = 'your_gemini_api_key'

export HF_TOKEN = 'your_huggingface_token'
```

### Installation

#### Option 1: Install via pip

You can install the tool directly from the repository using pip:

```bash
pip install secfixai
```

This will allow you to use the `secfixai` command directly in your terminal.

#### Option 2: Clone the Repository

If you prefer to clone the repository and install the dependencies manually:

```bash
git clone https://github.com/AymenAzizi/SecFixAI.git
cd SecFixAI
pip install -r requirements.txt
```

### Usage

#### Command Line Interface

##### Scanning files in your current directory

```bash
python run_cli.py --provider openai --directory path/to/your/code
```

OR

```bash
python run_cli.py --provider huggingface --directory path/to/your/code
```

##### Scanning with a Custom AI Server

To scan code using a custom AI server:

```bash
python run_cli.py --provider custom --host http://localhost --port 5000 --token your_token --directory path/to/your/code
```

##### Using Security Features

To use the security features:

```bash
python run_cli.py --provider huggingface --sast --fix --validate --directory path/to/your/code
```

##### Running DAST Scans

To perform a Dynamic Application Security Testing (DAST) scan on a web application:

```bash
python run_cli.py --provider huggingface --dast --target-url "https://example.com" --directory path/to/your/code
```

For a basic scan without using OWASP ZAP:

```bash
python run_cli.py --provider huggingface --dast --target-url "https://example.com" --use-basic-scanner --directory path/to/your/code
```

If you have OWASP ZAP installed, you can specify the path:

```bash
python run_cli.py --provider huggingface --dast --target-url "https://example.com" --zap-path "/path/to/zap" --directory path/to/your/code
```

##### Scanning GitHub Repositories

To scan a GitHub repository and create a pull request with fixes:

```bash
python run_cli.py --provider huggingface --sast --fix --validate --create-pr --repo "your-username/your-repo" --github-token "your-github-token" --dashboard
```

#### Web Interface

SecFixAI also provides a web interface for easier interaction:

1. Start the web server:

```bash
python run_web.py
```

2. The browser will automatically open to the home page at `http://127.0.0.1:5000`

3. Use the web interface to:
   - Scan your code for vulnerabilities using SAST, SCA, or DAST
   - Generate and validate fixes
   - Create pull requests with fixes
   - View security metrics dashboard
   - Connect to GitHub and scan repositories
   - Perform dynamic scanning of web applications

### Supported arguments

| name           | description                                               | required | default        |
| -------------- | --------------------------------------------------------- | -------- | -------------- |
| `provider`     | <p>AI provider</p>                                        | `true`   | `""`           |
| `model`        | <p>AI model to use</p>                                    | `false`  | `""`           |
| `directory`    | <p>Directory to scan</p>                                  | `false`  | `.`            |
| `changes_only` | <p>Scan only changed files</p>                            | `false`  | `false`        |
| `repo`         | <p>GitHub repository</p>                                  | `false`  | `""`           |
| `pr_number`    | <p>Pull request number</p>                                | `false`  | `""`           |
| `github_token` | <p>GitHub API token</p>                                   | `false`  | `""`           |
| `sast`         | <p>Perform SAST scanning</p>                              | `false`  | `false`        |
| `sca`          | <p>Perform SCA scanning</p>                              | `false`  | `false`        |
| `dast`         | <p>Perform DAST scanning</p>                             | `false`  | `false`        |
| `target_url`   | <p>Target URL for DAST scanning</p>                      | `false`  | `""`           |
| `fix`          | <p>Generate fixes for vulnerabilities</p>                 | `false`  | `false`        |
| `validate`     | <p>Validate generated fixes</p>                           | `false`  | `false`        |
| `create-pr`    | <p>Create a pull request with fixes</p>                    | `false`  | `false`        |
| `dashboard`    | <p>Show security metrics dashboard</p>                     | `false`  | `false`        |
| `host`         | <p>Custom AI server host</p>                              | `false`  | `""`           |
| `port`         | <p>Custom AI server port</p>                              | `false`  | `""`           |
| `token`        | <p>Token for authenticating with the custom AI server</p> | `false`  | `""`           |
| `endpoint`     | <p>API endpoint for the custom server</p>                 | `false`  | `/api/v1/scan` |

### Limitations

- **Large number of files:** SecFixAI currently does not support a scalable way to scan a large number of files in a single run. Depending on the capacity of your AI Provider, you might run into a `rate_limit_exceeded` error. To work around this, you can create a custom solution that breaks down the number of files for each run.

## Key Features

- **Multi-language Support**: Detects vulnerabilities in JavaScript, Python, Java, PHP, Ruby, and Go.
- **Context-aware Scanning**: Reduces false positives through intelligent context analysis.
- **Real-time Vulnerability Database**: Connects to the National Vulnerability Database (NVD) for up-to-date information.
- **Comprehensive CI/CD Integration**: Ready-to-use configurations for GitHub Actions, Jenkins, and GitLab CI.
- **Enhanced Reporting**: HTML and JSON reports with detailed vulnerability information.
- **Interactive Dashboard**: Visualize security metrics and trends with charts and graphs.

## Recent Improvements

- **Dynamic Application Security Testing (DAST)**: Added capability to scan web applications for runtime vulnerabilities.
- **Improved Web Interface**: Enhanced user experience with better navigation and results display.
- **Scan Type Selection**: Added ability to choose between SAST, SCA, and DAST scans or combinations.
- **Automatic Browser Launch**: The web interface now automatically opens in your default browser.
- **Better Results Display**: Improved formatting and organization of scan results for each scan type.
- **GitHub Integration**: Enhanced GitHub repository scanning and pull request creation.

## Roadmap

- **Batch Processing:** Implement batch processing for scanning large numbers of files efficiently.

- **Caching Implementation:** Add a caching mechanism to store results of previously scanned files, reducing the number of API calls and optimizing performance.

- **Expanded Git Provider Support:** Extend support to other Git providers like GitLab, Bitbucket, and Azure Repos beyond the current GitHub integration.

- **IDE Integrations:** Expand this tool to be accessible in various development environments, such as VSCode extensions.

- **Additional Language Support**: Add support for more programming languages like C/C++, C#, Rust, etc.

- **Machine Learning-based Vulnerability Detection**: Implement ML models to improve vulnerability detection accuracy.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your improvements.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.