# LFIer

![Python](https://img.shields.io/badge/Python-3.x-blue) ![Type](https://img.shields.io/badge/type-security%20tool-red)

A lightweight Python scanner that automates detection of **Local File Inclusion (LFI)** and path-traversal vulnerabilities in a single request parameter. It sweeps common traversal depths and payloads, retries with an encoding bypass, and flags a finding when a known file signature shows up in the response.

## How it works

For each payload it walks the directory tree upward (`../`, `../../`, `../../../`, …) and looks for a signature that only appears if the target file was actually read:

| Payload      | Signature checked | Target OS |
| ------------ | ----------------- | --------- |
| `etc/passwd` | `root:`           | Linux/Unix |
| `boot.ini`   | `[boot loader]`   | Windows   |

If the plain payload is filtered, it automatically retries with **double URL-encoded slashes** (`%252f`) to defeat naive input sanitisation.

## Usage

```bash
python3 LFIer.py -u <url> -p <parameter> [-d DEPTH]
```

| Flag | Description | Default |
| ---- | ----------- | ------- |
| `-u`, `--url`       | Target URL (the page that takes the parameter) | — (required) |
| `-p`, `--parameter` | Parameter to fuzz | — (required) |
| `-d`, `--depth`     | Maximum number of `../` levels to try | `6` |

### Example

```bash
python3 LFIer.py -u http://testphp.vulnweb.com/showimage.php -p file
```

## Install

```bash
git clone https://github.com/Mohamed-Newish/LFIer.git
cd LFIer
pip3 install -r requirements.txt
```

## Disclaimer

This tool is for **authorized security testing and educational use only**. Only run it against systems you own or have explicit permission to test. The author is not responsible for misuse or damage.

## License

Mohamed Sayed — [@kanike99](https://twitter.com/kanike99)
