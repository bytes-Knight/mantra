<h1 align="center">🔑 Mantra</h1>

<p align="center">
  <img src="assets/banner.png" alt="Mantra Banner">
</p>

## About Mantra

Mantra is a powerful tool written in Go that helps you find API keys and other secrets in web pages and JavaScript files. It scans the source code of websites for strings that match common patterns for API keys, preventing them from being exposed.

This tool is essential for developers and security professionals who need to ensure that sensitive credentials are not accidentally leaked. By identifying exposed keys, Mantra helps you secure your applications and protect against potential attacks.

## Features

- **Fast and Efficient**: Scans files quickly to find secrets without compromising performance.
- **Comprehensive Detection**: Identifies a wide range of API keys and secrets using an extensive set of regex patterns.
- **Easy to Use**: Simple command-line interface that can be easily integrated into your security workflows.
- **Customizable**: Supports custom regex patterns to help you find specific secrets.

## Getting Started

### Installation

You can install Mantra using one of the following methods:

**From Go:**

```bash
go install github.com/Brosck/mantra@latest
```

**From Source:**

```bash
git clone https://github.com/brosck/mantra
cd mantra
make
./build/mantra-amd64-linux -h
```

### Usage

You can use Mantra to scan a list of URLs from a file or standard input.

**Example:**

```bash
cat urls.txt | mantra -t 50
```

For more options and flags, use the `-h` flag to see the help menu.

![](assets/help.png)

## Example Output

Here is an example of Mantra detecting a Firebase API key leak:

<img width="1689" height="559" alt="image" src="https://github.com/user-attachments/assets/c06d2c2e-e2e8-4fc9-b20d-2f6b2ad9a096" />

## Support

If you find this tool helpful, please consider supporting its development.

<a href="https/pixgg.com/MrEmpy" target="_blank">
  <img src="https://pixgg.com/img/logo-darkmode.046d3b61.svg" height="30" width="30">
</a>
<br>
<br>
<a href="https://www.buymeacoffee.com/mrempy" target="_blank">
  <img src="https://play-lh.googleusercontent.com/aMb_Qiolzkq8OxtQZ3Af2j8Zsp-ZZcNetR9O4xSjxH94gMA5c5gpRVbpg-3f_0L7vlo" height="50" width="50">
</a>
