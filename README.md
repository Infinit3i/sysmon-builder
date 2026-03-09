# Sysmon Config Builder

<div align="center">
  <img src="https://github.com/Infinit3i/sysmon-builder/blob/d367ad1680b642e9badfaf7a506ef403aa0828e2/assets/sysmon.png" alt="SYSMON" width="400">
</div>

<p align="center">
  <br><br>
    <a title="Releases" target="_blank" href="https://github.com/infinit3i/sysmon-builder/releases"><img src="https://img.shields.io/github/release/infinit3i/sysmon-builder.svg?style=flat-square&color=9CF"></a>
    <a title="Hits" target="_blank" href="https://github.com/infinit3i/sysmon-builder"><img src="https://hits.b3log.org/infinit3i/sysmon-builder.svg"></a>
    <a title="Code Size" target="_blank" href="https://github.com/infinit3i/sysmon-builder"><img src="https://img.shields.io/github/languages/code-size/infinit3i/sysmon-builder.svg?style=flat-square&color=yellow"></a>
  <br>
    <a title="Stars" target="_blank" href="https://github.com/infinit3i/sysmon-builder/stars"><img src="https://img.shields.io/github/issues-pr-closed/infinit3i/sysmon-builder.svg?style=flat-square&color=FF9966"></a>
    <a title="GitHub Pull Requests" target="_blank" href="https://github.com/infinit3i/sysmon-builder/pulls"><img src="https://img.shields.io/github/issues-pr-closed/infinit3i/sysmon-builder.svg?style=flat-square&color=FF9966"></a>
    <a title="GitHub Commits" target="_blank" href="https://github.com/infinit3i/sysmon-builder/commits/master"><img src="https://img.shields.io/github/commit-activity/m/infinit3i/sysmon-builder.svg?style=flat-square"></a>
    <a title="Last Commit" target="_blank" href="https://github.com/infinit3i/sysmon-builder/commits/master"><img src="https://img.shields.io/github/last-commit/infinit3i/sysmon-builder.svg?style=flat-square&color=FF9900"></a>

Sysmon Config Builder is a GUI tool for creating, editing, importing, and exporting **Microsoft Sysmon configuration files**. It allows users to construct event filtering rules without manually editing XML, making it easier to build and maintain custom Sysmon configurations.

## Features

- Import existing Sysmon configuration XML files
- Create and modify Sysmon event filtering rules
- Support for all Sysmon Event IDs (1–30)
- Field-aware rule creation based on event type
- Preset values for common binaries and processes
- Export valid Sysmon XML configurations
- Cross-platform GUI built with PySide6

## Running the Application (Recommended)

## Download

Pre-built releases are available on the **Releases** page.

1. Download the latest release archive for your platform:
   - `sysmon-builder-windows.zip`
   - `sysmon-builder-linux.tar.gz`

2. Extract the archive.

3. Run the application:

### **Windows**

[![Download Windows](https://img.shields.io/badge/Download-Windows-blue?style=for-the-badge)](https://github.com/Infinit3i/sysmon-builder/releases/latest/download/sysmon-builder-windows.zip)

`unzip sysmon-builder-windows.zip`

Run:

```
dist/sysmon-builder/sysmon-builder.exe
```

or double-click `sysmon-builder.exe`.

### **Linux**

[![Download Linux](https://img.shields.io/badge/Download-Linux-orange?style=for-the-badge)](https://github.com/Infinit3i/sysmon-builder/releases/latest/download/sysmon-builder-linux.tar.gz)

`tar -xzvf sysmon-builder-linux.tar.gz`


Run:

```bash
./sysmon-builder
````

No Python installation is required when using the packaged release.

## Running From Source

If you want to run the project directly from source.

### Requirements

* Python 3.11+
* PySide6

Install dependencies:

```bash
pip install PySide6
```

Run the application:

```bash
python main.py
```

## Usage

1. Select a Sysmon event from the event list.
2. Choose rule parameters:

   * Rule type (`include` or `exclude`)
   * Field
   * Condition
   * Value (preset or custom)
3. Add rules to build the configuration.
4. Import an existing Sysmon XML configuration if desired.
5. Export the configuration to a new XML file.
