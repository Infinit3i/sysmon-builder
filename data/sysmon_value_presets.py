SYS_MON_VALUE_PRESETS: dict[str, list[str]] = {
    "Image": [
        "powershell.exe",              # Windows PowerShell interpreter (commonly abused for execution and download cradles)
        "powershell_ise.exe",          # PowerShell Integrated Scripting Environment
        "pwsh.exe",                    # PowerShell Core (cross-platform PowerShell)
        "cmd.exe",                     # Windows command interpreter
        "wscript.exe",                 # Windows Script Host (GUI)
        "cscript.exe",                 # Windows Script Host (CLI)
        "mshta.exe",                   # Executes HTA files (frequently abused LOLBin)
        "rundll32.exe",                # Executes exported DLL functions (common living-off-the-land technique)
        "regsvr32.exe",                # Registers COM objects (often abused to load remote scripts)
        "regsvcs.exe",                 # .NET service registration utility
        "regasm.exe",                  # Registers .NET assemblies
        "certutil.exe",                # Certificate utility often abused for file download/encoding
        "bitsadmin.exe",               # BITS download tool (used for persistence and file staging)
        "wmic.exe",                    # Windows Management Instrumentation CLI
        "schtasks.exe",                # Scheduled task management (persistence technique)
        "at.exe",                      # Legacy scheduled task tool
        "net.exe",                     # Windows networking command utility
        "net1.exe",                    # Alternative version of net.exe
        "whoami.exe",                  # Displays current user identity
        "ipconfig.exe",                # Network configuration display
        "nslookup.exe",                # DNS lookup tool
        "nltest.exe",                  # Active Directory domain controller testing
        "netstat.exe",                 # Displays network connections
        "tasklist.exe",                # Lists running processes
        "qprocess.exe",                # Displays processes on RDS servers
        "qwinsta.exe",                 # Query terminal sessions
        "rwinsta.exe",                 # Reset terminal session
        "quser.exe",                   # Query logged-in users
        "runas.exe",                   # Execute program as another user
        "curl.exe",                    # HTTP transfer tool
        "wget.exe",                    # HTTP download utility
        "ftp.exe",                     # FTP client
        "winrs.exe",                   # Windows Remote Shell
        "wsmprovhost.exe",             # WinRM provider host
        "winrshost.exe",               # WinRM command host
        "mofcomp.exe",                 # WMI MOF compiler (persistence vector)
        "wmiprvse.exe",                # WMI provider host process
        "scrcons.exe",                 # WMI script consumer
        "pcalua.exe",                  # Program compatibility assistant launcher
        "bash.exe",                    # Windows Subsystem for Linux launcher
        "hh.exe",                      # HTML help viewer (used in LOLBin chains)
        "installutil.exe",             # .NET installer utility (commonly abused)
        "msbuild.exe",                 # Microsoft build engine (used for code execution)
        "msiexec.exe",                 # Windows installer execution engine
        "odbcconf.exe",                # ODBC configuration tool
        "desktopimgdownldr.exe",       # Desktop image downloader (LOLBin abuse)
        "replace.exe",                 # Replace files utility
        "diskshadow.exe",              # VSS snapshot tool
        "esentutl.exe",                # Extensible storage engine utility
        "ntdsutil.exe",                # Active Directory database maintenance tool
        "rpcping.exe",                 # RPC connectivity testing tool
        "vssadmin.exe",                # Volume shadow copy management
        "wbadmin.exe",                 # Backup utility
        "bcdedit.exe",                 # Boot configuration editor
        "wevtutil.exe",                # Windows event log management tool
        "fsutil.exe",                  # File system utility
        "dnscmd.exe",                  # DNS server management tool
        "sc.exe",                      # Windows service controller
        "taskkill.exe",                # Process termination utility
        "xcopy.exe",                   # File copy utility
        "robocopy.exe",                # Advanced file copy utility
        "PktMon.exe",                  # Windows packet monitor
        "PsExec.exe",                  # Sysinternals remote execution tool
        "PsExec.c",
        "PsList.exe",                  # Sysinternals process listing tool
        "PsService.exe",               # Sysinternals service management tool
        "PsGetSID.exe",                # Sysinternals SID lookup
        "PsKill.exe",                  # Sysinternals process killer
        "PsLoggedOn.exe",              # Sysinternals user session viewer
        "PsFile.exe",                  # Sysinternals open file viewer
        "PipeList.exe",                # Sysinternals named pipe viewer
        "AccessChk.exe",               # Sysinternals permission auditing tool
        "AccessEnum.exe",              # Sysinternals access enumeration tool
        "LogonSessions.exe",           # Sysinternals logon session viewer
        "PsLogList.exe",               # Sysinternals event log viewer
        "PsInfo.exe",                  # Sysinternals system information tool
        "PsPasswd.exe",                # Sysinternals password reset tool
        "ProcDump.exe",                # Sysinternals process dump utility
        "procdump.exe",
        "chrome.exe",                  # Google Chrome browser
        "firefox.exe",                 # Mozilla Firefox browser
        "msedge.exe",                  # Microsoft Edge browser
        "iexplore.exe",                # Internet Explorer
        "outlook.exe",                 # Microsoft Outlook
        "winword.exe",                 # Microsoft Word
        "excel.exe",                   # Microsoft Excel
        "powerpnt.exe",                # Microsoft PowerPoint
        "onenote.exe",                 # Microsoft OneNote
        "msaccess.exe",                # Microsoft Access
        "teams.exe",                   # Microsoft Teams
        "discord.exe",                 # Discord client
        "java.exe",                    # Java runtime launcher
        "javaw.exe",                   # Java runtime launcher (no console)
        "javaws.exe",                  # Java Web Start
        "notepad.exe",                 # Windows text editor
        "mmc.exe",                     # Microsoft Management Console
        "explorer.exe",                # Windows shell
        "services.exe",                # Windows service control manager
        "svchost.exe",                 # Generic service host
        "lsass.exe",                   # Local Security Authority subsystem
        "dllhost.exe",                 # COM surrogate host
        "tor.exe",                     # Tor network client
        "software_reporter_tool.exe",  # Chrome cleanup/reporting tool
        "OneDrive.exe",                # Microsoft OneDrive client
        "OneDriveStandaloneUpdater.exe", # OneDrive updater
        "Dropbox.exe",                 # Dropbox client
        "spotify.exe",                 # Spotify client
        "splunk.exe",                  # Splunk CLI
        "splunkd.exe",                 # Splunk daemon
        "winlogbeat.exe",              # Elastic Windows log shipper
        "packetbeat.exe",              # Elastic network data shipper
            "procexp.exe",                 # Sysinternals Process Explorer
        "procmon.exe",                 # Sysinternals Process Monitor
        "tcpview.exe",                 # Sysinternals TCP connection viewer
        "autoruns.exe",                # Sysinternals persistence inspection tool
        "sigcheck.exe",                # Sysinternals file signature checker
        "strings.exe",                 # Sysinternals string extraction tool
        "handle.exe",                  # Sysinternals open handle viewer
        "vmmap.exe",                   # Sysinternals virtual memory inspector
        "rammap.exe",                  # Sysinternals memory analysis tool
        "bginfo.exe",                  # Sysinternals desktop system info display
        "livekd.exe",                  # Sysinternals kernel debugging tool
        "klist.exe",                   # Kerberos ticket viewer
        "ktpass.exe",                  # Kerberos service principal management
        "setspn.exe",                  # Service principal name configuration tool
        "dsquery.exe",                 # Active Directory query tool
        "dsget.exe",                   # Active Directory object information tool
        "dsadd.exe",                   # Active Directory object creation tool
        "dsmod.exe",                   # Active Directory object modification tool
        "dsrm.exe",                    # Active Directory object deletion tool
        "gpupdate.exe",                # Group policy update tool
        "gpresult.exe",                # Group policy result viewer
        "logoff.exe",                  # Logs off a user session
        "shutdown.exe",                # Shutdown or reboot system
        "takeown.exe",                 # Take ownership of files
        "icacls.exe",                  # Modify file ACL permissions
        "attrib.exe",                  # Change file attributes
        "timeout.exe",                 # Command line delay utility
        "choice.exe",                  # Command-line prompt selection tool
        "where.exe",                   # Locate executable paths
        "hostname.exe",                # Display system hostname
    ],
    "ParentImage": [
        "explorer.exe",
        "winword.exe",
        "excel.exe",
        "outlook.exe",
        "powerpnt.exe",
        "msaccess.exe",
        "powershell.exe",
        "cmd.exe",
        "services.exe",
        "svchost.exe",
        "lsass.exe",
        "mshta.exe",
        "rundll32.exe",
        "wmiprvse.exe",
        "wsl.exe",
        "control.exe",
        "hh.exe",
        "eventvwr.exe",
        "fodhelper.exe",
        "diskshadow.exe",
        "csc.exe",
        "wmic.exe",
        "wab.exe",
        "devtoolslauncher.exe",
        "vsjitdebugger.exe",
        "wscript.exe",
        "cscript.exe",
        "excel.exe",
        "winword.exe",
        "powerpnt.exe",
        "outlook.exe",
        "mspub.exe",
    ],
    "CommandLine": [
        "-enc",
        "-encodedcommand",
        "downloadstring",
        "invoke-expression",
        "iex",
        "http://",
        "https://",
        ".ps1",
        ".vbs",
        ".js",
        ".hta",
        ".bat",
        ".cmd",
        "frombase64",
        "gzip",
        "decompress",
        "replace",
        "../../",
        "Set-MpPreference",
        "-DisableRealTimeMonitoring $true",
        "-DisableBehaviorMonitoring $true",
        "-DisableScriptScanning $true",
        "/logfile=",
        "/LogToConsole=false",
        "/U",
        "/y",
        "/vss",
        "/d",
        "ifm",
        "delete shadow",
        "delete catalog",
        "recoveryenabled no",
        "bootstatuspolicy ignoreallfailures",
        "diskshadow.exe /s",
        "diskshadow.exe -s",
        "wsl.exe -e",
        "wsl.exe /e",
        "wsl.exe -u root",
        "wsl.exe /u root",
        "wsl.exe --exec bash",
        "pubprn",
        "slmgr",
        "manage-bde",
        "winrm",
        "rundll32.exe dfshim.dll,ShOpenVerbApplication http://",
        "msdeploy.exe -verb:sync -source:RunCommand",
        "vsjitdebugger",
        "Scriptrunner.exe -appvscript",
        "xwizard RunWizard",
        "net view",
        "net group",
        "net localgroup",
        "net user",
        "dir C:\\Users",
        "ls C:\\Users",
        "wevtutil cl",
        "clear-log",
        "reg.exe",
        "regedit.exe",
        "HKLM",
        "hkey_local_machine",
        "\\system",
        "\\sam",
        "\\security",
        "/i",
        ".reg",
        "runas",
        "pester",
        "bginfo",
        "update.exe --update",
        "update.exe --ProcessStart",
        "squirrel --download",
        "update --download",
        "misc::mflt",
        "unload",
        "detach",
        "vssadmin delete",
        "wbadmin delete",
        "bcdedit /set",
        "wmic delete shadowcopy",
    ],
    "DestinationPort": [
        "22",
        "23",
        "25",
        "53",
        "80",
        "88",
        "135",
        "139",
        "389",
        "443",
        "445",
        "636",
        "1080",
        "3128",
        "3389",
        "4444",
        "4500",
        "5353",
        "5555",
        "5800",
        "5900",
        "5985",
        "5986",
        "6667",
        "6697",
        "8080",
        "8443",
        "9001",
        "9030",
        "9389",
        "31337",
    ],
    "DestinationIp": [
        "127.0.0.1",        # localhost
        "0.0.0.0",          # wildcard address
        "8.8.8.8",          # Google DNS
        "1.1.1.1",          # Cloudflare DNS

        "8.8.4.4",          # Google secondary DNS
        "9.9.9.9",          # Quad9 DNS
        "149.112.112.112",  # Quad9 secondary DNS
        "208.67.222.222",   # OpenDNS
        "208.67.220.220",   # OpenDNS secondary
        "4.2.2.2",          # Level3 DNS
        "4.2.2.1",          # Level3 DNS
        "4.2.2.3",          # Level3 DNS
        "4.2.2.4",          # Level3 DNS
        "4.2.2.5",          # Level3 DNS
        "4.2.2.6",          # Level3 DNS
        "64.6.64.6",        # Verisign DNS
        "64.6.65.6",        # Verisign secondary DNS
        "94.140.14.14",     # AdGuard DNS
        "94.140.15.15",     # AdGuard secondary DNS
        "76.76.19.19",      # ControlD DNS
        "76.223.122.150",   # ControlD secondary DNS
        "185.228.168.9",    # CleanBrowsing DNS
        "185.228.169.9",    # CleanBrowsing secondary
        "198.101.242.72",   # Dyn DNS
        "156.154.70.1",     # Neustar DNS
        "156.154.71.1",     # Neustar secondary
        "192.168.1.1",      # common home router
        "192.168.0.1",      # common home router
        "10.0.0.1",         # internal gateway
        "172.16.0.1",       # internal gateway
        "169.254.169.254",  # cloud metadata service (AWS/Azure/GCP)
    ],
    "DestinationHostname": [
        ".windowsupdate.microsoft.com",
        ".windowsupdate.com",
        "wustat.windows.com",
        "go.microsoft.com",
        ".update.microsoft.com",
        "download.microsoft.com",
        "microsoft.com.akadns.net",
        "microsoft.com.nsatc.net",
    ],
    "ImageLoaded": [
        "amsi.dll",
        "ntdll.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "dbghelp.dll",
        "dbgcore.dll",
        "wininet.dll",
        "urlmon.dll",
        "clr.dll",
        "clrjit.dll",
        "mscoree.dll",
        "mscoreei.dll",
        "mscoreeis.dll",
        "mscorlib.dll",
        "mscorlib.ni.dll",
        "jscript.dll",
        "jscript9.dll",
        "vbscript.dll",
        "scrobj.dll",
        "wshom.ocx",
        "taskschd.dll",
        "mstask.dll",
        "system.management.automation.dll",
        "system.management.automation.ni.dll",
        "Microsoft.PowerShell.Commands.Diagnostics.dll",
        "Microsoft.PowerShell.Commands.Management.dll",
        "Microsoft.PowerShell.Commands.Utility.dll",
        "Microsoft.PowerShell.ConsoleHost.dll",
        "Microsoft.PowerShell.Security.dll",
        "wmiutils.dll",
        "bitsproxy.dll",
        "comsvcs.dll",
        "regsvc.dll",
        "scrrun.dll",
        "vbscript.dll",
    ],
    "TargetFilename": [
        ".exe",                         # executable file
        ".dll",                         # dynamic library
        ".ps1",                         # PowerShell script
        ".vbs",                         # VBScript
        ".js",                          # JavaScript
        ".hta",                         # HTML application
        ".bat",                         # batch script
        ".cmd",                         # command script
        ".scr",                         # screensaver executable
        ".zip",                         # compressed archive
        ".rar",                         # compressed archive
        ".wll",                         # Word add-in
        ".xll",                         # Excel add-in
        "C:\\Windows\\AppPatch\\Custom",             # Application Compatibility persistence location
        "C:\\Windows\\AppPatch\\Custom\\Custom64",   # 64-bit AppPatch persistence path
        "Zone.Identifier",              # Mark-of-the-Web ADS
        ".7z",                          # compressed archive
        ".iso",                         # disk image often used for malware delivery
        ".img",                         # disk image
        ".cab",                         # cabinet archive
        ".msi",                         # Windows installer package
        ".lnk",                         # Windows shortcut (frequently abused for execution)
        ".pif",                         # legacy program information file
        ".application",                 # ClickOnce deployment file
        ".jar",                         # Java archive
        ".class",                       # Java bytecode file
        ".sys",                         # driver file
        ".dat",                         # generic data file often used for payload storage
        ".tmp",                         # temporary file used in staging payloads
        ".config",                      # .NET configuration files
        ".manifest",                    # application manifest
        ".psm1",                        # PowerShell module
        ".psd1",                        # PowerShell module manifest
        ".chm",                         # compiled help file used for code execution
        ".ocx",                         # COM control
        ".drv",                         # driver file
        ".cpl",                         # Control Panel item
        ".msc",                         # Microsoft Management Console snap-in
        "C:\\Users\\Public",            # common attacker staging directory
        "C:\\ProgramData",              # hidden system-wide writable location
        "C:\\Windows\\Temp",            # system temp directory
        "%TEMP%",                       # user temp directory
    ],
    "TargetObject": [
        "Run",
        "RunOnce",
        "Services",
        "Winlogon",
        "Image File Execution Options",
        "Shell",
        "Userinit",
        "AppInit_DLLs",
        "IFEO",
        "CurrentVersion\\Run",
        "CurrentVersion\\RunOnce",
        "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    ],
    "QueryName": [
        "pastebin.com",
        "github.com",
        "raw.githubusercontent.com",
        "bit.ly",
        "tinyurl.com",
        "discord.com",
        "telegram.org",
        "1rx.io",
        "adservice.google.com",
        "ampcid.google.com",
        "clientservices.googleapis.com",
        "googleadapis.l.google.com",
        "imasdk.googleapis.com",
        "l.google.com",
        "mtalk.google.com",
        "update.googleapis.com",
        "www.googletagservices.com",
        "clients1.google.com",
        "clients2.google.com",
        "clients3.google.com",
        "clients4.google.com",
        "clients5.google.com",
        "clients6.google.com",
        "safebrowsing.googleapis.com",
        ".mozaws.net",
        ".mozilla.com",
        ".mozilla.net",
        ".mozilla.org",
        ".akadns.net",
        ".netflix.com",
        "ajax.googleapis.com",
        "cdnjs.cloudflare.com",
        "fonts.googleapis.com",
        ".typekit.net",
        ".steamcontent.com",
    ],
    "OriginalFileName": [
        "powershell.exe",
        "cmd.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "wmic.exe",
        "schtasks.exe",
        "mshta.exe",
        "regsvr32.exe",
        "rundll32.exe",
        "sc.exe",
        "dnscmd.exe",
        "taskkill.exe",
        "xcopy.exe",
        "robocopy.exe",
        "PktMon.exe",
        "esentutl.exe",
        "ntdsutil.exe",
        "rpcping.exe",
        "wevtutil.exe",
        "fsutil.exe",
        "runas.exe",
        "netsh.exe",
        "ipconfig.exe",
        "nslookup.exe",
        "tracert.exe",
        "route.exe",
        "whoami.exe",
        "quser.exe",
        "tasklist.exe",
        "reg.exe",
        "regedit.exe",
        "InstallUtil.exe",
        "odbcconf.exe",
        "hh.exe",
        "Mavinject.exe",
        "CMSTP.exe",
        "MSBuild.exe",
        "winrshost.exe",
        "wsmprovhost.exe",
        "curl.exe",
        "Print.exe",
        "IEExec.exe",
        "expand.exe",
        "replace.exe",
        "diskshadow.exe",
        "bcdedit.exe",
        "vssadmin.exe",
        "wbadmin.exe",
        "PsExec.exe",
        "ProcDump.exe",
    ],
    "SourceImage": [
        "powershell.exe",
        "cmd.exe",
        "wsmprovhost.exe",
        "wmiprvse.exe",
        "software_reporter_tool.exe",
        "MsMpEng.exe",
        "splunkd.exe",
        "Code.exe",
        "taskmgr.exe",
        "GoogleUpdate.exe",
        "svchost.exe",
        "wininit.exe",
        "csrss.exe",
        "services.exe",
        "winlogon.exe",
        "audiodg.exe",
        "dwm.exe",
    ],
    "TargetImage": [
        "lsass.exe",
        "csrss.exe",
        "wininit.exe",
        "winlogon.exe",
        "services.exe",
        "chrome.exe",
        "Code.exe",
        "cscript.exe",
        "Teams.exe",
    ],
    "PipeName": [
        "\\srvsvc",
        "\\wkssvc",
        "\\lsass",
        "\\winreg",
        "\\spoolss",
        "\\SQLLocal\\MSSQLSERVER",
        "\\SQLLocal\\INSTANCE01",
        "\\SQLLocal\\SQLEXPRESS",
        "\\SQLLocal\\COMMVAULT",
        "\\SQLLocal\\RTCLOCAL",
        "\\SQLLocal\\RTC",
        "\\SQLLocal\\TMSM",
        "\\pgsignal_",
        "\\mojo.",
        "\\chrome.sync.",
        "\\gecko-crash-server-pipe.",
        "\\cubeb-pipe-",
        "\\crashpad_",
        "\\MsFteWds",
        "\\OfcServerNamePipe",
        "\\ntapvsrq",
        "Anonymous Pipe",
    ],
}

SYS_MON_BASELINE_PRESETS: list[dict[str, object]] = [
    {
        "name": "Exclude Windows Binaries",
        "tooltip": "Common baseline move: exclude native Windows binary paths to reduce noise.",
        "rules": [("exclude", "Image", "begin with", "C:\\Windows\\")],
    },
    {
        "name": "Exclude Microsoft Signed",
        "tooltip": "Common baseline move: exclude known Microsoft-signed binaries/libraries where applicable.",
        "rules": [
            ("exclude", "Company", "contains", "Microsoft"),
            ("exclude", "Signature", "contains", "Microsoft"),
        ],
    },
    {
        "name": "Exclude Known Enterprise Apps",
        "tooltip": "Common baseline move: exclude repeatedly-seen enterprise software to focus on anomalies.",
        "rules": [
            ("exclude", "Image", "contains", "\\Program Files\\Microsoft Office\\"),
            ("exclude", "Image", "contains", "\\Program Files\\Google\\Chrome\\"),
            ("exclude", "Image", "contains", "\\Program Files (x86)\\Microsoft\\Edge\\"),
            ("exclude", "Image", "contains", "\\Program Files\\Microsoft OneDrive\\"),
        ],
    },
    {
        "name": "Include Non-Windows Apps",
        "tooltip": "Common baseline move: explicitly include non-Windows application paths for close monitoring.",
        "rules": [
            ("include", "Image", "begin with", "C:\\Program Files\\"),
            ("include", "Image", "begin with", "C:\\Program Files (x86)\\"),
        ],
    },
    {
        "name": "Include Unsigned Processes",
        "tooltip": "Common baseline move: include unsigned execution/module activity for triage priority.",
        "rules": [("include", "Signed", "is", "false")],
    },
]


def _unique(values: list[str], limit: int = 12) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        key = value.strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(value)
        if len(out) >= limit:
            break
    return out


def _values_by_keywords(field: str, keywords: list[str], limit: int = 12) -> list[str]:
    candidates = SYS_MON_VALUE_PRESETS.get(field, [])
    picked = [
        value
        for value in candidates
        if any(keyword.lower() in value.lower() for keyword in keywords)
    ]
    return _unique(picked, limit=limit)


def _rules(rule_type: str, field: str, condition: str, values: list[str]) -> list[tuple[str, str, str, str]]:
    return [(rule_type, field, condition, value) for value in values]


SYS_MON_BASELINE_PRESETS.extend(
    [
        {
            "name": "Include Scripting Interpreters",
            "tooltip": "Most teams monitor script engines closely for execution and staging activity.",
            "rules": _rules(
                "include",
                "Image",
                "is",
                _values_by_keywords(
                    "Image",
                    ["powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32"],
                    limit=10,
                ),
            ),
        },
        {
            "name": "Include Remote Admin Utilities",
            "tooltip": "Most teams monitor remote-admin binaries for lateral movement and hands-on-keyboard activity.",
            "rules": _rules(
                "include",
                "Image",
                "is",
                _values_by_keywords(
                    "Image",
                    ["psexec", "winrs", "wsmprovhost", "wmic", "schtasks", "net.exe", "quser", "qwinsta"],
                    limit=12,
                ),
            ),
        },
        {
            "name": "Include Data Staging Utilities",
            "tooltip": "Most teams monitor common download/transfer/staging utilities for suspicious use.",
            "rules": _rules(
                "include",
                "Image",
                "is",
                _values_by_keywords(
                    "Image",
                    ["curl.exe", "wget.exe", "ftp.exe", "certutil", "bitsadmin", "robocopy", "xcopy"],
                    limit=12,
                ),
            ),
        },
        {
            "name": "Include Suspicious CommandLine Flags",
            "tooltip": "Most teams include high-signal command-line patterns tied to obfuscation and defense evasion.",
            "rules": _rules(
                "include",
                "CommandLine",
                "contains",
                _values_by_keywords(
                    "CommandLine",
                    ["-enc", "encodedcommand", "invoke-expression", "downloadstring", "frombase64", "disable"],
                    limit=12,
                ),
            ),
        },
        {
            "name": "Exclude Common Parent Processes",
            "tooltip": "Most teams exclude very common parent processes first, then re-include scoped suspicious cases.",
            "rules": _rules(
                "exclude",
                "ParentImage",
                "is",
                _values_by_keywords(
                    "ParentImage",
                    ["explorer.exe", "services.exe", "svchost.exe", "winword.exe", "excel.exe", "outlook.exe"],
                    limit=10,
                ),
            ),
        },
        {
            "name": "Include High-Risk Target Processes",
            "tooltip": "Most teams include access/targeting against high-value processes for rapid triage.",
            "rules": _rules(
                "include",
                "TargetImage",
                "is",
                _values_by_keywords(
                    "TargetImage",
                    ["lsass.exe", "winlogon.exe", "services.exe", "csrss.exe", "wininit.exe"],
                    limit=8,
                ),
            ),
        },
        {
            "name": "Include Sensitive Named Pipes",
            "tooltip": "Most teams baseline known pipes and monitor unusual pipe usage.",
            "rules": _rules(
                "include",
                "PipeName",
                "contains",
                _values_by_keywords(
                    "PipeName",
                    ["\\lsass", "\\winreg", "\\spoolss", "\\srvsvc", "\\wkssvc", "\\crashpad"],
                    limit=10,
                ),
            ),
        },
    ]
)

SYS_MON_BASELINE_PRESETS = [
    preset for preset in SYS_MON_BASELINE_PRESETS if isinstance(preset.get("rules"), list) and preset["rules"]
]
