; Inno Setup Script for Veil AI Privacy Gateway
; Compiles VeilSetup.exe installer

#define MyAppName "Veil AI Privacy Gateway"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "Veil Security"
#define MyAppURL "https://github.com/veil-security/veil"
#define MyAppExeName "Veil.exe"

[Setup]
AppId={{9F82A2E1-C4A1-4890-9E11-37E4C4B18420}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\Veil
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
OutputDir=..\dist
OutputBaseFilename=VeilSetup
SetupIconFile=veil.ico
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "autostart"; Description: "Launch Veil automatically when Windows starts (minimized to system tray)"; GroupDescription: "System Integration:"
Name: "installca"; Description: "Install and trust Veil Root Certificate Authority (enables zero-config transparent AI interception)"; GroupDescription: "Security & Interception:"

[Files]
Source: "..\dist\Veil.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "veil.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Veil Privacy Gateway"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\veil.ico"
Name: "{group}\Uninstall Veil"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Veil"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\veil.ico"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "Veil"; ValueData: """{app}\{#MyAppExeName}"" --gui"; Flags: uninsdeletevalue; Tasks: autostart

[Run]
; Auto-install Root CA if task selected
Filename: "{app}\{#MyAppExeName}"; Parameters: "proxy install-ca"; Flags: runhidden; Tasks: installca; StatusMsg: "Configuring Veil Local Certificate Authority for AI interception..."
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Zero-Corruption Invariant: Roll back all connected IDEs and agent configurations before removing files
Filename: "{app}\{#MyAppExeName}"; Parameters: "disconnect-all"; Flags: runhidden; RunOnceId: "VeilDisconnectRollback"
; Disable Windows System Proxy if still active
Filename: "{app}\{#MyAppExeName}"; Parameters: "proxy disable"; Flags: runhidden; RunOnceId: "VeilProxyDisable"
; Uninstall Veil Root Certificate Authority from Windows trust store
Filename: "{app}\{#MyAppExeName}"; Parameters: "proxy uninstall-ca"; Flags: runhidden; RunOnceId: "VeilCAUninstall"
