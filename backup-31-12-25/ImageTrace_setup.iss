; Script for creating an installer for ImageTrace
; Needs to be compiled with Inno Setup

#define MyAppName "ImageTrace"
#define MyAppVersion "1.0"
#define MyAppPublisher "ImageTrace Project"
#define MyAppURL "https://github.com/user/ImageTrace" ; Placeholder URL
#define MyAppExeName "ImageTrace_GUI.exe"
#define MyAppCliExeName "ImageTrace_CLI.exe"
#define MySetupExeName "ImageTrace-Setup-v1.0"

[Setup]
AppId={{auto}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
LicenseFile=license.txt
SetupIconFile=icon.ico
DisableProgramGroupPage=no
OutputBaseFilename={#MySetupExeName}
Compression=lzma
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Types]
Name: "full"; Description: "Full installation"
Name: "compact"; Description: "Compact installation (GUI only)"
Name: "custom"; Description: "Custom installation"; Flags: iscustom

[Components]
Name: "gui"; Description: "Graphical User Interface"; Types: full compact custom; Flags: fixed
Name: "cli"; Description: "Command-Line Interface"; Types: full

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked; Components: gui

[Files]
Source: "dist\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: gui
Source: "dist\*"; DestDir: "{app}\cli"; Flags: ignoreversion recursesubdirs createallsubdirs; Components: cli
Source: "icon.ico"; DestDir: "{app}"; Flags: ignoreversion; Components: gui

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\icon.ico"; Components: gui
Name: "{autoprograms}\{#MyAppName} (CLI)"; Filename: "{app}\cli\{#MyAppCliExeName}"; Components: cli
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\icon.ico"; Tasks: desktopicon; Components: gui

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent; Components: gui
