; FCP 客户端 Windows 安装包（Inno Setup 6）。
;
; 由 .github/workflows/release.yml 的 windows-client job 调用：
;
;   ISCC.exe /DMyAppVersion=0.0.1 ^
;            /DSourceDir=D:\a\fcp\fcp\deploy ^
;            /DOutputDir=D:\a\fcp\fcp\dist ^
;            packaging\windows\fcp-client.iss
;
; SourceDir 就是 windeployqt 之后的可运行目录（fcp_client.exe + Qt 运行时 +
; platforms\qwindows.dll 等）。安装包不做任何"运行时缺席"的兜底：windeployqt
; 少拷了哪个 DLL，装出来就是启动即报缺 DLL —— 那是打包流程的问题，不是安装器
; 该掩盖的（release.yml 里有一条启动冒烟测试专门咬这个）。

#ifndef MyAppVersion
  #define MyAppVersion "0.0.0-dev"
#endif
#ifndef SourceDir
  #define SourceDir "..\..\build\windows-x64-app\apps\fcp-client\Release"
#endif
#ifndef OutputDir
  #define OutputDir "..\..\dist"
#endif

#define MyAppName "FCP 客户端"
#define MyAppNameEn "FCP Client"
#define MyAppPublisher "dchen8525-dev"
#define MyAppURL "https://github.com/dchen8525-dev/fcp"
#define MyAppExeName "fcp_client.exe"
; QSettings 在 Windows 上写注册表（organization FCP / application FCPClient，
; 见 apps/fcp-client/main.cc），卸载时清掉。
#define MyAppRegKey "Software\FCP"
; 运维文档目录（仓库 docs\），由调用方 /DDocsDir= 传入。
#ifndef DocsDir
  #define DocsDir "..\..\docs"
#endif

[Setup]
; AppId 是升级识别的唯一键：**一旦发布过就不要再改**，否则新版本会装成第二份。
AppId={{8C1F4B21-9D3E-4C77-A5B2-7E0F6D4A2C10}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}/releases
VersionInfoVersion={#MyAppVersion}
VersionInfoProductName={#MyAppNameEn}
VersionInfoCompany={#MyAppPublisher}
DefaultDirName={autopf}\FCP
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
; 默认按用户安装（免 UAC）：一个代理客户端不需要管理员权限，装进
; %LOCALAPPDATA%\Programs 即可。需要全机安装的用户可在安装界面切换。
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir={#OutputDir}
OutputBaseFilename=FCP-Client-{#MyAppVersion}-win64-setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
; 不设 ArchitecturesInstallIn64BitMode：客户端默认按用户装进
; %LOCALAPPDATA%\Programs，路径本就无重定向，装 32 位视图只会在注册表多一层
; WOW6432Node，卸载清理反而更绕。

[Languages]
Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; windeployqt 的输出整目录；recursesubdirs 拖进 platforms\、styles\、imageformats\ 等。
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; 运维/排障文档：调用方用 /DDocsDir= 指过来（仓库 docs\），装到程序目录，
; 卸载时一并删除。skipifsourcedoesntexist 保证手工 ISCC 试打包时不因此失败。
Source: "{#DocsDir}\部署运维指南.md"; DestDir: "{app}\docs"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{#MyAppName} 文档"; Filename: "{app}\docs\部署运维指南.md"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; 装完给个"立即运行"的勾选项；不勾也能从开始菜单起。
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent

[Code]
// 卸载时清掉 QSettings 留下的注册表键（Software\FCP\FCPClient）。
// 只删自己的键；用户机器上其它 Software\FCP 下的东西不动。
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    RegDeleteKeyIncludingSubkeys(HKCU, '{#MyAppRegKey}');
    if IsAdminInstallMode then
      RegDeleteKeyIncludingSubkeys(HKLM, '{#MyAppRegKey}');
  end;
end;
