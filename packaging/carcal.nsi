; carcal.nsi — NSIS installer for carcal (built by packaging/windows-installer.sh)
;
; Driven entirely from the command line, so it stays in sync with the zip:
;   makensis -DVERSION=0.0.5 -DSOURCE_DIR=... -DOUTFILE=... -DLICENSE_FILE=... carcal.nsi
;
; It installs the exact directory the bundler produced (carcal.exe + its DLLs +
; protos\ + grammars\ + scripts\), so the installed tree is byte-for-byte the
; portable zip. carcal finds its data relative to carcal.exe, so nothing here
; needs to set environment variables.
;
; Deliberately NOT touched: the system PATH. Editing it from NSIS means
; read-modify-writing a REG_EXPAND_SZ that routinely exceeds NSIS's 1024-char
; string limit, and a truncated PATH is a wrecked machine. Users who want
; carcal on the PATH can add it themselves.

Unicode true
SetCompressor /SOLID lzma

!include "MUI2.nsh"

!ifndef VERSION
  !define VERSION "0.0.0"
!endif
!ifndef SOURCE_DIR
  !error "SOURCE_DIR must be passed: makensis -DSOURCE_DIR=<bundle dir> ..."
!endif
!ifndef OUTFILE
  !define OUTFILE "carcal-setup.exe"
!endif

!define PRODUCT    "carcal"
!define PUBLISHER  "Sebastien Tricaud"
!define WEBSITE    "https://github.com/stricaud/carcal"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT}"
!define PROGID     "carcal.capture"

Name       "${PRODUCT} ${VERSION}"
OutFile    "${OUTFILE}"
InstallDir "$PROGRAMFILES64\${PRODUCT}"
InstallDirRegKey HKLM "Software\${PRODUCT}" "InstallDir"

; Program Files + HKLM + file associations all need elevation.
RequestExecutionLevel admin

VIProductVersion "${VERSION}.0"
VIAddVersionKey  "ProductName"     "${PRODUCT}"
VIAddVersionKey  "FileDescription" "carcal — a terminal packet analyzer"
VIAddVersionKey  "FileVersion"     "${VERSION}"
VIAddVersionKey  "ProductVersion"  "${VERSION}"
VIAddVersionKey  "CompanyName"     "${PUBLISHER}"
VIAddVersionKey  "LegalCopyright"  "MIT"

!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_TEXT "carcal was installed to $INSTDIR.$\r$\n$\r$\ncarcal is a terminal program: open it from the Start Menu, or run carcal.exe from a terminal with a capture file:$\r$\n$\r$\n    carcal.exe capture.pcapng$\r$\n$\r$\nLive capture is not available on Windows — open a file captured with Wireshark or dumpcap."
!define MUI_FINISHPAGE_LINK      "carcal on GitHub"
!define MUI_FINISHPAGE_LINK_LOCATION "${WEBSITE}"

!ifdef LICENSE_FILE
  !insertmacro MUI_PAGE_LICENSE "${LICENSE_FILE}"
!endif
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; ── Sections ────────────────────────────────────────────────────────────────

Section "carcal (required)" SecCore
  SectionIn RO
  SetOutPath "$INSTDIR"

  ; The whole bundle: carcal.exe, its DLLs, protos\, grammars\, scripts\.
  File /r "${SOURCE_DIR}\*.*"

  WriteRegStr HKLM "Software\${PRODUCT}" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "Software\${PRODUCT}" "Version"    "${VERSION}"

  ; Add/Remove Programs
  WriteRegStr   HKLM "${UNINST_KEY}" "DisplayName"     "${PRODUCT} ${VERSION}"
  WriteRegStr   HKLM "${UNINST_KEY}" "DisplayVersion"  "${VERSION}"
  WriteRegStr   HKLM "${UNINST_KEY}" "Publisher"       "${PUBLISHER}"
  WriteRegStr   HKLM "${UNINST_KEY}" "URLInfoAbout"    "${WEBSITE}"
  WriteRegStr   HKLM "${UNINST_KEY}" "DisplayIcon"     "$INSTDIR\carcal.exe"
  WriteRegStr   HKLM "${UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr   HKLM "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoRepair" 1

  WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

Section "Start Menu shortcut" SecStartMenu
  CreateDirectory "$SMPROGRAMS\${PRODUCT}"
  CreateShortCut  "$SMPROGRAMS\${PRODUCT}\carcal.lnk"      "$INSTDIR\carcal.exe"
  CreateShortCut  "$SMPROGRAMS\${PRODUCT}\Uninstall.lnk"   "$INSTDIR\uninstall.exe"
SectionEnd

; Off by default: most people analysing captures already have Wireshark
; associated with these extensions, and silently stealing them would be rude.
Section /o "Associate .pcap and .pcapng files" SecAssoc
  WriteRegStr HKLM "Software\Classes\${PROGID}" "" "Capture file"
  WriteRegStr HKLM "Software\Classes\${PROGID}\DefaultIcon" "" "$INSTDIR\carcal.exe,0"
  WriteRegStr HKLM "Software\Classes\${PROGID}\shell\open\command" "" '"$INSTDIR\carcal.exe" "%1"'
  WriteRegStr HKLM "Software\Classes\.pcap"   "" "${PROGID}"
  WriteRegStr HKLM "Software\Classes\.pcapng" "" "${PROGID}"
  System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0, i 0, i 0)'
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCore}      "carcal.exe and the protocol definitions it needs."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecStartMenu} "Add carcal to the Start Menu."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecAssoc}     "Open .pcap / .pcapng files with carcal by double-clicking. Leave unchecked to keep your current association (e.g. Wireshark)."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; ── Uninstall ───────────────────────────────────────────────────────────────

Section "Uninstall"
  Delete "$SMPROGRAMS\${PRODUCT}\carcal.lnk"
  Delete "$SMPROGRAMS\${PRODUCT}\Uninstall.lnk"
  RMDir  "$SMPROGRAMS\${PRODUCT}"

  ; Only give the extensions back if they still point at us — if the user has
  ; since reassociated them with Wireshark, leave that alone.
  ReadRegStr $0 HKLM "Software\Classes\.pcap" ""
  StrCmp $0 "${PROGID}" 0 +2
    DeleteRegKey HKLM "Software\Classes\.pcap"
  ReadRegStr $0 HKLM "Software\Classes\.pcapng" ""
  StrCmp $0 "${PROGID}" 0 +2
    DeleteRegKey HKLM "Software\Classes\.pcapng"
  DeleteRegKey HKLM "Software\Classes\${PROGID}"
  System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0, i 0, i 0)'

  DeleteRegKey HKLM "${UNINST_KEY}"
  DeleteRegKey HKLM "Software\${PRODUCT}"

  Delete "$INSTDIR\uninstall.exe"
  Delete "$INSTDIR\*.dll"
  Delete "$INSTDIR\carcal.exe"
  Delete "$INSTDIR\README.txt"
  RMDir /r "$INSTDIR\protos"
  RMDir /r "$INSTDIR\grammars"
  RMDir /r "$INSTDIR\scripts"
  RMDir "$INSTDIR"
SectionEnd
