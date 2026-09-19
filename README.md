# UURemoteTrayIconHider
Hide UU Remote (NetEase GameViewer) system-tray icon at boot - no explorer restart needed.

```
How it works:
  The script takes over GameViewer's autostart entry, launches the app itself,
  then patches Shell_NotifyIconW in the target process: the IAT slot for that
  API is redirected to a tiny stub (mov eax, 1; ret), so every call reports
  success without ever registering a tray icon. Polling every 20 ms with a
  pre-cached IAT map wins the race against the app's own registration, so the
  icon never appears at all - in the taskbar or in the overflow menu.

Autostart: put a shortcut of this script in the shell:startup folder with target:
  powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "<this file>"

Restore: 1) remove the startup-folder shortcut
         2) re-enable autostart inside the UU Remote app settings (or restore the
            backed-up value at HKCU\Software\HideUUTray\GameViewerAutostart into
            HKCU\Software\Microsoft\Windows\CurrentVersion\Run\GameViewer)
         3) reboot. The patch lives only in memory; nothing persists.
```
