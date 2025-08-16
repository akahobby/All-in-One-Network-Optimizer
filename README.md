# NetOpt – Network Optimizer

NetOpt is a Windows batch-based tool that applies proven TCP, NIC, and registry tweaks to improve network performance.  
It supports both Ethernet and Wi-Fi adapters and now features a classic dark-room UI and self-elevating launcher.

---

## ✨ Features
- **TCP Congestion Providers**
  - **BBR2** (best on Win 11 24H2+), **CUBIC** (default), **NewReno** (testing)
  - One-shot switch across `internet`, `internetcustom`, `datacenter`, `datacentercustom`, `compat`
  - Green `[+]` confirmations, dark-gray read-back, and a manual `netsh` block
  - Loopback Large MTU auto-toggle (**disabled** when selecting BBR2)
- **TCP Autotuning Control**
  - `disabled`, `highlyrestricted`, or `normal`
- **NIC Optimization**
  - Cross-vendor tweaks (offloads, metrics, power) + vendor modes: **Auto**, **Intel**, **Realtek**, or **Skip**
  - RX/TX buffers maximized **when exposed**; if not, NetOpt applies non-buffer tweaks and logs it clearly
  - Per-adapter and combined backups with restore
- **Registry Tweaks**
  - `FastSendDatagramThreshold = 409600` (AFD)
  - Safe TCP globals (e.g., RSS on, RSC off, timestamps off)
- **UI & Safety**
  - Dark-friendly colors (cyan headers, **yellow** prompts, **green** confirmations, **dark-gray** read-backs)
  - **Single Y/N** prompt for NIC tweaks during **Apply All**
  - Self-elevating `.bat` (UAC prompt shown on double-click)

---

## 📥 Installation & Usage
1. **Download** the latest ZIP from the [Releases](https://github.com/akahobby/All-in-One-Network-Optimizer/releases) page.  
2. **Extract** it to a folder on your PC.  
3. **Double-click** `network-optimizer-master.bat` (click **Yes** on the UAC prompt).  
4. Follow the menu flow:  
   **Congestion Provider → read-back → manual commands tip → Auto-Tuning → SAFE apply → NIC tweaks (Y/N).**

---

## ⚠️ Notes
- Backups are saved to `C:\ProgramData\NetOpt\Backups\` (paths printed in dark-gray).
- Some Windows builds lock `compat → newreno` or enforce provider choices; read-back reflects OS policy.
- Some changes may require a reboot.
- The script logs what changed so you can review results.
- Test results with the [Waveform Bufferbloat Test](https://www.waveform.com/tools/bufferbloat).

---

**Developer:** hobby  
**Contact:** Add `@akahobby` on Discord for bugs or fixes.
