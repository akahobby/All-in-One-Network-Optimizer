# NetOpt – Network Optimizer

NetOpt is a Windows batch-based tool that applies proven TCP, NIC, and registry tweaks to improve network performance.  
It supports both Ethernet and Wi-Fi adapters, with a menu-driven interface and built-in safety toggles.

---

## ✨ Features
- **TCP Autotuning Control**
  - Disable, enable, or set to `highlyrestricted` (keeps speed but may not be as responsive as disabled)
- **TCP Congestion Providers**
  - **BBR2** (best performance on Win 11 24H2+), **CUBIC** (default), **NewReno** (testing)
- **NIC Optimization**
  - Disables unnecessary protocols and offloads
  - Adjusts power management settings
- **Registry Tweaks**
  - `FastSendDatagramThreshold=409600`
  - RSS buffers, flow control, interrupt moderation
- Works on **any PC** with administrator rights

---

## 📥 Installation & Usage
1. **Download** the latest ZIP from the [Releases](https://github.com/akahobby/All-in-One-Network-Optimizer/releases) page.
2. **Extract** it to a folder on your PC.
3. **Right-click** the `.bat` file and choose **Run as administrator**.
4. Follow the menu prompts to apply optimizations.

---

## ⚠️ Notes
- Always create a restore point before making major changes.
- Some optimizations may require a reboot.
- The script logs changes so you can review what was applied.

---

**Developer:** hobby  
**Contact:** Add `@akahobby` on Discord for bugs or fixes.
