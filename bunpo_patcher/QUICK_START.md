# 🚀 Quick Start Guide - Bunpo APK Patcher

## Langkah Cepat (5 Menit)

### 1. Persiapan

```bash
# Pastikan Java terinstall
java -version

# Jika belum ada:
# Ubuntu: sudo apt install openjdk-17-jdk
# Termux: pkg install openjdk-17
# Windows: Download dari oracle.com
```

### 2. Download APK & Script

```bash
# Clone atau download repository
cd /workspace/bunpo_patcher

# Download APK target (contoh)
wget https://github.com/cocoba88/tugaskuliah/releases/download/bunpo/Bunpo_3.8.0_apks.apk
```

### 3. Jalankan Script

```bash
# Versi Lite (recommended untuk device resource terbatas)
python3 bunpo_patcher_lite.py Bunpo_3.8.0_apks.apk

# Tunggu proses selesai (3-10 menit tergantung device)
```

### 4. Install Hasil Patch

```bash
# Output file: Bunpo_3.8.0_apks_patched-aligned-signed.apk

# Via ADB
adb install Bunpo_3.8.0_apks_patched-aligned-signed.apk

# Atau copy manual ke Android device
```

---

## 📊 Apa yang Dilakukan Script?

```
┌─────────────────────────────────────────────────────────┐
│  1. Auto Download Tools                                 │
│     ✓ apktool.jar (decompile)                           │
│     ✓ uber-apk-signer.jar (signing)                     │
├─────────────────────────────────────────────────────────┤
│  2. Decompile APK                                       │
│     ✓ Extract smali code                                │
│     ✓ Multi-dex support (classes2, classes3, ...)       │
├─────────────────────────────────────────────────────────┤
│  3. Pattern Analysis                                    │
│     ✓ Integer methods (energy, coin, counter)           │
│     ✓ Boolean methods (validation, access check)        │
│     ✓ SharedPreferences access                          │
│     ✓ Conditional branches                              │
│     ✓ Termination calls (finish, exit)                  │
│     ✓ License verification                              │
├─────────────────────────────────────────────────────────┤
│  4. Auto Patching                                       │
│     ✓ Force boolean → true                              │
│     ✓ Set integer → max value (99999)                   │
│     ✓ Remove termination calls                          │
├─────────────────────────────────────────────────────────┤
│  5. Rebuild & Sign                                      │
│     ✓ Compile kembali ke APK                            │
│     ✓ Sign dengan debug certificate                     │
│     ✓ Zipalign optimization                             │
└─────────────────────────────────────────────────────────┘
```

---

## 🎯 Pola Detection (Anti-Obfuscation)

Script tidak bergantung pada nama class/method, tetapi menggunakan:

| Pattern | Return Type | Target |
|---------|-------------|--------|
| `.method...)I` | Integer | Energy, coin, limit, counter |
| `.method...)Z` | Boolean | isValid(), canAccess(), isUnlocked() |
| `if-eqz`, `if-nez` | N/A | Conditional logic |
| `finish()V`, `exit()` | N/A | App termination |
| `SharedPreferences` | N/A | Data storage |

**Keywords Detection:**
- `check`, `valid`, `verify`, `license`, `auth`
- `energy`, `coin`, `gem`, `gold`, `score`
- `unlock`, `premium`, `vip`, `access`

---

## 🔧 Troubleshooting Cepat

### ❌ "No space left on device"

```bash
# Bersihkan space
rm -rf /tmp/bunpo_patch_*
df -h

# Gunakan external storage
cd /sdcard
python3 /workspace/bunpo_patcher/bunpo_patcher_lite.py app.apk
```

### ❌ "Java not found"

```bash
# Install Java
sudo apt update && sudo apt install openjdk-17-jdk  # Ubuntu
pkg install openjdk-17                               # Termux
```

### ❌ "Decompile failed"

```bash
# Coba dengan --no-debug-info
java -jar tools/apktool.jar d app.apk -o output --no-debug-info
```

### ❌ "APK crashes after install"

1. Uninstall versi original dulu
2. Clear data app
3. Install APK patched
4. Jika masih crash, patch terlalu agresif - edit manual

---

## 📁 Struktur Output

```
bunpo_patcher/
├── bunpo_patcher.py           # Full version (1089 baris)
├── bunpo_patcher_lite.py      # Lite version (744 baris) ⭐
├── README.md                  # Dokumentasi lengkap
├── QUICK_START.md             # Panduan ini
├── tools/
│   ├── apktool.jar            # Auto-downloaded
│   └── uber-apk-signer.jar    # Auto-downloaded
└── <app>_patched-aligned-signed.apk  # HASIL AKHIR
```

---

## 💡 Tips Pro

1. **Backup dulu!**
   ```bash
   cp app.apk app_backup.apk
   ```

2. **Test bertahap**
   - Patch satu fitur dulu
   - Test di emulator/device
   - Lanjut patch lain jika stabil

3. **Manual inspection**
   ```bash
   # Lihat hasil decompile
   ls -la smali_output/smali*/com/pairip/
   
   # Grep pattern spesifik
   grep -r "isValid" smali_output/ | head -20
   ```

4. **Debug mode**
   ```bash
   # Enable verbose logging
   python3 bunpo_patcher_lite.py app.apk --verbose
   ```

---

## 📞 Support

Jika ada masalah:
1. Cek log output lengkap
2. Screenshot error message
3. Informasi device/Android version
4. Nama APK dan versi

---

**Happy Reverse Engineering! 🎓**

*Disclaimer: Hanya untuk tujuan pembelajaran!*
