# Bunpo APK Patcher - Panduan Lengkap

## 📋 Deskripsi

Tool otomatis untuk reverse engineering dan patching APK Android dengan pendekatan **pattern-based** yang adaptif terhadap obfuscation.

### Versi Script

| Script | Ukuran | Fitur | Penggunaan |
|--------|--------|-------|------------|
| `bunpo_patcher.py` | 1089 baris | Full analysis, comprehensive patching | Untuk analisis mendalam |
| `bunpo_patcher_lite.py` | 744 baris | Lightweight, resource-efficient | Untuk device dengan resource terbatas |

### Fitur Utama

- ✅ **Auto Download Dependencies** - apktool & uber-apk-signer
- ✅ **Pattern-Based Analysis** - Tidak bergantung nama class/method
- ✅ **Multi-Dex Support** - smali_classes2, smali_classes3, dst
- ✅ **Auto Patching** - Boolean, integer, conditional branches
- ✅ **Auto Rebuild & Sign** - Siap install
- ✅ **Cross-Platform** - Windows, Linux, Termux

---

## 🚀 Cara Penggunaan

### Prerequisites

1. **Java JDK** harus terinstall
   ```bash
   # Cek Java
   java -version
   
   # Jika belum ada, download dari:
   # https://www.oracle.com/java/technologies/downloads/
   ```

2. **Python 3.x** (sudah include urllib standard library)

### Langkah-Langkah

#### 1. Download APK Target

```bash
# Contoh: Download Bunpo APK
wget https://github.com/cocoba88/tugaskuliah/releases/download/bunpo/Bunpo_3.8.0_apks.apk
```

#### 2. Jalankan Script

```bash
# Linux / Termux - Versi Lite (recommended untuk resource terbatas)
python3 bunpo_patcher_lite.py Bunpo_3.8.0_apks.apk

# Linux / Termux - Versi Full (analisis lebih mendalam)
python3 bunpo_patcher.py Bunpo_3.8.0_apks.apk

# Windows - Versi Lite
python bunpo_patcher_lite.py Bunpo_3.8.0_apks.apk

# Windows - Versi Full
python bunpo_patcher.py Bunpo_3.8.0_apks.apk
```

#### 3. Install APK Hasil Patch

```bash
# Copy ke Android device
adb install Bunpo_3.8.0_apks_patched-aligned-signed.apk

# Atau transfer manual ke device
```

---

## 🔍 Struktur Script

### 1. SmaliAnalyzer

Mencari pattern penting tanpa bergantung nama:

| Pattern | Return Type | Deskripsi |
|---------|-------------|-----------|
| Integer Methods | `)I` | Energy, coin, counter, limit |
| Boolean Methods | `)Z` | Validasi akses, unlock status |
| SharedPreferences | N/A | Penyimpanan data lokal |
| Conditional Branches | `if-*` | Logika percabangan |
| Termination Calls | `finish()`, `exit()` | Penutupan app |
| License Checks | Keywords | Verifikasi lisensi |

### 2. SmaliPatcher

Metode patching otomatis:

```python
# Force boolean true
patch_boolean_method(file, pattern, return_value=True)

# Set integer max
patch_integer_method(file, pattern, new_value=99999)

# Invert condition
patch_conditional_branch(file, pattern, invert=True)

# Remove termination
patch_termination_call(file, pattern)
```

---

## 📝 Contoh Patch Manual

### 1. Force Boolean True

**Original:**
```smali
.method public isFeatureUnlocked()Z
    .locals 2
    
    iget-object v0, p0, Lcom/example/App;->prefs:Landroid/content/SharedPreferences;
    const-string v1, "unlocked"
    invoke-interface {v0, v1}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z
    
    move-result v0
    return v0
.end method
```

**Patched:**
```smali
.method public isFeatureUnlocked()Z
    .locals 1
    
    const/4 v0, 0x1
    
    return v0
.end method
```

### 2. Set Integer Max Value

**Original:**
```smali
.method public getEnergy()I
    .locals 1
    
    iget v0, p0, Lcom/example/User;->energy:I
    
    return v0
.end method
```

**Patched:**
```smali
.method public getEnergy()I
    .locals 1
    
    const v0, 99999
    
    return v0
.end method
```

### 3. Bypass Conditional Check

**Original:**
```smali
invoke-virtual {p0}, Lcom/example/License;->isValid()Z

move-result v0

if-eqz v0, :cond_fail  # Jika false, jump ke fail

# ... code untuk fitur unlocked ...

:cond_fail
invoke-virtual {p0}, Lcom/example/App;->showError()V
return-void
```

**Patched (Invert):**
```smali
invoke-virtual {p0}, Lcom/example/License;->isValid()Z

move-result v0

if-nez v0, :cond_fail  # Diblik: jika true, jump (skip error)

# ... code untuk fitur unlocked ...

:cond_fail
invoke-virtual {p0}, Lcom/example/App;->showError()V
return-void
```

**Atau Remove Completely:**
```smali
invoke-virtual {p0}, Lcom/example/License;->isValid()Z

move-result v0

nop  # Conditional dihapus

# ... code untuk fitur unlocked ...
```

### 4. Disable Finish/Exit Call

**Original:**
```smali
.method public onLicenseInvalid()V
    .locals 1
    
    const-string v0, "License invalid!"
    invoke-static {v0}, Landroid/widget/Toast;->makeText(...)V
    
    invoke-virtual {p0}, Lcom/example/MainActivity;->finish()V
    
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;
    const/4 v0, 0x0
    invoke-virtual {v0, v0}, Ljava/lang/Runtime;->exit(I)V
.end method
```

**Patched:**
```smali
.method public onLicenseInvalid()V
    .locals 0
    
    return-void
.end method
```

---

## 🎯 Pola Detection Prioritas

### Critical Priority (Patch Pertama)

1. **Boolean methods yang return false langsung**
   ```smali
   .method checkLicense()Z
       const/4 v0, 0x0
       return v0
   .end method
   ```

2. **Methods dengan keywords: verify, validate, check, license**
   ```smali
   .method verifySignature()Z
   .method validateUser()Z
   .method checkLicense()Z
   ```

3. **Termination calls setelah conditional**
   ```smali
   if-eqz v0, :fail
   ...
   :fail
   invoke-virtual {p0}, finish()V
   ```

### High Priority

1. **Simple getters dengan konstanta**
   ```smali
   .method getMaxEnergy()I
       const v0, 50
       return v0
   .end method
   ```

2. **SharedPreferences getInt/getBoolean**
   ```smali
   invoke-interface {prefs, key, default}, getInt()I
   ```

### Medium Priority

1. **Conditional branches kompleks**
2. **Method dengan perhitungan**

---

## 🛠️ Troubleshooting

### Error: Java tidak ditemukan

```bash
# Install Java
# Ubuntu/Debian
sudo apt install openjdk-17-jdk

# Windows
# Download dari oracle.com

# Termux
pkg install openjdk-17
```

### Error: Download gagal

Script akan retry 3x otomatis. Jika masih gagal:

```bash
# Download manual
cd tools/
wget https://github.com/iBotPeaches/Apktool/releases/download/v3.0.1/apktool_3.0.1.jar
wget https://github.com/patrickfav/uber-apk-signer/releases/download/v1.3.0/uber-apk-signer-1.3.0.jar
```

### Error: Rebuild gagal

Biasanya karena syntax smali salah. Cek:

```bash
# Lihat log error
cat bunpo_patcher.log

# Coba rebuild manual
java -jar tools/apktool.jar b smali_output -o output.apk
```

### APK crash setelah install

1. Backup data dulu sebelum install
2. Beberapa patch mungkin terlalu agresif
3. Coba patch selective (hanya target tertentu)

---

## 📂 Output Files

Setelah proses selesai:

```
bunpo_patcher/
├── bunpo_patcher.py          # Main script
├── tools/
│   ├── apktool.jar           # Decompile tool
│   └── uber-apk-signer.jar   # Signing tool
├── README.md                 # Dokumentasi ini
└── <nama_apk>_patched-aligned-signed.apk  # Hasil
```

---

## ⚠️ Disclaimer

**HANYA UNTUK TUJUAN PEMBELAJARAN!**

- Gunakan hanya pada APK yang Anda miliki
- Jangan distribusikan APK hasil patch
- Reverse engineering untuk educational purpose
- Penulis tidak bertanggung jawab atas penyalahgunaan

---

## 📚 Referensi

- [Apktool Documentation](https://ibotpeaches.github.io/Apktool/)
- [Smali/Baksmali](https://github.com/JesusFreke/smali)
- [Android Reverse Engineering](https://github.com/mstgszrca/awesome-android-reverse-engineering)
- [Uber APK Signer](https://github.com/patrickfav/uber-apk-signer)

---

## 🎓 Learning Path

Untuk memahami lebih dalam:

1. **Dasar Smali**
   - Register (v0, v1, p0, p1)
   - Instruction (const, move, invoke, return)
   - Control flow (if-*, goto, label)

2. **Analisis APK**
   - Decompile dengan apktool
   - Identifikasi entry point (AndroidManifest.xml)
   - Trace alur eksekusi

3. **Patching**
   - Modifikasi kecil dulu
   - Test setiap perubahan
   - Backup sebelum patch

4. **Advanced**
   - Native library (JNI)
   - String encryption
   - Anti-debugging techniques

---

**Happy Learning! 🚀**
