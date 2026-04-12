#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bunpo APK Patcher - LITE VERSION (Optimized for Limited Resources)
Untuk tujuan pembelajaran reverse engineering dan debugging

Fitur:
- Auto download dependency (apktool, uber-apk-signer)
- Pattern-based analysis (tidak bergantung nama class/method)
- Multi-dex support dengan resource management
- Cross-platform (Windows, Linux, Termux)
- Auto decompile, patch, rebuild, sign
- Optimized untuk disk space terbatas

Author: Educational Purpose Only
"""

import os
import sys
import re
import shutil
import subprocess
import urllib.request
import hashlib
import tempfile
import time
from pathlib import Path

# ============================================================================
# KONFIGURASI
# ============================================================================

APKTOOL_URL = "https://github.com/iBotPeaches/Apktool/releases/download/v3.0.1/apktool_3.0.1.jar"
APKTOOL_NAME = "apktool.jar"

UBER_SIGNER_URL = "https://github.com/patrickfav/uber-apk-signer/releases/download/v1.3.0/uber-apk-signer-1.3.0.jar"
UBER_SIGNER_NAME = "uber-apk-signer.jar"

TOOLS_DIR = None
SCRIPT_DIR = None

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_script_dir():
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).parent
    return Path(__file__).parent.resolve()

def get_tools_dir():
    global TOOLS_DIR
    if TOOLS_DIR is None:
        TOOLS_DIR = SCRIPT_DIR / "tools"
        TOOLS_DIR.mkdir(exist_ok=True)
    return TOOLS_DIR

def log_info(msg):
    print(f"[INFO] {msg}")

def log_error(msg):
    print(f"[ERROR] {msg}", file=sys.stderr)

def log_success(msg):
    print(f"[SUCCESS] {msg}")

def log_warning(msg):
    print(f"[WARNING] {msg}")

def check_java():
    try:
        result = subprocess.run(
            ["java", "-version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            version_line = result.stderr.split('\n')[0] if result.stderr else result.stdout.split('\n')[0]
            log_info(f"Java ditemukan: {version_line}")
            return True
    except FileNotFoundError:
        log_error("Java tidak ditemukan! Silakan install JDK terlebih dahulu.")
        log_error("Download: https://www.oracle.com/java/technologies/downloads/")
    except Exception as e:
        log_error(f"Error cek Java: {e}")
    return False

def download_file(url, dest_path, max_retries=3):
    for attempt in range(max_retries):
        try:
            log_info(f"Downloading dari {url}...")
            
            req = urllib.request.Request(
                url,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            
            with urllib.request.urlopen(req, timeout=60) as response:
                total_size = int(response.getheader('Content-Length', 0))
                downloaded = 0
                
                with open(dest_path, 'wb') as f:
                    chunk_size = 8192
                    while True:
                        chunk = response.read(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded += len(chunk)
                        
                        if total_size > 0:
                            progress = (downloaded / total_size) * 100
                            print(f"\r  Progress: {progress:.1f}%", end='', flush=True)
                    
                    print()
            
            file_size = dest_path.stat().st_size
            if file_size < 1000:
                log_warning(f"File terlalu kecil ({file_size:,} bytes), mungkin download gagal")
                dest_path.unlink()
                continue
                
            log_success(f"Download selesai: {dest_path.name} ({file_size:,} bytes)")
            return True
            
        except Exception as e:
            log_warning(f"Download gagal (attempt {attempt + 1}/{max_retries}): {e}")
            if dest_path.exists():
                dest_path.unlink()
            time.sleep(2)
    
    log_error(f"Gagal download setelah {max_retries} percobaan")
    return False

def ensure_tool(name, url, jar_name=None):
    tools_dir = get_tools_dir()
    
    if jar_name is None:
        jar_name = name
    
    jar_path = tools_dir / jar_name
    
    if jar_path.exists() and jar_path.stat().st_size > 1000:
        log_info(f"{name} sudah ada: {jar_path.name}")
        return jar_path
    
    log_info(f"{name} tidak ditemukan, akan diunduh...")
    
    if download_file(url, jar_path):
        return jar_path
    
    return None

# ============================================================================
# SMALI ANALYZER - PATTERN BASED
# ============================================================================

class SmaliAnalyzer:
    def __init__(self, smali_dir):
        self.smali_dir = Path(smali_dir)
        self.results = {
            'integer_methods': [],
            'boolean_methods': [],
            'shared_preferences': [],
            'conditional_branches': [],
            'termination_calls': [],
            'initialization_methods': [],
            'getter_setter': [],
            'license_checks': [],
            'activity_redirects': []
        }
        
    def discover_smali_files(self, limit=None):
        """Temukan file smali dengan limit untuk hemat memory"""
        log_info("Mencari file smali...")
        
        all_files = []
        for pattern in ['smali*/**/*.smali']:
            try:
                files = list(self.smali_dir.glob(pattern))
                all_files.extend(files)
            except Exception as e:
                log_warning(f"Error scanning: {e}")
        
        log_info(f"Ditemukan {len(all_files)} file smali")
        
        if limit:
            all_files = all_files[:limit]
            log_info(f"Dibatasi ke {limit} file untuk analisis")
        
        return all_files
    
    def analyze_patterns(self, file_path):
        """Analisis pola dalam satu file smali"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            return
        
        lines = content.split('\n')
        current_method = None
        method_lines = []
        in_method = False
        
        for i, line in enumerate(lines):
            stripped = line.strip()
            
            # Deteksi method
            if stripped.startswith('.method'):
                in_method = True
                current_method = stripped
                method_lines = [line]
                
                # Cek return type
                if ')I' in stripped and '->' in stripped:
                    self._check_integer_method(file_path, stripped, lines[i:i+30])
                elif ')Z' in stripped and '->' in stripped:
                    self._check_boolean_method(file_path, stripped, lines[i:i+30])
            
            elif in_method:
                method_lines.append(line)
                
                # Cek pola penting
                self._check_pattern_line(file_path, current_method, line)
                
                if stripped.startswith('.end method'):
                    in_method = False
                    
                    # Cek initialization
                    if self._is_init_method(method_lines):
                        self.results['initialization_methods'].append({
                            'file': str(file_path),
                            'method': current_method,
                            'line': i
                        })
    
    def _check_integer_method(self, file_path, method_decl, context):
        match = re.search(r'->([^\(]+)\(', method_decl)
        method_name = match.group(1) if match else 'unknown'
        
        is_simple = False
        has_const = False
        const_value = None
        
        for line in context[:20]:
            if 'iget' in line or 'sget' in line:
                is_simple = True
            if 'const' in line and ('v0' in line or 'return' in line):
                has_const = True
                const_match = re.search(r'const.*v0,\s*(-?\d+)', line)
                if const_match:
                    const_value = int(const_match.group(1))
        
        priority = 'low'
        if is_simple:
            priority = 'high'
        elif has_const:
            priority = 'medium'
        
        # Filter nama method yang mencurigakan
        suspicious_keywords = ['energy', 'coin', 'gem', 'gold', 'score', 'point', 
                              'count', 'limit', 'max', 'level', 'exp', 'money']
        
        method_lower = method_name.lower()
        is_suspicious = any(kw in method_lower for kw in suspicious_keywords)
        
        if priority == 'high' or is_suspicious or (has_const and const_value and const_value > 0):
            self.results['integer_methods'].append({
                'file': str(file_path),
                'method': method_decl,
                'priority': 'high' if is_suspicious else priority,
                'const_value': const_value,
                'is_suspicious': is_suspicious
            })
    
    def _check_boolean_method(self, file_path, method_decl, context):
        match = re.search(r'->([^\(]+)\(', method_decl)
        method_name = match.group(1) if match else 'unknown'
        
        returns_true = False
        returns_false = False
        has_check = False
        
        for line in context[:20]:
            if 'const/4 v0, 0x1' in line or 'const/4 v0, 0x0' in line:
                returns_true = '0x1' in line
                returns_false = '0x0' in line
            if 'if-' in line or 'cmp' in line:
                has_check = True
        
        # Keywords untuk validasi
        validation_keywords = ['check', 'valid', 'verify', 'is', 'can', 'has', 
                              'allow', 'enable', 'unlock', 'premium', 'vip',
                              'license', 'auth', 'permission', 'access']
        
        method_lower = method_name.lower()
        is_validation = any(kw in method_lower for kw in validation_keywords)
        
        if is_validation or has_check or returns_true or returns_false:
            self.results['boolean_methods'].append({
                'file': str(file_path),
                'method': method_decl,
                'returns_true': returns_true,
                'returns_false': returns_false,
                'has_check': has_check,
                'is_validation': is_validation
            })
    
    def _check_pattern_line(self, file_path, method, line):
        # SharedPreferences
        if 'SharedPreferences' in line or 'getSharedPreferences' in line:
            entry = {'file': str(file_path), 'method': method, 'line': line.strip()}
            if entry not in self.results['shared_preferences']:
                self.results['shared_preferences'].append(entry)
        
        # Conditional branches
        if re.search(r'if-\w+z?\s+v\d+', line):
            self.results['conditional_branches'].append({
                'file': str(file_path),
                'method': method,
                'instruction': line.strip()
            })
        
        # Termination calls
        if 'invoke-virtual' in line and ('finish()V' in line or 'exit(' in line):
            self.results['termination_calls'].append({
                'file': str(file_path),
                'method': method,
                'instruction': line.strip()
            })
        
        # License/Validation keywords
        license_keywords = ['license', 'validate', 'verify', 'check', 'auth']
        if any(kw in line.lower() for kw in license_keywords):
            self.results['license_checks'].append({
                'file': str(file_path),
                'method': method,
                'line': line.strip()
            })
        
        # Activity redirects
        if 'startActivity' in line or 'Intent' in line:
            self.results['activity_redirects'].append({
                'file': str(file_path),
                'method': method,
                'instruction': line.strip()
            })
    
    def _is_init_method(self, method_lines):
        content = '\n'.join(method_lines)
        init_patterns = ['.method.*<init>', '.method.*onCreate', '.method.*attachBaseContext']
        return any(re.search(p, content) for p in init_patterns)
    
    def get_top_targets(self, n=20):
        """Dapatkan target prioritas tinggi"""
        targets = []
        
        # Integer methods dengan prioritas high
        for m in self.results['integer_methods']:
            if m.get('priority') == 'high' or m.get('is_suspicious'):
                targets.append(('INTEGER', m))
        
        # Boolean validation methods
        for m in self.results['boolean_methods']:
            if m.get('is_validation'):
                targets.append(('BOOLEAN', m))
        
        return targets[:n]

# ============================================================================
# PATCHER
# ============================================================================

class SmaliPatcher:
    def __init__(self, smali_dir):
        self.smali_dir = Path(smali_dir)
        self.patched_count = 0
    
    def patch_boolean_method(self, file_path, method_decl):
        """Patch method boolean untuk selalu return true"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            log_error(f"Error reading {file_path}: {e}")
            return False
        
        # Ekstrak method name
        match = re.search(r'->([^\(]+)\(\)', method_decl)
        if not match:
            return False
        
        method_name = match.group(1)
        
        # Cari method body
        method_pattern = re.escape(method_decl)
        method_match = re.search(f'{method_pattern}.*?\\.end method', content, re.DOTALL)
        
        if not method_match:
            return False
        
        old_method = method_match.group(0)
        
        # Buat new method yang return true
        new_method = f"""{method_decl}
    const/4 v0, 0x1
    return v0
.end method"""
        
        new_content = content.replace(old_method, new_method)
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            self.patched_count += 1
            log_success(f"Patched boolean method: {method_name}")
            return True
        except Exception as e:
            log_error(f"Error writing {file_path}: {e}")
            return False
    
    def patch_integer_method(self, file_path, method_decl, value=99999):
        """Patch method integer untuk return nilai tetap"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            log_error(f"Error reading {file_path}: {e}")
            return False
        
        match = re.search(r'->([^\(]+)\(\)', method_decl)
        if not match:
            return False
        
        method_name = match.group(1)
        
        method_pattern = re.escape(method_decl)
        method_match = re.search(f'{method_pattern}.*?\\.end method', content, re.DOTALL)
        
        if not method_match:
            return False
        
        old_method = method_match.group(0)
        
        new_method = f"""{method_decl}
    const v0, {value}
    return v0
.end method"""
        
        new_content = content.replace(old_method, new_method)
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            self.patched_count += 1
            log_success(f"Patched integer method: {method_name} -> {value}")
            return True
        except Exception as e:
            log_error(f"Error writing {file_path}: {e}")
            return False

# ============================================================================
# MAIN PATCHER CLASS
# ============================================================================

class BunpoPatcherLite:
    def __init__(self, apk_path):
        self.apk_path = Path(apk_path).resolve()
        self.work_dir = Path(tempfile.mkdtemp(prefix='bunpo_patch_'))
        self.output_apk = self.apk_path.parent / f"{self.apk_path.stem}_patched.apk"
        self.smali_dir = self.work_dir / "smali_output"
        
    def cleanup(self):
        log_info("Cleaning up...")
        try:
            shutil.rmtree(self.work_dir, ignore_errors=True)
        except Exception as e:
            log_warning(f"Cleanup error: {e}")
    
    def run(self):
        log_info(f"Work directory: {self.work_dir}")
        log_info(f"Output APK: {self.output_apk}")
        
        print("\n" + "="*70)
        print("BUNPO APK PATCHER - LITE VERSION")
        print("="*70)
        
        # Check Java
        if not check_java():
            self.cleanup()
            return False
        
        # Download tools
        apktool_jar = ensure_tool("apktool", APKTOOL_URL, APKTOOL_NAME)
        if not apktool_jar:
            log_error("Gagal mendapatkan apktool")
            self.cleanup()
            return False
        
        signer_jar = ensure_tool("uber-apk-signer", UBER_SIGNER_URL, UBER_SIGNER_NAME)
        if not signer_jar:
            log_error("Gagal mendapatkan uber-apk-signer")
            self.cleanup()
            return False
        
        # Decompile
        log_info("Memulai decompile APK...")
        decompile_cmd = [
            "java", "-jar", str(apktool_jar),
            "d", str(self.apk_path),
            "-o", str(self.smali_dir),
            "-f", "-r"
        ]
        
        try:
            result = subprocess.run(
                decompile_cmd,
                capture_output=True,
                text=True,
                timeout=600
            )
            
            if result.returncode != 0:
                log_error(f"Decompile gagal!\n{result.stderr[-500:]}")
                self.cleanup()
                return False
            
            log_success("Decompile berhasil!")
            
        except subprocess.TimeoutExpired:
            log_error("Decompile timeout!")
            self.cleanup()
            return False
        except Exception as e:
            log_error(f"Decompile error: {e}")
            self.cleanup()
            return False
        
        # Analyze
        log_info("Menganalisis smali files...")
        analyzer = SmaliAnalyzer(self.smali_dir)
        
        # Dapatkan file smali (limit untuk hemat memory)
        smali_files = analyzer.discover_smali_files(limit=500)
        
        # Analisis file penting dulu
        priority_packages = [
            'com/pairip', 'Ld/', 'Lu2/', 'Lp1/', 'Lq2/',
            'license', 'check', 'valid', 'auth'
        ]
        
        priority_files = []
        other_files = []
        
        for f in smali_files:
            path_str = str(f).lower()
            if any(pkg in path_str for pkg in priority_packages):
                priority_files.append(f)
            else:
                other_files.append(f)
        
        # Analisis priority files dulu
        log_info(f"Menganalisis {len(priority_files)} file prioritas...")
        for f in priority_files[:200]:
            analyzer.analyze_patterns(f)
        
        # Analisis file lain jika masih ada space
        if len(other_files) > 0:
            log_info(f"Menganalisis {min(100, len(other_files))} file tambahan...")
            for f in other_files[:100]:
                analyzer.analyze_patterns(f)
        
        # Tampilkan hasil
        print("\n" + "="*70)
        print("HASIL ANALISIS")
        print("="*70)
        print(f"Integer methods: {len(analyzer.results['integer_methods'])}")
        print(f"Boolean methods: {len(analyzer.results['boolean_methods'])}")
        print(f"SharedPreferences: {len(analyzer.results['shared_preferences'])}")
        print(f"Conditional branches: {len(analyzer.results['conditional_branches'])}")
        print(f"Termination calls: {len(analyzer.results['termination_calls'])}")
        print(f"License checks: {len(analyzer.results['license_checks'])}")
        
        # Dapatkan top targets
        top_targets = analyzer.get_top_targets(n=30)
        
        if top_targets:
            print("\n" + "-"*70)
            print("TOP TARGETS UNTUK PATCHING:")
            print("-"*70)
            for i, (type_, target) in enumerate(top_targets[:15], 1):
                method_name = re.search(r'->([^\(]+)\(', target.get('method', ''))
                name = method_name.group(1) if method_name else 'unknown'
                print(f"{i}. [{type_}] {name}")
                print(f"   File: {target.get('file', '')[-60:]}")
        
        # Patching
        print("\n" + "="*70)
        print("MEMULAI PATCHING")
        print("="*70)
        
        patcher = SmaliPatcher(self.smali_dir)
        patched = 0
        
        # Patch boolean validation methods
        for type_, target in top_targets:
            if type_ == 'BOOLEAN' and target.get('is_validation'):
                if patcher.patch_boolean_method(
                    target['file'],
                    target['method']
                ):
                    patched += 1
                    if patched >= 5:  # Limit patching
                        break
        
        # Patch integer methods
        int_patched = 0
        for m in analyzer.results['integer_methods']:
            if m.get('priority') == 'high' or m.get('is_suspicious'):
                if patcher.patch_integer_method(m['file'], m['method'], 99999):
                    int_patched += 1
                    if int_patched >= 3:
                        break
        
        log_success(f"Total patches applied: {patched + int_patched}")
        
        # Rebuild
        log_info("Rebuilding APK...")
        rebuild_cmd = [
            "java", "-jar", str(apktool_jar),
            "b", str(self.smali_dir),
            "-o", str(self.output_apk),
            "-f"
        ]
        
        try:
            result = subprocess.run(
                rebuild_cmd,
                capture_output=True,
                text=True,
                timeout=600
            )
            
            if result.returncode != 0:
                log_error(f"Rebuild gagal!\n{result.stderr[-500:]}")
                self.cleanup()
                return False
            
            log_success("Rebuild berhasil!")
            
        except Exception as e:
            log_error(f"Rebuild error: {e}")
            self.cleanup()
            return False
        
        # Sign
        log_info("Signing APK...")
        sign_cmd = [
            "java", "-jar", str(signer_jar),
            "--apks", str(self.output_apk)
        ]
        
        try:
            result = subprocess.run(
                sign_cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode != 0:
                log_warning(f"Signing warning: {result.stderr[-200:]}")
            else:
                log_success("Signing berhasil!")
            
        except Exception as e:
            log_warning(f"Signing error: {e}")
        
        # Cleanup
        self.cleanup()
        
        # Final output
        print("\n" + "="*70)
        print("SELESAI!")
        print("="*70)
        
        if self.output_apk.exists():
            size_mb = self.output_apk.stat().st_size / (1024 * 1024)
            log_success(f"APK patched tersedia: {self.output_apk}")
            log_success(f"Ukuran: {size_mb:.2f} MB")
            
            # Check aligned version
            aligned_apk = self.output_apk.parent / f"{self.output_apk.stem}-aligned.apk"
            if aligned_apk.exists():
                log_success(f"APK aligned: {aligned_apk}")
            
            return True
        else:
            log_error("APK output tidak ditemukan!")
            return False

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    global SCRIPT_DIR
    
    SCRIPT_DIR = get_script_dir()
    
    print("\n" + "="*70)
    print("  BUNPO APK PATCHER LITE v1.0")
    print("  Reverse Engineering Tool untuk Tujuan Pembelajaran")
    print("="*70 + "\n")
    
    if len(sys.argv) < 2:
        print("Usage: python bunpo_patcher_lite.py <path_to_apk>")
        print("\nExample:")
        print("  python bunpo_patcher_lite.py Bunpo_3.8.0.apk")
        print("\nFeatures:")
        print("  ✓ Auto download dependencies")
        print("  ✓ Pattern-based analysis (anti-obfuscation)")
        print("  ✓ Resource-efficient (optimized for limited disk)")
        print("  ✓ Auto patching (boolean, integer)")
        print("  ✓ Auto rebuild & sign")
        print("  ✓ Cross-platform (Windows, Linux, Termux)")
        sys.exit(1)
    
    apk_path = Path(sys.argv[1])
    
    if not apk_path.exists():
        log_error(f"File APK tidak ditemukan: {apk_path}")
        sys.exit(1)
    
    patcher = BunpoPatcherLite(apk_path)
    success = patcher.run()
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
