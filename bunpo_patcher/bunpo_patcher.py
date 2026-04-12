#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bunpo APK Patcher - Full Standalone Script
Untuk tujuan pembelajaran reverse engineering dan debugging

Fitur:
- Auto download dependency (apktool, uber-apk-signer)
- Pattern-based analysis (tidak bergantung nama class/method)
- Multi-dex support
- Cross-platform (Windows, Linux, Termux)
- Auto decompile, patch, rebuild, sign

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
APKTOOL_HASH = ""  # Optional: SHA256 hash untuk validasi

UBER_SIGNER_URL = "https://github.com/patrickfav/uber-apk-signer/releases/download/v1.3.0/uber-apk-signer-1.3.0.jar"
UBER_SIGNER_NAME = "uber-apk-signer.jar"
UBER_SIGNER_HASH = ""

TOOLS_DIR = None
SCRIPT_DIR = None

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_script_dir():
    """Dapatkan direktori script"""
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).parent
    return Path(__file__).parent.resolve()

def get_tools_dir():
    """Dapatkan direktori tools"""
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
    """Cek apakah Java terinstall"""
    try:
        result = subprocess.run(
            ["java", "-version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            log_info(f"Java ditemukan: {result.stderr.split(chr(10))[0]}")
            return True
    except FileNotFoundError:
        log_error("Java tidak ditemukan! Silakan install JDK terlebih dahulu.")
        log_error("Download: https://www.oracle.com/java/technologies/downloads/")
    except Exception as e:
        log_error(f"Error cek Java: {e}")
    return False

def download_file(url, dest_path, max_retries=3):
    """Download file dengan retry"""
    for attempt in range(max_retries):
        try:
            log_info(f"Downloading dari {url}...")
            
            # Buat request dengan user-agent
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
                        
                        # Progress bar sederhana
                        if total_size > 0:
                            progress = (downloaded / total_size) * 100
                            print(f"\r  Progress: {progress:.1f}%", end='', flush=True)
                    
                    print()  # Newline setelah progress
            
            # Validasi ukuran file
            file_size = dest_path.stat().st_size
            if file_size < 1000:  # File terlalu kecil, kemungkinan error
                log_warning(f"File terlalu kecil ({file_size} bytes), mungkin download gagal")
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
    """Pastikan tool tersedia, download jika perlu"""
    tools_dir = get_tools_dir()
    
    if jar_name is None:
        jar_name = name
    
    jar_path = tools_dir / jar_name
    
    if jar_path.exists():
        log_info(f"{name} sudah ada: {jar_path}")
        return jar_path
    
    log_info(f"{name} tidak ditemukan, akan diunduh...")
    
    if download_file(url, jar_path):
        return jar_path
    else:
        log_error(f"Gagal mendapatkan {name}")
        return None

def run_command(cmd, cwd=None, timeout=300):
    """Jalankan command dan return output"""
    try:
        log_info(f"Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
        
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=isinstance(cmd, str)
        )
        
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
            
        return result.returncode == 0, result.stdout, result.stderr
        
    except subprocess.TimeoutExpired:
        log_error(f"Command timeout setelah {timeout} detik")
        return False, "", "Timeout"
    except Exception as e:
        log_error(f"Error running command: {e}")
        return False, "", str(e)

# ============================================================================
# SMALI ANALYZER
# ============================================================================

class SmaliAnalyzer:
    """Analyzer untuk mencari pattern penting dalam smali"""
    
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
        self.all_smali_files = []
        
    def discover_smali_files(self):
        """Temukan semua file smali termasuk multi-dex"""
        log_info("Mencari file smali...")
        
        patterns = ['smali*/**/*.smali']
        for pattern in patterns:
            self.all_smali_files.extend(self.smali_dir.glob(pattern))
        
        log_info(f"Ditemukan {len(self.all_smali_files)} file smali")
        return self.all_smali_files
    
    def analyze_file(self, file_path):
        """Analisis satu file smali"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            return
        
        current_method = None
        method_start_line = 0
        method_content = []
        in_method = False
        
        for i, line in enumerate(lines):
            stripped = line.strip()
            
            # Deteksi awal method
            if stripped.startswith('.method'):
                in_method = True
                current_method = stripped
                method_start_line = i
                method_content = [line]
                
                # Cek return type
                if ')I' in stripped and '->' in stripped:
                    # Integer return
                    self._analyze_integer_method(file_path, stripped, lines[i:i+50])
                elif ')Z' in stripped and '->' in stripped:
                    # Boolean return
                    self._analyze_boolean_method(file_path, stripped, lines[i:i+50])
                    
            elif in_method:
                method_content.append(line)
                
                # Cek pola penting dalam method
                self._check_patterns(file_path, current_method, line, lines[i:i+5])
                
                if stripped.startswith('.end method'):
                    in_method = False
                    
                    # Cek initialization patterns
                    if self._is_init_method(method_content):
                        self.results['initialization_methods'].append({
                            'file': str(file_path),
                            'method': current_method,
                            'lines': method_start_line
                        })
    
    def _analyze_integer_method(self, file_path, method_decl, context_lines):
        """Analisis method dengan return integer"""
        # Ekstrak nama method
        match = re.search(r'->([^\(]+)\(', method_decl)
        method_name = match.group(1) if match else 'unknown'
        
        # Cek apakah method ini simple getter (mengembalikan field atau konstanta)
        is_simple = False
        has_const = False
        const_value = None
        
        for line in context_lines[:20]:
            if 'iget' in line or 'sget' in line:
                is_simple = True
            if 'const' in line and ('v0' in line or 'return' in line):
                has_const = True
                # Coba ekstrak nilai konstanta
                const_match = re.search(r'const.*v0,\s*(\d+)', line)
                if const_match:
                    const_value = int(const_match.group(1))
        
        # Prioritas tinggi jika method pendek dan mengembalikan konstanta
        priority = 'low'
        if is_simple:
            priority = 'high'
        elif has_const:
            priority = 'medium'
        
        self.results['integer_methods'].append({
            'file': str(file_path),
            'method': method_decl,
            'method_name': method_name,
            'priority': priority,
            'has_const': has_const,
            'const_value': const_value,
            'is_simple_getter': is_simple
        })
    
    def _analyze_boolean_method(self, file_path, method_decl, context_lines):
        """Analisis method dengan return boolean"""
        match = re.search(r'->([^\(]+)\(', method_decl)
        method_name = match.group(1) if match else 'unknown'
        
        # Cek pola return true/false langsung
        returns_true = False
        returns_false = False
        has_comparison = False
        has_check_call = False
        
        for line in context_lines[:30]:
            if 'const/4 v0, 0x1' in line or 'const/4 v0, 0x0' in line:
                if '0x1' in line:
                    returns_true = True
                else:
                    returns_false = True
            if 'if-' in line or 'cmp' in line:
                has_comparison = True
            if 'invoke' in line and ('check' in line.lower() or 'verify' in line.lower() or 'valid' in line.lower()):
                has_check_call = True
        
        # Prioritas berdasarkan pola
        priority = 'low'
        if returns_true or returns_false:
            priority = 'high'  # Mudah di-patch
        elif has_check_call:
            priority = 'critical'  # Kemungkinan validation
        elif has_comparison:
            priority = 'medium'
        
        self.results['boolean_methods'].append({
            'file': str(file_path),
            'method': method_decl,
            'method_name': method_name,
            'priority': priority,
            'returns_true': returns_true,
            'returns_false': returns_false,
            'has_comparison': has_comparison,
            'has_check_call': has_check_call
        })
    
    def _check_patterns(self, file_path, method_name, line, context):
        """Cek berbagai pola penting"""
        
        # SharedPreferences
        if 'SharedPreferences' in line or 'getSharedPreferences' in line:
            self.results['shared_preferences'].append({
                'file': str(file_path),
                'method': method_name,
                'line': line.strip(),
                'context': '\\n'.join(context)
            })
        
        # Conditional branches
        if re.match(r'\s*if-', line):
            self.results['conditional_branches'].append({
                'file': str(file_path),
                'method': method_name,
                'instruction': line.strip(),
                'context': '\\n'.join(context)
            })
        
        # Termination calls
        if 'invoke-virtual' in line and ('finish()V' in line or 'exit' in line.lower()):
            self.results['termination_calls'].append({
                'file': str(file_path),
                'method': method_name,
                'instruction': line.strip(),
                'context': '\\n'.join(context)
            })
        
        # Runtime.exit atau System.exit
        if 'Runtime.getRuntime().exit' in line or 'System.exit' in line:
            self.results['termination_calls'].append({
                'file': str(file_path),
                'method': method_name,
                'instruction': line.strip(),
                'context': '\\n'.join(context)
            })
        
        # License/Validation checks
        if any(keyword in line.lower() for keyword in ['license', 'verify', 'validate', 'check', 'auth']):
            self.results['license_checks'].append({
                'file': str(file_path),
                'method': method_name,
                'line': line.strip(),
                'context': '\\n'.join(context)
            })
        
        # Activity redirects
        if 'startActivity' in line or 'Intent' in line:
            self.results['activity_redirects'].append({
                'file': str(file_path),
                'method': method_name,
                'line': line.strip(),
                'context': '\\n'.join(context)
            })
        
        # Getter/Setter patterns
        if re.search(r'->(get|set)[A-Z]', line):
            self.results['getter_setter'].append({
                'file': str(file_path),
                'method': line.strip(),
                'context': '\\n'.join(context)
            })
    
    def _is_init_method(self, method_content):
        """Cek apakah method adalah initialization method"""
        content_str = '\\n'.join(method_content)
        init_keywords = ['onCreate', '<init>', '<clinit>', 'init', 'initialize']
        return any(kw in content_str.lower() for kw in init_keywords)
    
    def analyze_all(self):
        """Analisis semua file smali"""
        self.discover_smali_files()
        
        log_info("Memulai analisis pattern...")
        
        for i, file_path in enumerate(self.all_smali_files):
            if (i + 1) % 100 == 0:
                log_info(f"Progress: {i + 1}/{len(self.all_smali_files)} files")
            self.analyze_file(file_path)
        
        log_success("Analisis selesai!")
        self.print_summary()
        
        return self.results
    
    def print_summary(self):
        """Print ringkasan hasil analisis"""
        print("\\n" + "="*70)
        print("RINGKASAN HASIL ANALISIS")
        print("="*70)
        
        print(f"\\n📊 Integer Methods (return I): {len(self.results['integer_methods'])}")
        high_priority_int = [m for m in self.results['integer_methods'] if m['priority'] == 'high']
        print(f"   - High priority: {len(high_priority_int)}")
        
        print(f"\\n🔴 Boolean Methods (return Z): {len(self.results['boolean_methods'])}")
        critical_bool = [m for m in self.results['boolean_methods'] if m['priority'] == 'critical']
        high_priority_bool = [m for m in self.results['boolean_methods'] if m['priority'] == 'high']
        print(f"   - Critical (validation): {len(critical_bool)}")
        print(f"   - High priority: {len(high_priority_bool)}")
        
        print(f"\\n💾 SharedPreferences Access: {len(self.results['shared_preferences'])}")
        print(f"\\n🔀 Conditional Branches: {len(self.results['conditional_branches'])}")
        print(f"\\n🛑 Termination Calls: {len(self.results['termination_calls'])}")
        print(f"\\n🔐 License Checks: {len(self.results['license_checks'])}")
        print(f"\\n🔄 Activity Redirects: {len(self.results['activity_redirects'])}")
        print(f"\\n⚙️ Initialization Methods: {len(self.results['initialization_methods'])}")
        
        print("\\n" + "="*70)
    
    def get_top_targets(self, category, limit=10):
        """Ambil target teratas berdasarkan prioritas"""
        targets = self.results.get(category, [])
        
        # Sort by priority
        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        sorted_targets = sorted(targets, key=lambda x: priority_order.get(x.get('priority', 'low'), 3))
        
        return sorted_targets[:limit]


# ============================================================================
# SMALI PATCHER
# ============================================================================

class SmaliPatcher:
    """Patcher untuk memodifikasi file smali"""
    
    def __init__(self, smali_dir):
        self.smali_dir = Path(smali_dir)
        self.patched_files = []
        self.patch_log = []
    
    def patch_integer_method(self, file_path, method_pattern, new_value=99999):
        """
        Patch method integer untuk mengembalikan nilai tetap
        
        Args:
            file_path: Path ke file smali
            method_pattern: Regex pattern untuk menemukan method
            new_value: Nilai integer yang akan dikembalikan
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            original_content = content
            
            # Temukan method yang match
            method_match = re.search(
                r'(\.method\s+(?:public|private|protected)?\s*(?:static)?\s*' + 
                 method_pattern + r'\\s*\\([^)]*\\)I[^\\n]*\\n)' +
                 r'(.*?)' +
                 r'(\\.end method)',
                content,
                re.DOTALL | re.IGNORECASE
            )
            
            if method_match:
                method_start = method_match.group(1)
                method_end = method_match.group(3)
                
                # Buat body method baru
                new_body = f"""    .locals 1

    const v0, {new_value}

    return v0
.end method
"""
                # Replace method
                new_content = content.replace(
                    method_match.group(0),
                    method_start + new_body.replace('.end method', '') + method_end
                )
                
                if new_content != original_content:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    
                    self.patched_files.append(str(file_path))
                    self.patch_log.append({
                        'action': 'patch_integer',
                        'file': str(file_path),
                        'method': method_pattern,
                        'new_value': new_value
                    })
                    return True
            
            return False
            
        except Exception as e:
            log_error(f"Error patching {file_path}: {e}")
            return False
    
    def patch_boolean_method(self, file_path, method_pattern, return_value=True):
        """
        Patch method boolean untuk selalu return true/false
        
        Args:
            file_path: Path ke file smali
            method_pattern: Regex pattern untuk menemukan method
            return_value: True untuk return true, False untuk return false
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            original_content = content
            bool_value = '0x1' if return_value else '0x0'
            
            # Temukan method yang match
            method_match = re.search(
                r'(\.method\s+(?:public|private|protected)?\s*(?:static)?\s*' +
                 method_pattern + r'\\s*\\([^)]*\\)Z[^\\n]*\\n)' +
                 r'(.*?)' +
                 r'(\\.end method)',
                content,
                re.DOTALL | re.IGNORECASE
            )
            
            if method_match:
                method_start = method_match.group(1)
                method_end = method_match.group(3)
                
                # Buat body method baru
                new_body = f"""    .locals 1

    const/4 v0, {bool_value}

    return v0
.end method
"""
                # Replace method
                new_content = content.replace(
                    method_match.group(0),
                    method_start + new_body.replace('.end method', '') + method_end
                )
                
                if new_content != original_content:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    
                    self.patched_files.append(str(file_path))
                    self.patch_log.append({
                        'action': 'patch_boolean',
                        'file': str(file_path),
                        'method': method_pattern,
                        'return_value': return_value
                    })
                    return True
            
            return False
            
        except Exception as e:
            log_error(f"Error patching {file_path}: {e}")
            return False
    
    def patch_conditional_branch(self, file_path, line_pattern, invert=True):
        """
        Patch conditional branch untuk membalik logika
        
        Args:
            file_path: Path ke file smali
            line_pattern: Pattern untuk menemukan instruction
            invert: Jika True, invert condition (if-eqz -> if-nez)
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            modified = False
            new_lines = []
            
            # Mapping untuk invert condition
            invert_map = {
                'if-eqz': 'if-nez',
                'if-nez': 'if-eqz',
                'if-eq': 'if-ne',
                'if-ne': 'if-eq',
                'if-ltz': 'if-gez',
                'if-gez': 'if-ltz',
                'if-gtz': 'if-lez',
                'if-lez': 'if-gtz',
                'if-lt': 'if-ge',
                'if-ge': 'if-lt',
                'if-gt': 'if-le',
                'if-le': 'if-gt'
            }
            
            for line in lines:
                if re.search(line_pattern, line):
                    if invert:
                        # Coba invert condition
                        for old, new in invert_map.items():
                            if old in line:
                                new_line = line.replace(old, new)
                                new_lines.append(new_line)
                                modified = True
                                self.patch_log.append({
                                    'action': 'invert_condition',
                                    'file': str(file_path),
                                    'original': line.strip(),
                                    'modified': new_line.strip()
                                })
                                break
                        else:
                            new_lines.append(line)
                    else:
                        # Remove conditional jump (replace dengan nop atau skip)
                        new_lines.append('    nop\n')
                        modified = True
                        self.patch_log.append({
                            'action': 'remove_condition',
                            'file': str(file_path),
                            'original': line.strip()
                        })
                else:
                    new_lines.append(line)
            
            if modified:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.writelines(new_lines)
                
                self.patched_files.append(str(file_path))
                return True
            
            return False
            
        except Exception as e:
            log_error(f"Error patching {file_path}: {e}")
            return False
    
    def patch_termination_call(self, file_path, method_pattern):
        """
        Patch method yang memanggil finish() atau exit() untuk tidak melakukan apa-apa
        
        Args:
            file_path: Path ke file smali
            method_pattern: Pattern untuk menemukan method
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            original_content = content
            
            # Temukan method
            method_match = re.search(
                r'(\.method\s+[^\n]+\n)' +
                r'(.*?)(invoke-virtual[^\n]+(?:finish|exit)[^\n]*\\n)' +
                r'(.*?)(\\.end method)',
                content,
                re.DOTALL | re.IGNORECASE
            )
            
            if method_match:
                # Hapus panggilan finish/exit
                method_start = method_match.group(1)
                before_call = method_match.group(2)
                after_call = method_match.group(4)
                method_end = method_match.group(5)
                
                # Tambahkan return-void sebelum finish/exit dihapus
                new_content = content.replace(
                    method_match.group(0),
                    method_start + before_call + '    return-void\n' + method_end
                )
                
                if new_content != original_content:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    
                    self.patched_files.append(str(file_path))
                    self.patch_log.append({
                        'action': 'remove_termination',
                        'file': str(file_path),
                        'method': method_pattern
                    })
                    return True
            
            return False
            
        except Exception as e:
            log_error(f"Error patching {file_path}: {e}")
            return False
    
    def apply_auto_patches(self, analyzer_results):
        """
        Apply patches otomatis berdasarkan hasil analisis
        
        Args:
            analyzer_results: Hasil dari SmaliAnalyzer
        """
        log_info("Applying automatic patches...")
        
        patched_count = 0
        
        # 1. Patch boolean methods dengan prioritas critical/high yang return false
        for method in analyzer_results.get('boolean_methods', [])[:20]:
            if method['priority'] in ['critical', 'high'] and method.get('returns_false'):
                file_path = Path(method['file'])
                if file_path.exists():
                    # Ekstrak method signature
                    match = re.search(r'->([^\(]+)\(', method['method'])
                    if match:
                        method_name = re.escape(match.group(1))
                        if self.patch_boolean_method(file_path, f'.*[^\n]*->{method_name}', True):
                            patched_count += 1
                            log_info(f"Patched boolean: {method['method']}")
        
        # 2. Patch termination calls
        for term in analyzer_results.get('termination_calls', [])[:10]:
            file_path = Path(term['file'])
            if file_path.exists():
                # Cari method yang mengandung termination call
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Temukan method yang berisi finish/exit
                method_matches = re.findall(
                    r'(\.method[^\n]+\n.*?(?:finish|exit)[^\n]*?.*?\.end method)',
                    content,
                    re.DOTALL | re.IGNORECASE
                )
                
                for method_full in method_matches[:3]:
                    # Extract method declaration
                    decl_match = re.search(r'(\.method[^\n]+)', method_full)
                    if decl_match:
                        method_decl = decl_match.group(1)
                        # Replace dengan method kosong
                        if 'V)' in method_decl or ')V' in method_decl:
                            # Void return
                            new_method = re.sub(
                                r'(\.method[^\n]+\n).*?(\.end method)',
                                r'\\1    .locals 0\\n\\n    return-void\\n.end method',
                                method_full,
                                flags=re.DOTALL
                            )
                            new_content = content.replace(method_full, new_method)
                            if new_content != content:
                                with open(file_path, 'w', encoding='utf-8') as f:
                                    f.write(new_content)
                                patched_count += 1
                                log_info(f"Patched termination: {method_decl}")
        
        # 3. Patch conditional branches yang mengarah ke termination/error
        for branch in analyzer_results.get('conditional_branches', [])[:20]:
            file_path = Path(branch['file'])
            if file_path.exists():
                context = branch.get('context', '')
                # Jika context mengandung finish, exit, atau error
                if any(kw in context.lower() for kw in ['finish', 'exit', 'error', 'throw']):
                    # Invert condition
                    instruction = branch.get('instruction', '')
                    if instruction:
                        pattern = re.escape(instruction.strip())
                        if self.patch_conditional_branch(file_path, pattern, invert=True):
                            patched_count += 1
                            log_info(f"Inverted condition: {instruction}")
        
        log_success(f"Total patches applied: {patched_count}")
        return patched_count
    
    def save_patch_report(self, output_path):
        """Simpan laporan patch ke file"""
        import json
        
        report = {
            'patched_files': self.patched_files,
            'patch_log': self.patch_log,
            'total_patches': len(self.patch_log)
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        log_info(f"Patch report saved to: {output_path}")


# ============================================================================
# MAIN PATCHER ORCHESTRATOR
# ============================================================================

class BunpoPatcher:
    """Main orchestrator untuk proses patching"""
    
    def __init__(self, apk_path):
        self.apk_path = Path(apk_path)
        self.work_dir = None
        self.smali_dir = None
        self.output_apk = None
        
        # Setup directories
        self.setup_directories()
    
    def setup_directories(self):
        """Setup working directories"""
        self.work_dir = tempfile.mkdtemp(prefix='bunpo_patch_')
        self.smali_dir = Path(self.work_dir) / 'smali_output'
        self.output_apk = self.apk_path.parent / f"{self.apk_path.stem}_patched.apk"
        
        log_info(f"Work directory: {self.work_dir}")
        log_info(f"Output APK: {self.output_apk}")
    
    def decompile(self, apktool_path):
        """Decompile APK menggunakan apktool"""
        log_info("Memulai decompile APK...")
        
        cmd = [
            'java', '-jar', str(apktool_path),
            'd', str(self.apk_path),
            '-o', str(self.smali_dir),
            '-f',  # Force overwrite
            '-r',  # Don't decode resources
        ]
        
        success, stdout, stderr = run_command(cmd, timeout=600)
        
        if success:
            log_success("Decompile berhasil!")
            return True
        else:
            log_error("Decompile gagal!")
            return False
    
    def analyze_and_patch(self):
        """Analyze dan apply patches"""
        log_info("Memulai analisis dan patching...")
        
        # Analyzer
        analyzer = SmaliAnalyzer(self.smali_dir)
        results = analyzer.analyze_all()
        
        # Patcher
        patcher = SmaliPatcher(self.smali_dir)
        
        # Apply auto patches
        patch_count = patcher.apply_auto_patches(results)
        
        # Simpan report
        report_path = self.work_dir / 'patch_report.json'
        patcher.save_patch_report(report_path)
        
        # Print top targets untuk user
        self._print_top_targets(analyzer)
        
        return patch_count > 0
    
    def _print_top_targets(self, analyzer):
        """Print target terbaik untuk manual patching"""
        print("\\n" + "="*70)
        print("TARGET TERBAIK UNTUK MANUAL PATCHING")
        print("="*70)
        
        # Top boolean methods
        print("\\n🎯 Top 5 Boolean Methods (untuk force true):")
        for i, method in enumerate(analyzer.get_top_targets('boolean_methods', 5), 1):
            print(f"  {i}. {method['method']}")
            print(f"     File: {method['file']}")
            print(f"     Priority: {method['priority']}")
        
        # Top integer methods
        print("\\n🔢 Top 5 Integer Methods (untuk set max value):")
        for i, method in enumerate(analyzer.get_top_targets('integer_methods', 5), 1):
            print(f"  {i}. {method['method']}")
            print(f"     File: {method['file']}")
            print(f"     Has const: {method.get('has_const', False)}")
        
        # Critical license checks
        if analyzer.results['license_checks']:
            print("\\n🔐 Critical License Checks:")
            for check in analyzer.results['license_checks'][:5]:
                print(f"  • {check['file']}")
                print(f"    {check['line']}")
    
    def rebuild(self, apktool_path):
        """Rebuild APK"""
        log_info("Rebuilding APK...")
        
        cmd = [
            'java', '-jar', str(apktool_path),
            'b', str(self.smali_dir),
            '-o', str(self.output_apk),
            '-f',
        ]
        
        success, stdout, stderr = run_command(cmd, timeout=600)
        
        if success:
            log_success("Rebuild berhasil!")
            return True
        else:
            log_error("Rebuild gagal!")
            return False
    
    def sign(self, signer_path):
        """Sign APK dengan uber-apk-signer"""
        log_info("Signing APK...")
        
        cmd = [
            'java', '-jar', str(signer_path),
            '--apks', str(self.output_apk),
        ]
        
        success, stdout, stderr = run_command(cmd, timeout=300)
        
        if success:
            log_success("Signing berhasil!")
            
            # Check if signed APK exists
            signed_apk = self.output_apk.parent / f"{self.output_apk.stem}-aligned-signed.apk"
            if signed_apk.exists():
                self.output_apk = signed_apk
                log_success(f"Signed APK: {self.output_apk}")
            
            return True
        else:
            log_warning("Signing mungkin gagal, tapi APK masih bisa diinstall (debug mode)")
            return True  # Return True agar tidak stop proses
    
    def cleanup(self):
        """Cleanup temporary files"""
        log_info("Cleaning up...")
        try:
            shutil.rmtree(self.work_dir)
            log_info("Temporary files removed")
        except Exception as e:
            log_warning(f"Failed to cleanup: {e}")
    
    def run(self):
        """Jalankan seluruh proses patching"""
        print("\\n" + "="*70)
        print("BUNPO APK PATCHER - FULL AUTOMATIC")
        print("="*70)
        
        # Check prerequisites
        if not self.apk_path.exists():
            log_error(f"APK tidak ditemukan: {self.apk_path}")
            return False
        
        if not check_java():
            return False
        
        # Download tools
        apktool_path = ensure_tool('apktool', APKTOOL_URL, APKTOOL_NAME)
        if not apktool_path:
            return False
        
        signer_path = ensure_tool('uber-apk-signer', UBER_SIGNER_URL, UBER_SIGNER_NAME)
        if not signer_path:
            return False
        
        try:
            # Step 1: Decompile
            if not self.decompile(apktool_path):
                return False
            
            # Step 2: Analyze & Patch
            if not self.analyze_and_patch():
                log_warning("Tidak ada patch yang diterapkan, lanjut rebuild...")
            
            # Step 3: Rebuild
            if not self.rebuild(apktool_path):
                return False
            
            # Step 4: Sign
            self.sign(signer_path)
            
            # Success!
            print("\\n" + "="*70)
            log_success("PATCHING SELESAI!")
            print("="*70)
            print(f"\\n📦 APK hasil patch: {self.output_apk}")
            print(f"\\n📝 Patch report: {self.work_dir / 'patch_report.json'}")
            print("\\n⚠️  CATATAN:")
            print("   - Install APK hasil patch pada device Android")
            print("   - Backup data sebelum install")
            print("   - Gunakan hanya untuk tujuan pembelajaran")
            print("="*70 + "\\n")
            
            return True
            
        finally:
            # Cleanup
            self.cleanup()


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point"""
    global SCRIPT_DIR
    
    SCRIPT_DIR = get_script_dir()
    
    print("\\n" + "="*70)
    print("  BUNPO APK PATCHER v1.0")
    print("  Reverse Engineering Tool untuk Tujuan Pembelajaran")
    print("="*70 + "\\n")
    
    # Parse arguments
    if len(sys.argv) < 2:
        print("Usage: python bunpo_patcher.py <path_to_apk>")
        print("\\nExample:")
        print("  python bunpo_patcher.py Bunpo_3.8.0.apk")
        print("  python bunpo_patcher.py /path/to/app.apk")
        print("\\nFeatures:")
        print("  ✓ Auto download dependencies")
        print("  ✓ Pattern-based analysis (anti-obfuscation)")
        print("  ✓ Multi-dex support")
        print("  ✓ Auto patching (boolean, integer, conditions)")
        print("  ✓ Auto rebuild & sign")
        print("  ✓ Cross-platform (Windows, Linux, Termux)")
        sys.exit(1)
    
    apk_path = Path(sys.argv[1])
    
    if not apk_path.exists():
        log_error(f"File APK tidak ditemukan: {apk_path}")
        sys.exit(1)
    
    # Run patcher
    patcher = BunpoPatcher(apk_path)
    success = patcher.run()
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
