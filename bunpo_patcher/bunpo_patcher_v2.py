#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BUNPO APK PATCHER v2.0 - SAFE EDITION
Reverse Engineering Tool untuk Tujuan Pembelajaran
Fix: Mencegah corrupt pada file inner class & konstanta besar
Fix: TypeError path operations
"""

import os
import sys
import re
import shutil
import subprocess
import tempfile
import json
import time
from pathlib import Path
from urllib.request import urlretrieve
from typing import List, Dict, Tuple, Optional

# --- KONFIGURASI ---
APKTOOL_URL = "https://github.com/iBotPeaches/Apktool/releases/download/v3.0.1/apktool_3.0.1.jar"
SIGNER_URL = "https://github.com/patrickfav/uber-apk-signer/releases/download/v1.3.0/uber-apk-signer-1.3.0.jar"
SCRIPT_DIR = Path(__file__).parent.resolve()
TOOLS_DIR = SCRIPT_DIR / "tools"
MAX_FILES_ANALYZE = 2000
SAFE_MODE = True

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def log_info(msg): print(f"{Colors.OKCYAN}[INFO]{Colors.ENDC} {msg}")
def log_success(msg): print(f"{Colors.OKGREEN}[SUCCESS]{Colors.ENDC} {msg}")
def log_warning(msg): print(f"{Colors.WARNING}[WARNING]{Colors.ENDC} {msg}")
def log_error(msg): print(f"{Colors.FAIL}[ERROR]{Colors.ENDC} {msg}")

def check_java():
    try:
        result = subprocess.run(["java", "-version"], capture_output=True, text=True)
        if result.returncode == 0:
            version_line = result.stderr.splitlines()[0] if result.stderr else result.stdout.splitlines()[0]
            log_info(f"Java ditemukan: {version_line}")
            return True
    except FileNotFoundError:
        log_error("Java tidak ditemukan! Instal JDK terlebih dahulu.")
    return False

def download_file(url, dest):
    if dest.exists():
        log_info(f"{dest.name} sudah ada.")
        return True
    
    log_info(f"Mengunduh {dest.name}...")
    retries = 3
    for i in range(retries):
        try:
            urlretrieve(url, dest)
            if dest.stat().st_size > 1000:
                log_success(f"Download selesai: {dest.name}")
                return True
            else:
                log_warning("File download korup, retry...")
                dest.unlink()
        except Exception as e:
            log_warning(f"Gagal download (percobaan {i+1}/{retries}): {e}")
            if i < retries - 1:
                time.sleep(2)
    
    log_error("Download gagal setelah beberapa percobaan.")
    return False

def setup_tools():
    TOOLS_DIR.mkdir(exist_ok=True)
    apktool = TOOLS_DIR / "apktool.jar"
    signer = TOOLS_DIR / "uber-apk-signer.jar"
    
    if not download_file(APKTOOL_URL, apktool): return False
    if not download_file(SIGNER_URL, signer): return False
    return True

class SmaliAnalyzer:
    def __init__(self, work_dir: Path):
        self.work_dir = work_dir
        self.smali_dirs = list(work_dir.glob("smali*"))
        self.stats = {
            "integer_methods": [],
            "boolean_methods": [],
            "shared_prefs": 0,
            "conditionals": 0,
            "terminations": 0,
            "license_checks": 0
        }

    def find_smali_files(self) -> List[Path]:
        files = []
        for d in self.smali_dirs:
            files.extend(d.rglob("*.smali"))
        return sorted(files, key=lambda x: x.stat().st_size)

    def is_safe_to_patch(self, content: str, filename: str) -> bool:
        if "$" in filename and len(content) > 2000:
            return False
        if ".array-data" in content and content.count(".array-data") > 5:
            return False
        return True

    def analyze_file(self, file_path: Path) -> Dict:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return {}

        results = {"path": str(file_path), "patches": []}
        
        if "SharedPreferences" in content or "getSharedPreferences" in content:
            self.stats["shared_prefs"] += 1

        self.stats["conditionals"] += len(re.findall(r'\bif-(eq|ne|lt|ge|gt|le)', content))

        if re.search(r'(finish\(\)|System\.exit|Process\.kill)', content):
            self.stats["terminations"] += 1

        if re.search(r'(verify|validate|check|license|sign|auth)', content, re.IGNORECASE):
            self.stats["license_checks"] += 1

        method_pattern = r'\.method\s+([^\n]+?)\n(.*?)\.end method'
        matches = re.finditer(method_pattern, content, re.DOTALL)

        for match in matches:
            header = match.group(1)
            body = match.group(2)
            
            if len(body) > 3000: continue

            ret_type_match = re.search(r'\)([IZLjava/.;]+)', header)
            if not ret_type_match: continue
            ret_type = ret_type_match.group(1)

            if ret_type == 'Z':
                score = 0
                if 'if-' in body: score += 1
                if 'return v' in body or 'return p' in body: score += 1
                method_name = header.split('(')[0].split()[-1]
                if 'check' in header.lower() or 'valid' in header.lower() or 'is' in method_name: score += 2
                
                if score >= 2 and self.is_safe_to_patch(body, file_path.name):
                    results["patches"].append({
                        "type": "BOOL_TRUE",
                        "match": match.group(0),
                        "reason": f"Boolean validator (score: {score})"
                    })

            elif ret_type == 'I':
                if 'return v' in body or 'return p' in body:
                    if 'const' not in body:
                         if self.is_safe_to_patch(body, file_path.name):
                            results["patches"].append({
                                "type": "INT_MAX",
                                "match": match.group(0),
                                "reason": "Integer getter"
                            })

        return results

    def run_analysis(self, limit: int = MAX_FILES_ANALYZE):
        log_info("Menganalisis smali files...")
        all_files = self.find_smali_files()
        total = len(all_files)
        log_info(f"Ditemukan {total} file smali")
        
        priority_files = []
        for f in all_files:
            try:
                if f.stat().st_size < 100000:
                    txt = f.read_text(errors='ignore')
                    if any(k in txt for k in ['SharedPreferences', 'License', 'Check', 'Valid']):
                        priority_files.append(f)
            except: pass
        
        files_to_scan = priority_files[:limit] if priority_files else all_files[:limit]
        
        log_info(f"Menganalisis {len(files_to_scan)} file prioritas...")
        
        count = 0
        for f in files_to_scan:
            count += 1
            if count % 500 == 0:
                log_info(f"Progress: {count}/{len(files_to_scan)} files")
            
            res = self.analyze_file(f)
            if res and "patches" in res:
                for p in res["patches"]:
                    if p["type"] == "BOOL_TRUE":
                        self.stats["boolean_methods"].append({"file": str(f), "patch": p})
                    elif p["type"] == "INT_MAX":
                        self.stats["integer_methods"].append({"file": str(f), "patch": p})
        
        log_success("Analisis selesai!")
        self.print_summary()

    def print_summary(self):
        print(f"\n{Colors.HEADER}{'='*60}")
        print("RINGKASAN HASIL ANALISIS")
        print(f"{'='*60}{Colors.ENDC}")
        print(f"📊 Integer Methods (candidate): {len(self.stats['integer_methods'])}")
        print(f"🔴 Boolean Methods (candidate): {len(self.stats['boolean_methods'])}")
        print(f"💾 SharedPreferences Access: {self.stats['shared_prefs']}")
        print(f"🔀 Conditional Branches: {self.stats['conditionals']}")
        print(f"🛑 Termination Calls: {self.stats['terminations']}")
        print(f"🔐 License Keywords Found: {self.stats['license_checks']}")
        print(f"{'='*60}\n")

class SmaliPatcher:
    def __init__(self, analyzer: SmaliAnalyzer):
        self.analyzer = analyzer
        self.patch_count = 0

    def patch_method_body(self, content: str, old_match: str, patch_type: str) -> str:
        if patch_type == "BOOL_TRUE":
            new_body = "\n    const/4 v0, 0x1\n    return v0\n"
        elif patch_type == "INT_MAX":
            new_body = "\n    const v0, 0x1869f\n    return v0\n"
        else:
            return content

        header_line = ""
        for line in old_match.split('\n'):
            if line.strip().startswith('.method'):
                header_line = line
                break
        
        if not header_line:
            return content
            
        new_method = f"{header_line}{new_body}.end method"
        return content.replace(old_match, new_method)

    def apply_patches(self):
        log_info("Applying automatic patches...")
        
        for item in self.analyzer.stats["boolean_methods"][:20]:
            file_path = Path(item["file"])
            if not file_path.exists(): continue
            
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            old_match = item["patch"]["match"]
            
            if old_match in content:
                new_content = self.patch_method_body(content, old_match, "BOOL_TRUE")
                if new_content != content:
                    file_path.write_text(new_content, encoding='utf-8')
                    self.patch_count += 1
                    log_info(f"Patched boolean: {item['patch']['reason']} in {file_path.name}")

        for item in self.analyzer.stats["integer_methods"][:20]:
            file_path = Path(item["file"])
            if not file_path.exists(): continue
            
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            old_match = item["patch"]["match"]
            
            if old_match in content:
                new_content = self.patch_method_body(content, old_match, "INT_MAX")
                if new_content != content:
                    file_path.write_text(new_content, encoding='utf-8')
                    self.patch_count += 1
                    log_info(f"Patched integer: {item['patch']['reason']} in {file_path.name}")
        
        log_success(f"Total patches applied: {self.patch_count}")

class ApkPatcher:
    def __init__(self, apk_path: str):
        self.apk_path = Path(apk_path).resolve()
        if not self.apk_path.exists():
            raise FileNotFoundError(f"APK tidak ditemukan: {apk_path}")
        
        self.temp_dir = Path(tempfile.mkdtemp(prefix="bunpo_patch_"))
        self.work_dir = self.temp_dir / "smali_output"
        self.output_apk = self.apk_path.parent / f"{self.apk_path.stem}_patched.apk"
        
        log_info(f"Work directory: {self.temp_dir}")
        log_info(f"Output APK: {self.output_apk}")

    def decompile(self):
        log_info("Memulai decompile APK...")
        cmd = ["java", "-jar", str(TOOLS_DIR / "apktool.jar"), "d", 
               str(self.apk_path), "-o", str(self.work_dir), "-f", "--no-src"]
        
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            log_success("Decompile berhasil!")
            return True
        except subprocess.CalledProcessError as e:
            log_error(f"Decompile gagal: {e.stderr}")
            return False

    def rebuild(self):
        log_info("Rebuilding APK...")
        cmd = ["java", "-jar", str(TOOLS_DIR / "apktool.jar"), "b", 
               str(self.work_dir), "-o", str(self.output_apk), "-f"]
        
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)
            log_success("Rebuild berhasil!")
            return True
        except subprocess.TimeoutExpired:
            log_error("Rebuild timeout! File mungkin terlalu besar.")
            return False
        except subprocess.CalledProcessError as e:
            log_error(f"Rebuild gagal!\n{e.stderr}")
            if "Error for input" in e.stderr:
                log_error("Terjadi kesalahan sintaks smali. Patch mungkin terlalu agresif.")
                log_info("Tips: Gunakan mode --safe atau kurangi jumlah patch.")
            return False

    def sign(self):
        log_info("Signing APK...")
        cmd = ["java", "-jar", str(TOOLS_DIR / "uber-apk-signer.jar"), 
               "--apks", str(self.output_apk)]
        
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            signed_files = list(self.apk_path.parent.glob("*patched*-aligned-signed.apk"))
            if signed_files:
                final_name = signed_files[0]
                target_name = self.apk_path.parent / f"{self.apk_path.stem}_patched-signed.apk"
                final_name.rename(target_name)
                log_success(f"APK Signed: {target_name}")
            else:
                log_warning("Signing selesai tapi file output tidak ditemukan.")
            return True
        except subprocess.CalledProcessError as e:
            log_error(f"Signing gagal: {e.stderr}")
            return False

    def cleanup(self):
        log_info("Cleaning up...")
        try:
            shutil.rmtree(self.temp_dir)
            log_info("Temporary files removed")
        except Exception as e:
            log_warning(f"Gagal hapus temp: {e}")

    def run(self):
        if not check_java(): return False
        if not setup_tools(): return False
        
        if not self.decompile():
            self.cleanup()
            return False

        analyzer = SmaliAnalyzer(self.work_dir)
        analyzer.run_analysis()
        
        patcher = SmaliPatcher(analyzer)
        patcher.apply_patches()
        
        # FIX: Gunakan Path object, bukan string concatenation
        report_path = self.temp_dir / "patch_report.json"
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump({
                "integer_patches": len(analyzer.stats["integer_methods"]),
                "boolean_patches": len(analyzer.stats["boolean_methods"]),
                "total_applied": patcher.patch_count
            }, f, indent=2)
        log_info(f"Report saved to: {report_path}")

        if not self.rebuild():
            log_error("Build gagal. File smali mungkin corrupt.")
            self.cleanup()
            return False
            
        if not self.sign():
            log_warning("APK rebuilt tapi gagal sign.")
        
        self.cleanup()
        log_success(f"Selesai! Cek file: {self.apk_path.parent}")
        return True

def main():
    print(f"\n{Colors.HEADER}{'='*70}")
    print("  BUNPO APK PATCHER v2.0 - SAFE EDITION")
    print("  Reverse Engineering Tool untuk Tujuan Pembelajaran")
    print(f"{'='*70}{Colors.ENDC}\n")
    
    if len(sys.argv) < 2:
        print("Usage: python bunpo_patcher.py <path_to_apk>")
        sys.exit(1)
    
    apk_file = sys.argv[1]
    patcher = ApkPatcher(apk_file)
    
    success = patcher.run()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
