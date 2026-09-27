#!/usr/bin/env python3
"""Version detector: auto-discover mod injection layout for any TikTok MOD version.

Usage:
  python3 version_detect.py <apk_or_dex_dir>

Works on either an APK file or a directory of extracted .dex files.
Outputs a JSON report with:
  - versionName / versionCode (from aapt if APK)
  - all mod injection packages found (class definitions)
  - which dex each package is in
  - which native .so files are mod-related
  - which .so files contain popup-related JNI strings (dont/AlertDialog/setCancelable)
  - the Application class and whether it's Dex2C (native)
  - the AES encryption keys found in mod code
  - recommended patch strategy

No hardcoded version assumptions. Discovers everything at runtime.
"""
import sys, os, re, json, struct, subprocess, zipfile, glob

# --- known mod package prefixes (extend as new versions are discovered) ---
MOD_PREFIXES = [
    ('Lcom/aaaaaaa/',         'Gold/Assem/TikTok Prime'),
    ('Lme/tiktokupdatez/',     '9MOD/max.ru'),
    ('L\u012bi/\u00efi/',      '9MOD Unicode obfuscation'),
    ('Lassem/',                'ApkSignatureKillerEx'),
    ('Lprime0/',                'Dex2C loader v46.7.5'),
    ('Lprobeq0/',               'Dex2C loader v46.3.5'),
    ('LGoldDcc0/',              'Dex2C loader Gold'),
    ('Lieuwh0/',                'native loader v46.7.5'),
    ('Lchillbro0/',             'native loader v46.3.5'),
    ('Lcom/acra/',              'ACRA crash reporter'),
    ('Lcom/tiktok/plugin/',    'TikTok mod plugin client'),
]

# --- popup-related JNI strings to search in .so files ---
POPUP_SO_STRINGS = [
    'AlertDialog', 'setCancelable', 'show',
    'getSharedPreferences', 'getBoolean', 'dont',
    'pk$100000008', 'registerNativesForClass',
    'num6', 'num5', 'num4', 'num3', 'num2', 'num',
    'bb', 'en', 'vc',
]

# --- known AES keys (from decompiled mod code) ---
KNOWN_AES_KEYS = ['MD5CryptoByte128', 'MySecretKey12345']

def extract_dex(path):
    """Extract all .dex from APK or use directory. Uses a unique temp dir per APK."""
    if os.path.isdir(path):
        return {f: os.path.join(path, f) for f in sorted(os.listdir(path)) if f.endswith('.dex')}
    import hashlib
    tag = hashlib.md5(os.path.abspath(path).encode()).hexdigest()[:8]
    tmpdir = f'/tmp/_vd_dex_{tag}'
    z = zipfile.ZipFile(path)
    os.makedirs(tmpdir, exist_ok=True)
    result = {}
    for n in z.namelist():
        if n.endswith('.dex'):
            p = os.path.join(tmpdir, os.path.basename(n))
            # always overwrite (avoid stale cache from different APK)
            open(p, 'wb').write(z.read(n))
            result[os.path.basename(n)] = p
    return result

def find_mod_classes(dex_paths):
    """Find all class definitions matching mod prefixes in each dex."""
    import importlib.util
    spec = importlib.util.spec_from_file_location('dexscan',
        os.path.join(os.path.dirname(__file__), 'dexscan.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    results = {}
    for fname, fpath in dex_paths.items():
        try:
            d = mod.Dex(fpath)
        except Exception:
            continue
        for c, _ in d.class_defs():
            for prefix, label in MOD_PREFIXES:
                if c.startswith(prefix):
                    results.setdefault(fname, []).append({'class': c, 'framework': label})
    return results

def find_mod_native_libs(apk_or_dir):
    """Find .so files that contain mod popup-related strings.

    Only report .so files that contain at least 2 popup-specific strings
    (to avoid false positives from short strings like 'num'/'bb'/'en'
    that appear in many official TikTok .so files).
    """
    # Strings that are highly specific to the popup mechanism
    HIGH_SPECIFICITY = ['AlertDialog', 'setCancelable', 'getSharedPreferences',
                        'getBoolean', 'dont', 'pk$100000008', 'registerNativesForClass']
    # Strings that are moderately specific but common in mod .so
    MOD_SPECIFIC = ['num6', 'num5', 'num4', 'num3', 'num2', 'show', 'vc']
    # Short strings that cause false positives (only count if combined with high-specificity)
    LOW_SPECIFICITY = ['num', 'bb', 'en']

    so_files = {}
    if os.path.isdir(apk_or_dir):
        for root, _, files in os.walk(apk_or_dir):
            for f in files:
                if f.endswith('.so'):
                    so_files[f] = os.path.join(root, f)
    else:
        z = zipfile.ZipFile(apk_or_dir)
        for n in z.namelist():
            if n.endswith('.so'):
                so_files[os.path.basename(n)] = n
    mod_libs = {}
    for name, path_or_entry in so_files.items():
        if os.path.isfile(path_or_entry):
            data = open(path_or_entry, 'rb').read()
        else:
            data = zipfile.ZipFile(apk_or_dir).read(path_or_entry)
        high_hits = [s for s in HIGH_SPECIFICITY if s.encode() in data]
        mod_hits = [s for s in MOD_SPECIFIC if s.encode() in data]
        # Only report if at least 1 high-specificity string OR 3+ mod-specific strings
        if high_hits or len(mod_hits) >= 3:
            all_hits = high_hits + mod_hits
            mod_libs[name] = all_hits
    return mod_libs

def find_aes_keys(dex_dir):
    """Search dex files for known AES key strings."""
    found = {}
    for f in os.listdir(dex_dir):
        if not f.endswith('.dex'): continue
        data = open(os.path.join(dex_dir, f), 'rb').read()
        for key in KNOWN_AES_KEYS:
            if key.encode() in data:
                found.setdefault(key, []).append(f)
    return found

def find_application_class(apk_path):
    """Find the Application class name from manifest via aapt."""
    try:
        out = subprocess.check_output(
            ['aapt', 'dump', 'xmltree', apk_path, 'AndroidManifest.xml'],
            stderr=subprocess.DEVNULL, timeout=30).decode('utf-8', 'replace')
        for line in out.split('\n'):
            if 'android:name' in line and ('Application' in line or 'aweme.app.host' in line):
                m = re.search(r'"([^"]*Application[^"]*)"', line)
                if m:
                    return m.group(1)
    except Exception:
        pass
    return None

def check_application_native(dex_dir, app_class):
    """Check if the Application class's onCreate is native (Dex2C)."""
    if not app_class:
        return None
    desc = 'L' + app_class.replace('.', '/') + ';'
    for f in os.listdir(dex_dir):
        if not f.endswith('.dex'): continue
        data = open(os.path.join(dex_dir, f), 'rb').read()
        if desc.encode() in data:
            return f
    return None

def recommend_strategy(mod_classes, mod_libs, aes_keys, app_native):
    """Recommend patch strategy based on findings."""
    strategies = []
    has_dont = any('dont' in v for v in mod_libs.values())
    has_sharedprefs = any('getSharedPreferences' in v for v in mod_libs.values())
    has_alertdialog = any('AlertDialog' in v for v in mod_libs.values())

    if has_dont and has_sharedprefs:
        strategies.append({
            'strategy': 'A: preset dont=true',
            'reason': 'native reads SharedPreferences("").getBoolean("dont") -> preset true to skip popup',
            'risk': 'low (pure Java, no native modification)',
            'inject_point': 'Application.onCreate (find a pure-Java superclass or loader class)',
        })
    if 'me/tiktokupdatez' in str(mod_classes):
        strategies.append({
            'strategy': 'B: break f/a.d(Context) dispatch chain',
            'reason': 'me.tiktokupdatez.f.a.d(Context) -> f/e.run() -> HTTP fetch -> f/g.run() draw',
            'risk': 'low (pure Java, no native modification)',
            'methods_to_noop': [
                'me/tiktokupdatez/f/a.d(Landroid/content/Context;)V',
                'me/tiktokupdatez/f/e.run()V',
                'me/tiktokupdatez/f/f.run()V',
                'me/tiktokupdatez/f/g.run()V',
            ],
        })
    if has_alertdialog and not has_dont:
        strategies.append({
            'strategy': 'C: run() -> Java no-op (keep clinit intact!)',
            'reason': 'popup Runnable is native run(); replace with Java no-op',
            'risk': 'MEDIUM - must keep registerNativesForClass in clinit (triggers lib load); '
                    'may trigger native integrity check -> process killed',
            'warning': 'If process is killed after patch, native has integrity check on dex. '
                       'Use strategy A or D instead.',
        })
    if aes_keys:
        strategies.append({
            'strategy': 'D: invalidate URL in float table (num6)',
            'reason': 'change afmod.com -> afmod.inv (same length) in pk$100000005.num6() float array',
            'risk': 'MEDIUM - native may verify float table integrity',
            'warning': 'If process is killed, native has integrity check. Use strategy A or B instead.',
        })
    if app_native:
        strategies.append({
            'note': 'Application.onCreate is native (Dex2C) - cannot inject pref preset there. '
                    'Find a pure-Java superclass or mod loader class (<clinit>) as injection point.',
        })
    return strategies

def main():
    path = sys.argv[1]
    is_apk = path.endswith('.apk')

    print(f"[*] Scanning: {path}")

    # version info
    version = {}
    if is_apk:
        try:
            out = subprocess.check_output(['aapt', 'dump', 'badging', path],
                                          stderr=subprocess.DEVNULL, timeout=30).decode('utf-8', 'replace')
            for m in re.finditer(r"^package: name='([^']+)' versionCode='(\d+)' versionName='([^']+)'", out, re.M):
                version = {'package': m.group(1), 'versionCode': m.group(2), 'versionName': m.group(3)}
        except Exception:
            pass
    print(f"[*] Version: {version}")

    # extract dex (unique temp dir per APK to avoid cross-version contamination)
    if is_apk:
        dex_paths = extract_dex(path)
        dex_dir = os.path.dirname(list(dex_paths.values())[0]) if dex_paths else '.'
    else:
        dex_dir = path
        dex_paths = {f: os.path.join(dex_dir, f) for f in sorted(os.listdir(dex_dir)) if f.endswith('.dex')}
    print(f"[*] DEX files: {len(dex_paths)}")

    # find mod classes
    mod_classes = find_mod_classes(dex_paths)
    print(f"\n[*] Mod injection packages found:")
    for dex, classes in sorted(mod_classes.items()):
        frameworks = sorted(set(c['framework'] for c in classes))
        print(f"  {dex}: {frameworks} ({len(classes)} classes)")

    # find mod native libs
    mod_libs = find_mod_native_libs(path if is_apk else dex_dir)
    print(f"\n[*] Mod native libraries (with popup strings):")
    for lib, strings in sorted(mod_libs.items()):
        print(f"  {lib}: {strings}")

    # find AES keys
    aes_keys = find_aes_keys(dex_dir)
    print(f"\n[*] AES keys found:")
    for key, dexes in aes_keys.items():
        print(f"  '{key}' in {dexes}")

    # application class
    app_class = find_application_class(path) if is_apk else None
    app_dex = check_application_native(dex_dir, app_class) if app_class else None
    print(f"\n[*] Application class: {app_class} (in {app_dex})")

    # strategy
    strategies = recommend_strategy(mod_classes, mod_libs, aes_keys, app_dex)
    print(f"\n[*] Recommended strategies:")
    for s in strategies:
        for k, v in s.items():
            print(f"  {k}: {v}")
        print()

    # JSON output
    report = {
        'version': version,
        'dex_count': len(dex_paths),
        'mod_classes': mod_classes,
        'mod_native_libs': mod_libs,
        'aes_keys': aes_keys,
        'application_class': app_class,
        'application_dex': app_dex,
        'strategies': strategies,
    }
    print(f"\n[*] JSON report:")
    print(json.dumps(report, indent=2, ensure_ascii=False))

if __name__ == '__main__':
    main()
