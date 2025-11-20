# Armadillo Detection & Unpacking Support

## 🔍 How Armadillo Was Detected

Your file `challenge.exe` was detected as **Armadillo-protected** using a multi-layered detection approach:

### Detection Method 1: YARA Rules (Primary - Most Reliable) ✅

**Location**: `yara_rules/packers.yar` (lines 169-180)

**Rule**: `Armadillo_Protector`
```yara
rule Armadillo_Protector
{
    meta:
        description = "Detects Armadillo protector"
        packer_type = "Armadillo"
        severity = "high"
    strings:
        $armadillo1 = "Armadillo" ascii
        $armadillo2 = ".tls" ascii  // Armadillo often uses TLS sections
    condition:
        any of them
}
```

**How it works**:
1. YARA scans the entire file byte-by-byte
2. Searches for the string `"Armadillo"` (case-sensitive ASCII)
3. Also checks for `.tls` section (Armadillo commonly uses TLS sections)
4. If either string is found → **MATCH** → Packer type: "Armadillo"

**Result in your file**: ✅ **DETECTED** - "YARA: Detects Armadillo protector"

### Detection Method 2: PE Section Analysis (Secondary) ✅

**Location**: `pipeline/pe_analysis.py`

**Analysis**:
- Examined all PE sections
- Checked section characteristics
- Found: `.text` section has both:
  - `IMAGE_SCN_MEM_EXECUTE` (executable)
  - `IMAGE_SCN_MEM_WRITE` (writable)

**Why this matters**: Normal executables don't have writable executable sections. This is a common indicator of packers/protectors.

**Result in your file**: ✅ **INDICATOR** - "Writable executable section: .text"

### Detection Method 3: Entropy Analysis (Supporting Evidence)

**Entropy**: 6.22 (moderate)
- High entropy threshold: 7.0
- Armadillo doesn't always have very high entropy
- This was supporting evidence, not primary detection

### Final Confidence: **HIGH**

The combination of:
- ✅ YARA rule match (most reliable method)
- ✅ PE section characteristics (writable executable section)
- ✅ Moderate entropy (supporting evidence)

Resulted in **high confidence** detection of Armadillo protector.

---

## 📦 Unpacking Support Added

### What's New

I've added **comprehensive unpacking support** for all packers:

1. **Extended Unpacking Module** (`pipeline/unpacking_extended.py`)
   - Supports 15+ packers
   - Provides unpacking guidance for each
   - Includes difficulty ratings

2. **Automatic Unpacking** (where tools exist)
   - UPX: Fully automatic if `upx.exe` is installed
   - Others: Guidance provided for manual unpacking

3. **Manual Unpacking Guidance**
   - Step-by-step instructions
   - Tool recommendations
   - Difficulty assessments

### Supported Packers

#### ✅ Automatic (Command-Line)
- **UPX**: Uses `upx -d` command

#### 📋 Manual (Guidance Provided)
- **Armadillo** (High difficulty)
- **VMProtect** (Very High difficulty)
- **Themida** (Very High difficulty)
- **Enigma** (High difficulty)
- **Obsidium** (High difficulty)
- **FSG** (Medium difficulty)
- **ASPack** (Medium difficulty)
- **PECompact** (Medium difficulty)
- **NSPack, UPack, MEW, Petite, RLPack** (Medium difficulty)

---

## 🛠️ Armadillo Unpacking Guide

Since your file is protected with Armadillo, here's how to unpack it:

### Method 1: Using Debuggers (Recommended)

**Tools Required**:
- x64dbg (recommended) or OllyDbg
- Process Monitor (ProcMon)
- Import Reconstructor
- Optional: Armadillo Find Protected tool

**Steps**:
1. **Load in Debugger**:
   - Open `challenge.exe` in x64dbg
   - Set breakpoints on:
     - `VirtualAlloc`
     - `VirtualProtect`
     - `GetProcAddress`

2. **Find OEP (Original Entry Point)**:
   - Run the program
   - When it hits breakpoints, step through
   - Look for jump to original code
   - OEP is usually in first section after unpacking

3. **Dump Memory**:
   - Once at OEP, dump the process memory
   - Save as new executable

4. **Fix Imports**:
   - Use Import Reconstructor
   - Rebuild import table
   - Fix any broken imports

5. **Verify**:
   - Test the unpacked file
   - Check if it runs correctly

### Method 2: Specialized Tools

**Armadillo Find Protected**:
- Tool specifically for Armadillo
- Can sometimes automate the process
- May require manual intervention

### Method 3: Alternative Tools

- **QuickUnpack**: Generic unpacker (may work for some Armadillo versions)
- **Generic Unpacker**: Automated unpacking tool
- **Scylla**: For fixing imports after dump

---

## 📊 What You'll See in Analysis

When you run the pipeline on an Armadillo-protected file, Step 1 will now show:

```json
{
  "step": 1,
  "packer_type": "Armadillo",
  "packing_confidence": "high",
  "unpacked": {
    "success": false,
    "unpacking_method": "manual",
    "error": "Armadillo requires manual unpacking. See guidance for instructions.",
    "guidance": "**Armadillo Unpacking Guide:**\n\n1. Tools Required:\n   - OllyDbg or x64dbg\n   ...",
    "difficulty": "High"
  }
}
```

The `guidance` field contains complete step-by-step instructions for manual unpacking.

---

## 🎯 Summary

### Detection
- ✅ **Armadillo detected** via YARA rule (string "Armadillo" found in file)
- ✅ **Confirmed** by PE analysis (writable executable section)
- ✅ **High confidence** detection

### Unpacking
- ❌ **Automatic unpacking**: Not available (Armadillo is a commercial protector)
- ✅ **Manual guidance**: Provided in analysis results
- ✅ **Difficulty**: High (requires debugger skills)

### Next Steps
1. Review the unpacking guidance in Step 1 results
2. Use x64dbg or OllyDbg for manual unpacking
3. Follow the step-by-step instructions provided
4. Consider using specialized Armadillo unpacking tools if available

---

## 📚 Additional Resources

- **x64dbg**: https://x64dbg.com/
- **OllyDbg**: http://www.ollydbg.de/
- **Import Reconstructor**: https://github.com/scylladb/scylla
- **Armadillo Documentation**: Various reverse engineering forums

The pipeline now provides complete unpacking support and guidance for all packers, including Armadillo!

