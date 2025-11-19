# Packing Detection & Unpacking Implementation Plan

## Current Status

### ✅ Implemented
- Basic file type detection using `python-magic`
- File format identification (PE, ELF heuristics)

### ❌ Missing
- Packing detection (entropy, packer signatures)
- Unpacking capabilities
- Detailed PE/ELF structure analysis (despite `pefile` being in requirements)

---

## Recommended Tools & Implementation

### 1. Packing Detection

#### **Primary Tools:**

**A. Entropy Calculation (Python)**
- **Tool**: Custom implementation using `scipy` or `numpy`
- **Why**: High entropy (>7.0) indicates compression/encryption
- **Implementation**: Calculate Shannon entropy on file sections
- **Dependencies**: `scipy` or `numpy` (lightweight)

**B. PEiD Signatures (Python)**
- **Tool**: `pefile` + custom signature database
- **Why**: Detects known packers (UPX, ASPack, VMProtect, etc.)
- **Implementation**: 
  - Use `pefile` to parse PE structure
  - Check section names, entry point characteristics
  - Match against packer signatures
- **Dependencies**: `pefile` (already in requirements.txt)

**C. YARA Rules**
- **Tool**: `yara-python` (already in requirements.txt!)
- **Why**: Pattern matching for packer signatures
- **Implementation**: Create YARA rules for common packers
- **Dependencies**: `yara-python` (already installed)

**D. Detect It Easy (DiE) - External Tool**
- **Tool**: Command-line wrapper for DiE
- **Why**: Industry-standard packer detection
- **Implementation**: Subprocess call to `diec.exe` (Windows)
- **Dependencies**: Download DiE separately

#### **Best Choice for Your Project:**
**Combine `pefile` + entropy calculation + YARA rules** - All Python-based, no external dependencies needed.

---

### 2. Unpacking

#### **Primary Tools:**

**A. UPX Unpacking**
- **Tool**: `upx` command-line tool
- **Why**: Most common packer, has built-in unpacking
- **Implementation**: 
  ```python
  subprocess.run(['upx', '-d', packed_file, '-o', unpacked_file])
  ```
- **Dependencies**: Download UPX binary (free, open-source)

**B. Generic Unpacking (Advanced)**
- **Tool**: `unpacker` or `generic_unpacker` scripts
- **Why**: Handles unknown/custom packers
- **Implementation**: Dynamic analysis approach (requires sandbox execution)
- **Dependencies**: Complex, requires execution environment

**C. Ghidra Scripts**
- **Tool**: Custom Ghidra scripts (you already have Ghidra integration!)
- **Why**: Can analyze and manually unpack during decompilation
- **Implementation**: Extend existing `DumpArtifacts.java` script
- **Dependencies**: Ghidra (already integrated)

**D. OllyDbg/x64dbg (Manual)**
- **Tool**: External debuggers
- **Why**: Industry standard for manual unpacking
- **Implementation**: Not automatable, manual process
- **Dependencies**: External tool

#### **Best Choice for Your Project:**
**Start with UPX unpacking** - Simple, common, automatable. Add Ghidra-based unpacking later.

---

### 3. Enhanced File Format Checking

#### **Primary Tools:**

**A. pefile (Python) - ALREADY IN REQUIREMENTS!**
- **Tool**: `pefile` library
- **Why**: Detailed PE structure analysis
- **Implementation**: Parse PE headers, sections, imports, exports
- **Dependencies**: `pefile` (already in requirements.txt, but NOT USED!)

**B. LIEF (Library to Instrument Executable Formats)**
- **Tool**: `lief` Python library
- **Why**: Cross-platform (PE, ELF, Mach-O), modern API
- **Implementation**: Parse and modify binary formats
- **Dependencies**: `pip install lief`

**C. file (Unix tool) / python-magic (Current)**
- **Tool**: You're already using `python-magic`
- **Why**: Basic file type detection
- **Status**: ✅ Already implemented
- **Enhancement**: Add more detailed analysis

**D. Droid (UK National Archives)**
- **Tool**: External tool for batch file identification
- **Why**: Comprehensive format detection
- **Implementation**: Command-line wrapper
- **Dependencies**: External tool, Java-based

#### **Best Choice for Your Project:**
**Use `pefile` (already in requirements) + enhance with `lief` for ELF support**

---

## Implementation Priority

### Phase 1: Quick Wins (High Priority)
1. **Add entropy calculation** - Simple Python function
2. **Use `pefile` for PE analysis** - Already in requirements, just need to use it
3. **Add UPX detection** - Check section names, entry point
4. **Add UPX unpacking** - Simple subprocess call

### Phase 2: Enhanced Detection (Medium Priority)
5. **YARA rules for packers** - Leverage existing `yara-python`
6. **PE section analysis** - Use `pefile` to detect suspicious sections
7. **ELF support** - Add `lief` for Linux binary analysis

### Phase 3: Advanced Features (Low Priority)
8. **Generic unpacking** - Dynamic analysis approach
9. **DiE integration** - External tool wrapper
10. **Ghidra unpacking scripts** - Extend existing Ghidra integration

---

## Recommended Dependencies to Add

```txt
# Add to requirements.txt:
scipy>=1.9.0          # For entropy calculation (or use numpy)
lief>=0.13.0           # For ELF/Mach-O analysis (cross-platform)
```

**Optional (external tools):**
- UPX binary (download separately)
- Detect It Easy (DiE) - download separately

---

## Code Structure Recommendation

```
pipeline/
├── packing.py          # NEW: Packing detection (entropy, signatures)
├── unpacking.py        # NEW: Unpacking logic (UPX, generic)
├── pe_analysis.py      # NEW: Detailed PE analysis using pefile
└── static_analysis.py # ENHANCE: Add packing detection calls
```

---

## Example Implementation Snippets

### Entropy Calculation
```python
import math
from collections import Counter

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy
```

### UPX Detection (using pefile)
```python
import pefile

def detect_upx(pe_path: str) -> bool:
    try:
        pe = pefile.PE(pe_path)
        for section in pe.sections:
            if b'UPX' in section.Name:
                return True
        # Check entry point characteristics
        if pe.OPTIONAL_HEADER.AddressOfEntryPoint < 0x1000:
            # Suspicious entry point
            return True
    except:
        pass
    return False
```

### UPX Unpacking
```python
import subprocess
import os

def unpack_upx(packed_file: str, output_file: str) -> bool:
    try:
        result = subprocess.run(
            ['upx', '-d', packed_file, '-o', output_file],
            capture_output=True,
            timeout=60
        )
        return result.returncode == 0 and os.path.exists(output_file)
    except:
        return False
```

---

## Integration Points

1. **In `static_analysis.py`**:
   - Add `detect_packing()` function
   - Add entropy to `compute_hashes_and_metadata()`
   - Add packer detection results to static artifacts

2. **In `orchestrator.py`**:
   - After static analysis, check for packed files
   - Attempt unpacking if detected
   - Re-analyze unpacked files

3. **In `compute_hashes_and_metadata()`**:
   - Add `entropy` field
   - Add `is_packed` field
   - Add `packer_type` field (if detected)

---

## Next Steps

1. ✅ Review this plan
2. Implement Phase 1 (entropy + pefile + UPX)
3. Test with sample packed/unpacked binaries
4. Integrate into existing pipeline
5. Add to static analysis output

