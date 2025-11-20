# How Armadillo Was Detected

## Detection Method

Armadillo was detected using a **multi-layered approach**:

### 1. **YARA Rule Detection** (Primary Method - Most Reliable)
- **Location**: `yara_rules/packers.yar` (lines 169-180)
- **Rule**: `Armadillo_Protector`
- **Detection Strings**:
  - `"Armadillo"` (ASCII string)
  - `".tls"` (TLS section - Armadillo often uses TLS sections)
- **How it works**:
  1. YARA scans the entire file for these signature strings
  2. If found, it matches the `Armadillo_Protector` rule
  3. Returns packer type: "Armadillo" with severity "high"
- **Result**: ✅ **Detected** - "YARA: Detects Armadillo protector"

### 2. **PE Section Analysis** (Secondary Method)
- **Location**: `pipeline/pe_analysis.py`
- **How it works**:
  1. Analyzes PE file sections
  2. Checks for writable executable sections (common in packers)
  3. Found: `.text` section is writable and executable
- **Result**: ✅ **Detected** - "Writable executable section: .text"

### 3. **Entropy Analysis** (Supporting Evidence)
- **Entropy**: 6.22 (moderate)
- **Threshold**: 7.0 (high entropy indicator)
- **Note**: Armadillo doesn't always have very high entropy, so this was supporting evidence

## Detection Confidence: **HIGH**

The combination of:
- ✅ YARA rule match (most reliable)
- ✅ PE section characteristics (writable executable section)
- ✅ Moderate entropy

Resulted in **high confidence** detection of Armadillo protector.

---

## Why Armadillo is Hard to Unpack

Armadillo is a **commercial protector** (not just a packer), which means:
- Uses anti-debugging techniques
- Employs code obfuscation
- Has multiple protection layers
- Requires specialized tools or manual unpacking
- No simple command-line tool available

This is why automatic unpacking failed - Armadillo requires advanced techniques beyond simple unpacking tools.

