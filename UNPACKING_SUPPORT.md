# Unpacking Support Guide

## Supported Packers

The pipeline now supports unpacking guidance for all detected packers. Automatic unpacking is available for some, while others require manual methods.

### ✅ Automatic Unpacking (Command-Line Tools)

| Packer | Tool | Status | Notes |
|--------|------|--------|-------|
| **UPX** | `upx.exe` | ✅ Fully Supported | Built-in unpacking with `upx -d` |

### 📋 Manual Unpacking (Guidance Provided)

| Packer | Difficulty | Method | Tools Required |
|--------|-----------|--------|----------------|
| **Armadillo** | High | Manual | OllyDbg/x64dbg, Armadillo Find Protected |
| **VMProtect** | Very High | Manual | x64dbg/IDA Pro, VMProtect scripts |
| **Themida** | Very High | Manual | x64dbg, Themida unpacker scripts |
| **Enigma** | High | Manual | OllyDbg/x64dbg, Enigma scripts |
| **Obsidium** | High | Manual | x64dbg, Obsidium tools |
| **FSG** | Medium | Manual | OllyDbg/x64dbg, FSG scripts |
| **ASPack** | Medium | Manual | ASPack unpacker tools or OllyDbg |
| **PECompact** | Medium | Manual | PECompact unpacker or OllyDbg |
| **NSPack** | Medium | Manual | NSPack unpacker or OllyDbg |
| **UPack** | Medium | Manual | UPack unpacker or OllyDbg |
| **MEW** | Medium | Manual | MEW unpacker or OllyDbg |
| **Petite** | Medium | Manual | Petite unpacker or OllyDbg |
| **RLPack** | Medium | Manual | RLPack unpacker or OllyDbg |

---

## How It Works

### Detection → Unpacking Attempt → Guidance

1. **Detection**: Packer is detected via YARA rules or PE analysis
2. **Automatic Attempt**: If tool available, attempts automatic unpacking
3. **Guidance**: If automatic fails or not supported, provides manual unpacking guidance

### Output Structure

When unpacking is attempted, the result includes:

```json
{
  "success": false,
  "unpacked_path": null,
  "error": "Armadillo requires manual unpacking. See guidance for instructions.",
  "unpacking_method": "manual",
  "guidance": "**Armadillo Unpacking Guide:**\n\n1. **Tools Required:**\n   - OllyDbg or x64dbg\n   ...",
  "difficulty": "High"
}
```

---

## Armadillo Detection Explained

### How Armadillo Was Detected in Your File

**Method 1: YARA Rule** (Primary - Most Reliable)
- **Rule**: `Armadillo_Protector` in `yara_rules/packers.yar`
- **Strings Searched**:
  - `"Armadillo"` (ASCII)
  - `".tls"` (TLS section - Armadillo often uses TLS)
- **Result**: ✅ **MATCHED** - "YARA: Detects Armadillo protector"

**Method 2: PE Section Analysis** (Secondary)
- **Check**: Writable executable sections
- **Found**: `.text` section is writable and executable
- **Result**: ✅ **INDICATOR** - "Writable executable section: .text"

**Method 3: Entropy** (Supporting)
- **Entropy**: 6.22 (moderate)
- **Note**: Armadillo doesn't always have very high entropy

**Final Confidence**: **HIGH** (combination of YARA match + PE indicators)

---

## Unpacking Methods

### Automatic Unpacking (UPX)

```powershell
# UPX automatically unpacks if tool is installed
# Command: upx -d input.exe -o output.exe
```

### Manual Unpacking (All Others)

For packers like Armadillo, VMProtect, Themida, etc., the pipeline provides:
- **Detailed guidance** in the analysis results
- **Step-by-step instructions**
- **Tool recommendations**
- **Difficulty assessment**

---

## Adding New Unpackers

To add support for a new packer:

1. **Add YARA rule** in `yara_rules/packers.yar`
2. **Add to UNPACKER_TOOLS** in `pipeline/unpacking_extended.py`
3. **Add guidance** in `get_unpacking_guidance()` function

---

## Example: Armadillo Unpacking

Since Armadillo was detected in your file, here's what you'll see:

**In Step 1 Results:**
```json
{
  "unpacked": {
    "success": false,
    "error": "Armadillo requires manual unpacking. See guidance for instructions.",
    "unpacking_method": "manual",
    "guidance": "**Armadillo Unpacking Guide:**\n\n1. Tools Required:\n   - OllyDbg or x64dbg\n   ...",
    "difficulty": "High"
  }
}
```

**Guidance Provided:**
- Tools needed (OllyDbg, x64dbg, etc.)
- Step-by-step unpacking process
- Difficulty assessment
- Alternative methods

---

## Tools for Manual Unpacking

### Recommended Tools:
1. **x64dbg** - Modern debugger (recommended)
2. **OllyDbg** - Classic debugger
3. **IDA Pro** - Disassembler (commercial)
4. **Process Monitor** - For behavior analysis
5. **Import Reconstructor** - For fixing imports after dump

### Specialized Unpackers:
- **Armadillo Find Protected** - For Armadillo
- **VMProtect Unpacker** - For VMProtect (if available)
- **Themida Unpacker Scripts** - For Themida

---

## Next Steps

1. **For UPX**: Automatic unpacking works if UPX tool is installed
2. **For Others**: Review the guidance in analysis results
3. **Manual Unpacking**: Follow the step-by-step instructions provided
4. **Alternative**: Use specialized unpacking tools if available

The pipeline now provides comprehensive unpacking support and guidance for all detected packers!

