# Multi-Packer Unpacking Support

## Overview

The pipeline now supports **automatic unpacking** for multiple packer types using various tools and methods.

## Supported Packers & Methods

### ✅ Automatic Unpacking (Command-Line Tools)

| Packer | Tool | Method | Status |
|--------|------|--------|--------|
| **UPX** | `upx.exe` | Command-line | ✅ Fully Supported |

### ✅ Automatic Unpacking (Unipacker - Python Library)

| Packer | Tool | Method | Status |
|--------|------|--------|--------|
| **UPX** | Unipacker | Python API | ✅ Supported |
| **ASPack** | Unipacker | Python API | ✅ Supported |
| **FSG** | Unipacker | Python API | ✅ Supported |
| **MEW** | Unipacker | Python API | ✅ Supported |
| **MPRESS** | Unipacker | Python API | ✅ Supported |
| **PEtite** | Unipacker | Python API | ✅ Supported |
| **YZPack** | Unipacker | Python API | ✅ Supported |

### 📋 Manual Unpacking (Guidance Provided)

| Packer | Difficulty | Method |
|--------|-----------|--------|
| **Armadillo** | High | Manual (debugger required) |
| **VMProtect** | Very High | Manual (advanced techniques) |
| **Themida** | Very High | Manual (specialized tools) |
| **Enigma** | High | Manual (debugger required) |
| **Obsidium** | High | Manual (specialized tools) |
| **PECompact** | Medium | Manual (tools or debugger) |

---

## Installation

### UPX (Command-Line Tool)

1. **Download**: https://upx.github.io/
2. **Extract** `upx.exe` to:
   - Project `tools/` directory, OR
   - Add to system PATH

### Unipacker (Python Library)

**Install via pip:**
```bash
pip install unipacker
```

**Or add to requirements.txt:**
```txt
unipacker
```

**Note**: Unipacker is optional but highly recommended for multi-packer support.

---

## How It Works

### Detection → Unpacking Attempt → Guidance

1. **Detection**: Packer is detected via YARA rules or PE analysis
2. **Automatic Attempt**: 
   - First tries Unipacker (if packer is supported and library is installed)
   - Falls back to command-line tools (e.g., UPX)
   - If both fail, provides manual guidance
3. **Guidance**: For packers requiring manual unpacking, detailed instructions are provided

### Priority Order

1. **Unipacker** (if packer is supported and library installed)
2. **Command-line tools** (e.g., UPX for UPX-packed files)
3. **Manual guidance** (for complex packers)

---

## Example Usage

### Automatic Unpacking (UPX)

```python
# If UPX tool is installed, unpacking happens automatically
# Result:
{
    "success": true,
    "unpacked_path": "sample.unpacked.exe",
    "packer_type": "UPX",
    "unpacking_method": "command_line"
}
```

### Automatic Unpacking (Unipacker)

```python
# If Unipacker is installed and packer is supported
# Result:
{
    "success": true,
    "unpacked_path": "sample.unpacked_ASPack.exe",
    "packer_type": "ASPack",
    "unpacking_method": "python_unipacker"
}
```

### Manual Unpacking (Armadillo)

```python
# For packers requiring manual unpacking
# Result:
{
    "success": false,
    "unpacking_method": "manual",
    "error": "Armadillo requires manual unpacking. See guidance for instructions.",
    "guidance": "**Armadillo Unpacking Guide:**\n\n1. Tools Required:\n   ...",
    "difficulty": "High"
}
```

---

## Unipacker Details

### What is Unipacker?

Unipacker is an **automatic, platform-independent unpacker** for Windows binaries that uses emulation to handle various packers.

### Supported Packers (via Unipacker)

- ✅ UPX
- ✅ ASPack
- ✅ FSG
- ✅ MEW
- ✅ MPRESS
- ✅ PEtite
- ✅ YZPack

### Installation

```bash
pip install unipacker
```

### Usage in Pipeline

The pipeline automatically detects if Unipacker is installed and uses it for supported packers. No manual configuration needed!

---

## Adding New Packers

To add support for a new packer:

1. **Add to `UNPACKER_TOOLS`** in `pipeline/unpacking_extended.py`:
   ```python
   "NewPacker": {
       "tool": "tool_name",
       "method": "command_line" or "python_unipacker" or "manual",
       "command": ["tool", "args"],
       "description": "Description",
       "unipacker_supported": True/False
   }
   ```

2. **Add guidance** in `get_unpacking_guidance()` function

3. **Add YARA rule** in `yara_rules/packers.yar` (if applicable)

---

## Troubleshooting

### "Unipacker library not installed"
- **Solution**: Install with `pip install unipacker`
- **Note**: Pipeline will still work, but won't use Unipacker for supported packers

### "UPX executable not found"
- **Solution**: Download UPX and place `upx.exe` in project directory or add to PATH
- **Note**: Only affects UPX-packed files

### Unpacking Fails
- Check that the file is actually packed with the detected packer
- Some packers have multiple versions - older/newer versions may not be supported
- Try manual unpacking if automatic methods fail

---

## Benefits

✅ **Multi-tool support**: Uses best available tool for each packer  
✅ **Automatic fallback**: Tries multiple methods before giving up  
✅ **Comprehensive guidance**: Provides manual instructions when needed  
✅ **Easy installation**: Simple pip install for Unipacker  
✅ **Extensible**: Easy to add new packers and tools  

---

## Next Steps

1. **Install Unipacker**: `pip install unipacker`
2. **Install UPX**: Download from https://upx.github.io/
3. **Test**: Run pipeline on packed samples
4. **Review**: Check unpacking results in Step 1 output

The pipeline now provides comprehensive unpacking support for multiple packer types!

