// Requires: Ghidra script API (run via analyzeHeadless -postScript)
// Args: outJson=<path> maxFuncs=<n> maxPcode=<k>

import java.io.FileWriter;
import java.util.*;

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;

public class DumpArtifacts extends GhidraScript {

    private String getArg(String key, String defVal) {
        String[] args = getScriptArgs();
        if (args == null) return defVal;
        for (String a : args) {
            if (a.startsWith(key + "=")) {
                return a.substring(key.length() + 1);
            }
        }
        return defVal;
    }

    @Override
    protected void run() throws Exception {
        String outJson = getArg("outJson", null);
        if (outJson == null) {
            println("outJson arg is required");
            return;
        }
        int maxFuncs = Integer.parseInt(getArg("maxFuncs", "300"));
        int maxPcode = Integer.parseInt(getArg("maxPcode", "5"));

        Map<String, Object> root = new LinkedHashMap<>();

        Program program = currentProgram;
        if (program == null) {
            println("No current program");
            return;
        }

        root.put("language", program.getLanguageID().getIdAsString());
        root.put("compiler", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
        root.put("executableFormat", program.getExecutableFormat());

        // Imports
        List<String> imports = new ArrayList<>();
        try {
            SymbolTable symtab = program.getSymbolTable();
            SymbolIterator it = symtab.getExternalSymbols();
            while (it.hasNext()) {
                monitor.checkCancelled();
                Symbol s = it.next();
                imports.add(s.getName());
            }
        } catch (CancelledException e) {
            // ignore
        }
        root.put("imports", imports);

        // Strings
        List<Map<String, Object>> strings = new ArrayList<>();
        try {
            Listing listing = program.getListing();
            Address start = program.getMinAddress();
            Address end = program.getMaxAddress();
            CodeUnitIterator cui = listing.getCodeUnits(start, true);
            while (cui.hasNext()) {
                monitor.checkCancelled();
                CodeUnit cu = cui.next();
                if (cu instanceof Data) {
                    Data d = (Data) cu;
                    if (d.isDefined() && d.hasStringValue()) {
                        Object v = d.getValue();
                        if (v != null) {
                            Map<String, Object> entry = new LinkedHashMap<>();
                            entry.put("addr", d.getAddress().toString());
                            entry.put("value", v.toString());
                            strings.add(entry);
                        }
                    }
                }
            }
        } catch (Exception e) {
            // ignore
        }
        root.put("strings", strings);

        // Functions and pseudocode (limited)
        List<Map<String, Object>> functions = new ArrayList<>();
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(program);
        Listing listing = program.getListing();
        FunctionIterator fit = listing.getFunctions(true);
        int count = 0;
        while (fit.hasNext() && count < maxFuncs) {
            monitor.checkCancelled();
            Function f = fit.next();
            Map<String, Object> fobj = new LinkedHashMap<>();
            fobj.put("name", f.getName());
            fobj.put("entry", f.getEntryPoint().toString());
            fobj.put("size", f.getBody().getNumAddresses());
            // Decompile selected small subset
            if (count < maxPcode) {
                DecompileOptions options = new DecompileOptions();
                ifc.setOptions(options);
                DecompileResults res = ifc.decompileFunction(f, 60, monitor);
                HighFunction hf = res.getHighFunction();
                String code = res.getDecompiledFunction() != null ? res.getDecompiledFunction().getC() : null;
                if (code != null) {
                    fobj.put("pseudocode", code);
                }
            }
            functions.add(fobj);
            count++;
        }
        root.put("functions", functions);

        try (FileWriter fw = new FileWriter(outJson)) {
            fw.write(toJson(root));
        }
        println("Dumped artifacts to: " + outJson);
    }

    private String escape(String s) {
        return s
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n");
    }

    private String toJson(Object o) {
        if (o == null) return "null";
        if (o instanceof String) return "\"" + escape((String)o) + "\"";
        if (o instanceof Number || o instanceof Boolean) return o.toString();
        if (o instanceof Map) {
            StringBuilder sb = new StringBuilder();
            sb.append("{");
            boolean first = true;
            for (Object k : ((Map<?,?>)o).keySet()) {
                if (!first) sb.append(",");
                first = false;
                sb.append(toJson(k.toString()));
                sb.append(":");
                sb.append(toJson(((Map<?,?>)o).get(k)));
            }
            sb.append("}");
            return sb.toString();
        }
        if (o instanceof Iterable) {
            StringBuilder sb = new StringBuilder();
            sb.append("[");
            boolean first = true;
            for (Object el : (Iterable<?>)o) {
                if (!first) sb.append(",");
                first = false;
                sb.append(toJson(el));
            }
            sb.append("]");
            return sb.toString();
        }
        return toJson(o.toString());
    }
}


