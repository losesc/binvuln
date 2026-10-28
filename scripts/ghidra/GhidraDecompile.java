import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;

public class GhidraDecompile extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) { println("no output path"); return; }
        PrintWriter out = new PrintWriter(args[0], "UTF-8");

        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);

        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            // skip library thunks / external stubs so the model sees user code
            if (f.isThunk() || f.isExternal()) continue;
            DecompileResults r = d.decompileFunction(f, 60, monitor);
            if (r != null && r.decompileCompleted()) {
                out.println(r.getDecompiledFunction().getC());
                out.println();
            }
        }
        out.close();
        println("wrote " + args[0]);
    }
}
