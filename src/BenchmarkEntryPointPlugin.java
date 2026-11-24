package cs6215;

import java.util.List;

import pascal.taie.analysis.pta.core.heap.Descriptor;
import pascal.taie.analysis.pta.core.heap.HeapModel;
import pascal.taie.analysis.pta.core.heap.Obj;
import pascal.taie.analysis.pta.core.solver.EntryPoint;
import pascal.taie.analysis.pta.core.solver.Solver;
import pascal.taie.analysis.pta.core.solver.SpecifiedParamProvider;
import pascal.taie.analysis.pta.plugin.Plugin;
import pascal.taie.language.classes.ClassHierarchy;
import pascal.taie.language.classes.JClass;
import pascal.taie.language.classes.JMethod;

/**
 * Tai-e entry-point plugin for OWASP BenchmarkJava servlets.
 *
 * <p>Benchmark test cases are {@code HttpServlet} subclasses whose
 * entry points are {@code doGet}/{@code doPost}; they have no
 * {@code main()} method, and Tai-e's built-in entry-point handling
 * only adds the program's {@code main} plus JVM-internal implicit
 * entries (see {@code pascal.taie.analysis.pta.plugin.EntryPointHandler}).
 * This plugin adds {@code doGet} and {@code doPost} of every
 * {@code HttpServlet} subclass present in the analysed world as entry
 * points, so a run scoped with {@code --input-classes
 * org.owasp.benchmark.testcode.BenchmarkTestXXXXX} analyses exactly
 * that test case.
 *
 * <p>Why {@link SpecifiedParamProvider} and not the simpler
 * {@code DeclaredParamProvider} (as in Tai-e's own
 * {@code CustomEntryPointPlugin} test)? {@code DeclaredParamProvider}
 * ignores non-instantiable types
 * ({@code DeclaredParamProvider.isInstantiable}: abstract classes are
 * skipped), and both servlet parameters are interfaces
 * ({@code HttpServletRequest}, {@code HttpServletResponse}), so it
 * would create <i>no</i> objects for {@code request}/{@code response}
 * and every call on them would silently stay unresolved. The builder
 * below creates the mock objects explicitly via
 * {@code HeapModel.getMockObj}, which imposes no instantiability
 * check.
 *
 * <p>Why this works even though the mock {@code request} object is
 * interface-typed (so virtual dispatch on it finds no concrete
 * callee): the taint configuration runs in call-site mode
 * ({@code call-site-mode: true} in {@code configs/taint-config.yml}),
 * where sources, sinks and transfers fire from the method reference
 * at the call site in a reachable method, without needing a resolved
 * call edge (see {@code SourceHandler}, {@code SinkHandler} and
 * {@code TransferHandler} in Tai-e 0.5.5-SNAPSHOT, commit
 * {@code 407994d}). Reachability of {@code doGet}/{@code doPost} is
 * all the plugin has to supply.
 *
 * <p>Compile against the Tai-e release jar (no Tai-e source build
 * needed) and load it with the {@code plugins:} pta option; see
 * {@code PILOT.md}. The plugin class must be on the JVM classpath
 * when Tai-e starts, i.e. run Tai-e as
 * {@code java -cp tai-e-all-0.5.4.jar:&lt;plugin-classes&gt;
 * pascal.taie.Main ...} instead of {@code java -jar ...}
 * ({@code java -jar} ignores {@code -cp}, so {@code Class.forName}
 * in {@code PointerAnalysis.addPlugins} would not find it).
 */
public class BenchmarkEntryPointPlugin implements Plugin {

    private Solver solver;

    private ClassHierarchy hierarchy;

    private HeapModel heapModel;

    @Override
    public void setSolver(Solver solver) {
        this.solver = solver;
        this.hierarchy = solver.getHierarchy();
        this.heapModel = solver.getHeapModel();
    }

    @Override
    public void onStart() {
        JClass httpServlet = hierarchy.getClass("javax.servlet.http.HttpServlet");
        if (httpServlet == null) {
            return;
        }
        for (JClass testClass : hierarchy.getAllSubclassesOf(httpServlet)) {
            if (testClass.isAbstract()) {
                continue;
            }
            String onlyClass = System.getenv("CS6215_ENTRY_CLASS");
            if (onlyClass != null && !onlyClass.isEmpty()
                    && !testClass.getName().equals(onlyClass)) {
                continue;
            }
            for (String name : List.of("doGet", "doPost")) {
                JMethod entry = testClass.getDeclaredMethod(name);
                if (entry == null) {
                    continue;
                }
                SpecifiedParamProvider.Builder builder =
                        new SpecifiedParamProvider.Builder(entry);
                Obj thisObj = heapModel.getMockObj(
                        Descriptor.ENTRY_DESC, "MethodParam{this}",
                        testClass.getType(), entry);
                builder.addThisObj(thisObj);
                for (int i = 0; i < entry.getParamCount(); ++i) {
                    Obj paramObj = heapModel.getMockObj(
                            Descriptor.ENTRY_DESC, "MethodParam{" + i + "}",
                            entry.getParamType(i), entry);
                    builder.addParamObj(i, paramObj);
                }
                solver.addEntryPoint(new EntryPoint(entry, builder.build()));
            }
        }
    }
}
