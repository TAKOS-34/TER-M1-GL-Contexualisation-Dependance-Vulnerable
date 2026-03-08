import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.IMethod;
import com.ibm.wala.ipa.callgraph.*;
import com.ibm.wala.ipa.callgraph.impl.AllApplicationEntrypoints;
import com.ibm.wala.ipa.callgraph.impl.DefaultEntrypoint;
import com.ibm.wala.ipa.callgraph.impl.Util;
import com.ibm.wala.ipa.cha.ClassHierarchy;
import com.ibm.wala.ipa.cha.ClassHierarchyFactory;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import com.ibm.wala.types.ClassLoaderReference;
import com.ibm.wala.util.MonitorUtil;
import com.ibm.wala.util.collections.HashSetFactory;
import com.ibm.wala.core.util.config.AnalysisScopeReader;
import com.ibm.wala.classLoader.Language;

import java.io.*;
import java.util.HashSet;
import java.util.Iterator;

import static com.ibm.wala.ipa.callgraph.impl.Util.makeMainEntrypoints;



public class CallGraphConstructor {
    private static boolean isExclude(String name) {
        String excludes[] = { "java.", "com.sun.", "sun.", "com.ibm.wala" };
        for (int i = 0; i < excludes.length; ++i) {
            if (name.startsWith(excludes[i])) {
                return true;
            }
        }
        return false;
    }

    private static Iterable<Entrypoint> makeMainEntrypoints(ClassLoaderReference clr, IClassHierarchy cha) {
        if (cha == null) {
            throw new IllegalArgumentException("cha is null");
        }
        final HashSet<Entrypoint> result = HashSetFactory.make();
        PrintWriter writer;
        try {
            writer = new PrintWriter("entry_points.txt", "UTF-8");

            for (IClass klass : cha) {
                if (klass.getClassLoader().getReference().equals(clr)) {
                    for(IMethod m : klass.getAllMethods()) {
                        if(!m.isAbstract() && !m.isPrivate() && !isExclude(m.getSignature())) {
                            writer.println(m.getSignature());
                            result.add(new DefaultEntrypoint(m, cha));
                        }

                    }
                }
            }

            writer.close();
            return result::iterator;
        } catch (FileNotFoundException | UnsupportedEncodingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) throws Exception {
        // Create an analysis scope with all class files in a directory
        String classPath = "C:\\Users\\DELL\\IdeaProjects\\Pradeo-Analyser\\out\\production\\Pradeo-Analyser\\main.class";  // Adjust to your project path
        AnalysisScope scope = AnalysisScopeReader.instance.makeJavaBinaryAnalysisScope(classPath, null);

        // Build the class hierarchy
        ClassHierarchy cha = ClassHierarchyFactory.make(scope);
        Iterable<Entrypoint> entryPoint = new AllApplicationEntrypoints(scope,cha);
        Iterable<Entrypoint> entryPoints = makeMainEntrypoints(scope.getApplicationLoader(), cha);
        // Define analysis options
        AnalysisOptions options = new AnalysisOptions(scope, entryPoint);
        //options.setEntrypoints(entryPoint);
        AnalysisCache cache = new AnalysisCacheImpl();
        System.out.println(options);
        System.out.println(entryPoints);
        System.out.println(entryPoint);



        // Create and build the call graph
        CallGraphBuilder<?> builder = Util.makeZeroCFABuilder(

                Language.JAVA, // Specify language
                options,
                cache,
                cha

        );
        System.out.println("1");
        CallGraph callGraph = builder.makeCallGraph(options, null);
        System.out.println("2");

        // Output call graph details, filtering by application loader
        try (FileWriter fw = new FileWriter("call_graph.dot")) {
            fw.write("digraph CallGraph {\n");
            callGraph.forEach(node -> {
                IMethod method = node.getMethod();
                if (!scope.isApplicationLoader(method.getDeclaringClass().getClassLoader())) {
                    return;  // Skip non-application classes
                }
                for (Iterator<CGNode> it = callGraph.getSuccNodes(node); it.hasNext(); ) {
                    CGNode succNode = it.next();
                    IMethod succMethod = succNode.getMethod();
                    if (scope.isApplicationLoader(succMethod.getDeclaringClass().getClassLoader())) {
                        try {
                            fw.write("\"" + method.getSignature() + "\" -> \"" + succMethod.getSignature() + "\";\n");
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    }
                }
            });
            fw.write("}\n");
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Output call graph details, filtering by application loader

        callGraph.forEach(node -> {
            IMethod method = node.getMethod();
            if (!scope.isApplicationLoader(method.getDeclaringClass().getClassLoader())) {
                return;  // Skip non-application classes
            }
            System.out.println("Method: " + method.getSignature());
        });
    }
}
