import org.eclipse.jdt.core.dom.AST;
import org.eclipse.jdt.core.dom.ASTParser;
import org.eclipse.jdt.core.dom.CompilationUnit;
import org.eclipse.jdt.core.dom.ASTVisitor;
import org.eclipse.jdt.core.dom.MethodDeclaration;


public class call {
    public static void main(String[] args) {
        // The Java source code to be parsed
        String source = "public class HelloWorld { " +
                "public static void main(String[] args) { " +
                "System.out.println(\"Hello, world!\"); " +
                "} " +
                "}";

        // Create the AST parser
        ASTParser parser = ASTParser.newParser(AST.JLS8); // or AST.JLS_Latest for the latest version
        parser.setSource(source.toCharArray());
        parser.setKind(ASTParser.K_COMPILATION_UNIT);

        // Parse the source code and obtain the compilation unit
        CompilationUnit cu = (CompilationUnit) parser.createAST(null);

        // Visit the nodes in the AST
        cu.accept(new ASTVisitor() {
            @Override
            public boolean visit(MethodDeclaration node) {
                System.out.println("Method name: " + node.getName());
                return super.visit(node);
            }
        });
    }
}
