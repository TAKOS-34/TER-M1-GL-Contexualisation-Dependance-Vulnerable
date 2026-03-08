import org.eclipse.jdt.core.dom.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.stream.Collectors;

public class AstExtractor {

    public static void main(String[] args) {
        String projectPath = "C:\\Users\\DELL\\IdeaProjects\\Pradeo-Analyser";
        try {
            Files.walk(Paths.get(projectPath))
                    .filter(Files::isRegularFile)
                    .filter(path -> path.toString().endsWith(".java"))
                    .forEach(path -> {
                        try {
                            String source = Files.lines(path, StandardCharsets.UTF_8)
                                    .collect(Collectors.joining("\n"));
                            parseAndPrintAST(source);
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    });
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void parseAndPrintAST(String source) {
        ASTParser parser = ASTParser.newParser(AST.JLS8);
        parser.setSource(source.toCharArray());
        parser.setKind(ASTParser.K_COMPILATION_UNIT);
        CompilationUnit cu = (CompilationUnit) parser.createAST(null);

        cu.accept(new ASTVisitor() {
            @Override
            public boolean visit(TypeDeclaration node) {
                System.out.println("Class: " + node.getName());
                return super.visit(node);
            }

            @Override
            public boolean visit(MethodDeclaration node) {
                System.out.println("Method: " + node.getName());
                return super.visit(node);
            }

            @Override
            public boolean visit(FieldDeclaration node) {
                System.out.println("Field: " + node.fragments().toString());
                return super.visit(node);
            }
        });
    }
}
