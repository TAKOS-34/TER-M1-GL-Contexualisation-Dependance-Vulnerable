package org.example;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.ConstructorDeclaration;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.type.Type;

public class AstParser {
    public static void main(String[] args) {
        String sourceCode = "\n" +
                "import java.io.BufferedReader;\n" +
                "import java.io.IOException;\n" +
                "import java.io.InputStreamReader;\n" +
                "\n" +
                "public class SbomExtractor {\n" +
                "\n" +
                "    public static void ExtractSbom(String ProjectPath , int Format) {\n" +
                "        //TIP Press <shortcut actionId=\"ShowIntentionActions\"/> with your caret at the highlighted text\n" +
                "        try {\n" +
                "            // Command to run Syft and generate SBOM\n" +
                "            String command;\n" +
                "            switch (Format) {\n" +
                "                case 1:\n" +
                "                    command = \"syft \" + ProjectPath + \" -o spdx-json=sbom.spdx.json\";\n" +
                "                    break;\n" +
                "                case 2:\n" +
                "                    command = \"syft \" + ProjectPath + \" -o cyclonedx-json=sbom.cyclonedx.json\";\n" +
                "                    break;\n" +
                "                default:\n" +
                "                    throw new IllegalArgumentException(\"Invalid format. Please provide format 1 or 2.\");\n" +
                "            }\n" +
                "\n" +
                "            // Execute command using ProcessBuilder\n" +
                "            ProcessBuilder processBuilder = new ProcessBuilder(command.split(\"\\\\s+\"));\n" +
                "            processBuilder.redirectErrorStream(true);\n" +
                "            Process process = processBuilder.start();\n" +
                "\n" +
                "\n" +
                "            // Wait for the process to complete\n" +
                "            int exitCode = process.waitFor();\n" +
                "            System.out.println(\"Syft process exited with code \" + exitCode);\n" +
                "\n" +
                "        } catch (IOException | InterruptedException e) {\n" +
                "            e.printStackTrace();\n" +
                "        }\n" +
                "\n" +
                "    }\n" +
                "\n" +
                "}\n";

        // Parse the source code
        JavaParser parser = new JavaParser();
        CompilationUnit cu = parser.parse(sourceCode).getResult().orElseThrow();

        // Visit the AST nodes
        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(ClassOrInterfaceDeclaration cid, Void arg) {
                System.out.println("Class name: " + cid.getName());
                super.visit(cid, arg);
            }

            @Override
            public void visit(MethodDeclaration md, Void arg) {
                System.out.println("Method name: " + md.getName());
                System.out.println("Return type: " + md.getType());
                super.visit(md, arg);
            }

            @Override
            public void visit(FieldDeclaration fd, Void arg) {
                System.out.println("Field type: " + fd.getVariable(0).getType());
                System.out.println("Field name: " + fd.getVariable(0).getName());
                super.visit(fd, arg);
            }

            @Override
            public void visit(ConstructorDeclaration cd, Void arg) {
                System.out.println("Constructor name: " + cd.getName());
                super.visit(cd, arg);
            }

            @Override
            public void visit(MethodCallExpr mce, Void arg) {
                System.out.println("Method call: " + mce.getName());
                super.visit(mce, arg);
            }
        }, null);
    }
}
