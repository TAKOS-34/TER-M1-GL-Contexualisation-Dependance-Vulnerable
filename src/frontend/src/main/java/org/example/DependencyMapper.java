package org.example;

import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.resolution.TypeSolver;
import com.github.javaparser.resolution.types.ResolvedType;
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.JavaParserTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DependencyMapper {

    public static void main(String[] args) throws Exception {
        String fixcommit = "@@ -1,7 +1,8 @@\n" +
                " import java.time.LocalDateTime;\n" +
                " import java.time.format.DateTimeFormatter;\n" +
                " import java.time.format.DateTimeParseException;\n" +
                " \n" +
                " +#define FORMAT_PATTERN \"yyyy/MM/dd HH:mm:ss\"\n" +
                " \n" +
                " @Override\n" +
                " public String formatDateTime(LocalDateTime now) {\n" +
                " -    DateTimeFormatter dtf = DateTimeFormatter.ofPattern(\"yyyy/MM/dd HH:mm:ss\");\n" +
                " +    DateTimeFormatter dtf = DateTimeFormatter.ofPattern(FORMAT_PATTERN);\n" +
                "     try {\n" +
                " -        return dtf.format(now);  // This might be your vulnerable line\n" +
                " +        return dtf.format(now);\n" +
                "     } catch (DateTimeParseException e) {\n" +
                "         // Handle exception or provide a fallback\n" +
                "         return \"Invalid date format\";\n" +
                "     }\n" +
                " }";
        File projectDir = new File("C:\\Users\\ellio\\Desktop\\projet_java_test");

        // Extract deleted code from fix commit
        List<String> deletedCodeFragments = extractDeletedCode(fixcommit);
        System.out.println(deletedCodeFragments);

        // Set up the type solver
        CombinedTypeSolver typeSolver = new CombinedTypeSolver();
        typeSolver.add(new ReflectionTypeSolver());
        typeSolver.add(new JavaParserTypeSolver(projectDir));

        // Configure JavaParser to use symbol solver
        JavaSymbolSolver symbolSolver = new JavaSymbolSolver(typeSolver);
        
        // Create a configuration and set the symbol resolver
        ParserConfiguration config = new ParserConfiguration();
        config.setSymbolResolver(symbolSolver);
        StaticJavaParser.setConfiguration(config);

        // Parse files in the project directory and compare with deleted code fragments
        processDirectory(projectDir, typeSolver, deletedCodeFragments);
    }

    private static List<String> extractDeletedCode(String fixCommit) {
        List<String> deletedCodeFragments = new ArrayList<>();

        // Print the input to verify its format
        System.out.println("Fix Commit:");
        System.out.println(fixCommit);

        // Regex pattern to match lines that start with space followed by '-'
        Pattern linePattern = Pattern.compile("^\\s*-.*$", Pattern.MULTILINE);
        Matcher lineMatcher = linePattern.matcher(fixCommit);

        while (lineMatcher.find()) {
            String line = lineMatcher.group().trim();
            if (!line.isEmpty()) {
                // Remove the leading spaces and '-' character
                String deletedLine = line.substring(line.indexOf('-') + 1).trim();
                if (!deletedLine.isEmpty()) {
                    deletedCodeFragments.add(deletedLine);
                }
            }
        }

        return deletedCodeFragments;
    }



    private static void processDirectory(File directory, TypeSolver typeSolver, List<String> deletedCodeFragments) throws Exception {
        for (File file : directory.listFiles()) {
            if (file.isDirectory()) {
                processDirectory(file, typeSolver, deletedCodeFragments);
            } else if (file.getName().endsWith(".java")) {
                processFile(file, typeSolver, deletedCodeFragments);
            }
        }
    }

    private static void processFile(File file, TypeSolver typeSolver, List<String> deletedCodeFragments) throws Exception {
        CompilationUnit cu = StaticJavaParser.parse(file);

        cu.findAll(ClassOrInterfaceDeclaration.class).forEach(clazz -> {
            System.out.println("Class: " + clazz.getName());

            // Process Methods
            clazz.findAll(MethodDeclaration.class).forEach(method -> {
                System.out.println("  Method: " + method.getName());

                try {
                    // Resolve Method Return Type
                    ResolvedType returnType = method.getType().resolve();
                    System.out.println("    Return Type: " + returnType.describe());
                } catch (RuntimeException e) {
                    System.err.println("    Unresolved Return Type: " + method.getType() + " - " + e.getMessage());
                }

                // Process Variables within the method
                method.findAll(VariableDeclarator.class).forEach(variable -> {
                    System.out.println("    Variable: " + variable.getName());

                    try {
                        // Resolve Variable Type
                        ResolvedType variableType = variable.getType().resolve();
                        System.out.println("      Type: " + variableType.describe());
                    } catch (RuntimeException e) {
                        System.err.println("      Unresolved Variable Type: " + variable.getType() + " - " + e.getMessage());
                    }
                });

                // Process Method Calls within the method
                method.findAll(MethodCallExpr.class).forEach(methodCall -> {
                    System.out.println("    Method Call: " + methodCall.getName());

                    try {
                        // Resolve the called method's return type
                        ResolvedType methodCallReturnType = methodCall.calculateResolvedType();
                        System.out.println("      Call Return Type: " + methodCallReturnType.describe());
                    } catch (RuntimeException e) {
                        System.err.println("      Unresolved Method Call Return Type: " + methodCall + " - " + e.getMessage());
                    }

                    // Resolve the type of the scope of the method call (i.e., what object the method is called on)
                    methodCall.getScope().ifPresent(scope -> {
                        try {
                            ResolvedType scopeType = scope.calculateResolvedType();
                            System.out.println("      Scope Type: " + scopeType.describe());
                        } catch (RuntimeException e) {
                            System.err.println("      Unresolved Scope Type: " + scope + " - " + e.getMessage());
                        }
                    });
                });

                // Check for vulnerable nodes in the method body
                checkForVulnerableNodes(method, deletedCodeFragments);
                System.out.println("hhh");
            });
        });
    }

    private static void checkForVulnerableNodes(MethodDeclaration method, List<String> deletedCodeFragments) {
        String methodBody = method.getBody().map(body -> body.toString()).orElse("");

        deletedCodeFragments.forEach(fragment -> {
            // Calculate the match percentage
            double matchPercentage = calculateMatchPercentage(methodBody, fragment);

            // If more than 60% of the fragment is found in the method body, consider it vulnerable
            if (matchPercentage >= 80.0) {
                System.out.println("    Vulnerable Node Detected in Method: " + method.getName());
                System.out.println("    Deleted Code Fragment: " + fragment);
                System.out.println("    Match Percentage: " + matchPercentage + "%");
            }
        });
    }

    private static double calculateMatchPercentage(String methodBody, String fragment) {
        // Split the fragment into words
        String[] fragmentWords = fragment.split("\\s+");
        int totalWords = fragmentWords.length;
        int matchedWords = 0;

        // Count how many words from the fragment are present in the method body
        for (String word : fragmentWords) {
            if (methodBody.contains(word)) {
                matchedWords++;
            }
        }

        // Calculate the percentage of words that matched
        return (matchedWords / (double) totalWords) * 100;
    }

}
