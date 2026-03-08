import org.graphstream.graph.*;
import org.graphstream.graph.implementations.*;

public class test {
    public static void main(String[] args) {
        System.setProperty("org.graphstream.ui", "swing");

        // Create a graph
        Graph graph = new SingleGraph("Dependency Graph");

        // Add central project node
        Node projectNode = graph.addNode("Project");
        projectNode.setAttribute("ui.style", "fill-color: blue; size: 40px; text-size: 17px;");
        projectNode.setAttribute("label", "Analyzed Project");
        projectNode.setAttribute("weight", 5.0);

        // Add transitive dependency nodes
        Node transitiveDep1 = graph.addNode("Dep1");
        transitiveDep1.setAttribute("ui.style", "fill-color: green; size: 30px; text-size: 17px;");
        transitiveDep1.setAttribute("label", "Transitive Dep 1");
        transitiveDep1.setAttribute("weight", 3.0);

        Node transitiveDep2 = graph.addNode("Dep2");
        transitiveDep2.setAttribute("ui.style", "fill-color: green; size: 30px; text-size: 17px;");
        transitiveDep2.setAttribute("label", "Transitive Dep 2");
        transitiveDep2.setAttribute("weight", 3.0);

        Node transitiveDep3 = graph.addNode("Dep3");
        transitiveDep3.setAttribute("ui.style", "fill-color: green; size: 30px; text-size: 17px;");
        transitiveDep3.setAttribute("label", "Transitive Dep 3");
        transitiveDep3.setAttribute("weight", 3.0);

        Node transitiveDep4 = graph.addNode("Dep4");
        transitiveDep4.setAttribute("ui.style", "fill-color: green; size: 30px; text-size: 17px;");
        transitiveDep4.setAttribute("label", "Transitive Dep 4");
        transitiveDep4.setAttribute("weight", 3.0);

        // Add vulnerability nodes
        Node vulnerability1 = graph.addNode("Vuln1");
        vulnerability1.setAttribute("ui.style", "fill-color: red; size: 20px; text-size: 17px;");
        vulnerability1.setAttribute("label", "Vulnerability 1");
        vulnerability1.setAttribute("severity", "high");

        Node vulnerability2 = graph.addNode("Vuln2");
        vulnerability2.setAttribute("ui.style", "fill-color: orange; size: 20px; text-size: 17px;");
        vulnerability2.setAttribute("label", "Vulnerability 2");
        vulnerability2.setAttribute("severity", "medium");

        Node vulnerability3 = graph.addNode("Vuln3");
        vulnerability3.setAttribute("ui.style", "fill-color: yellow; size: 20px; text-size: 17px;");
        vulnerability3.setAttribute("label", "Vulnerability 3");
        vulnerability3.setAttribute("severity", "low");

        // Add edges between project and dependencies
        graph.addEdge("ProjectDep1", "Project", "Dep1");
        graph.addEdge("ProjectDep2", "Project", "Dep2");
        graph.addEdge("ProjectDep3", "Project", "Dep3");
        graph.addEdge("ProjectDep4", "Project", "Dep4");

        // Add edges between dependencies and vulnerabilities
        graph.addEdge("Dep1Vuln1", "Dep1", "Vuln1");
        graph.addEdge("Dep2Vuln2", "Dep2", "Vuln2");
        graph.addEdge("Dep3Vuln3", "Dep2", "Vuln3");

        // Display the graph
        graph.display();
    }
}
