import Services.CveService;
import javafx.application.Application;

public class Main {
    public static void main(String[] args) {
     //String ProjectPath="C:\\Users\\ellio\\Desktop\\projet_java_test";
     //SbomExtractor.ExtractSbom(ProjectPath,2);
     //System.out.println("xx");
     //SbomExtractor.extractCpeFromCycloneDx("sbom.cyclonedx.json");
     //String url = "http://127.0.0.1:8000/config_nodes_cpe_match/?criteria=cpe:2.3:h:schneider-electric:modicon_m251:-:*:*:*:*:*:*:*";
     //System.out.println(CveService.fetchDataFromApi(url));
        Application.launch(DependencyAnalyzerApp.class, args);
    }
}