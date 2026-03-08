package Services;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.io.IOException;



public class CveService {


    public static String fetchDataFromApi(String url) {
        // Create an instance of HttpClient
        HttpClient client = HttpClient.newHttpClient();

        // Create a GET request to the FastAPI endpoint
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .build();

        // Send the request and handle the response
        try {
            System.out.println(1);
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
           System.out.println(2);
            // Print the response status code
            System.out.println("Response code: " + response.statusCode());

            // Return the response body
            return response.body();
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }

        // Return null if an error occurs
        return null;
    }
}
