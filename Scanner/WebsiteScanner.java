import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class WebsiteScanner {

    // Function to check if HTTPS is used
    public static boolean isUsingHTTPS(String url) {
        return url.startsWith("https://");
    }

    // Function to send an HTTP request and get the response headers
    public static HttpURLConnection sendRequest(String urlString) throws Exception {
        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(20000); // 5 seconds timeout
        connection.setReadTimeout(20000);
        connection.connect();
        return connection;
    }

    // Function to check if a security header is present
    public static boolean hasSecurityHeader(HttpURLConnection connection, String headerName) {
        return connection.getHeaderField(headerName) != null;
    }

    // Function to simulate a basic SQL Injection check
    public static boolean detectSQLInjection(String url) {
        String injectionUrl = url + "?id=1' OR '1'='1";
        try {
            HttpURLConnection connection = sendRequest(injectionUrl);
            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String inputLine;
            StringBuilder content = new StringBuilder();
            while ((inputLine = in.readLine()) != null) {
                content.append(inputLine);
            }
            in.close();

            // Check if the response contains SQL errors
            if (content.toString().toLowerCase().contains("sql syntax") || content.toString().toLowerCase().contains("mysql")) {
                return true; // Potential SQL Injection found
            }
        } catch (Exception e) {
            System.out.println("Error detecting SQL Injection: " + e.getMessage());
        }
        return false;
    }

    // Function to simulate a basic XSS check
    public static boolean detectXSS(String url) { 

        
        String filePath = "wordlist.txt";

        // Create a list to store the words
        List<String> words = new ArrayList<>();

        // Try-with-resources to automatically close the BufferedReader
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            // Read the file line by line
            while ((line = br.readLine()) != null) {
                words.add(line); // Add each word to the list
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        for (String word : words) {
        String xssUrl = url + word;
        try {
            HttpURLConnection connection = sendRequest(xssUrl);
            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String inputLine;
            StringBuilder content = new StringBuilder();
            while ((inputLine = in.readLine()) != null) {
                content.append(inputLine);
            }
            in.close();

            // Check if the response contains the XSS payload without sanitization
            if (content.toString().contains("<script>alert('XSS')</script>")) {
                return true; // Potential XSS vulnerability found
            }
        } catch (Exception e) {
            System.out.println("Error detecting XSS: " + e.getMessage());
        }
    }
        return false;
    }

    // Main function to scan the website for vulnerabilities
    public static void scanWebsite(String url) {
        System.out.println("\n" + "Scanning website: " + url);

        // Check if the site is using HTTPS
        if (isUsingHTTPS(url)) {
            System.out.println("The website is using HTTPS.");
        } else {
            System.out.println("The website is NOT using HTTPS. This is a potential vulnerability.");
        }

        try {
            // Send request to the website
            HttpURLConnection connection = sendRequest(url);

            // Check for security headers
            if (hasSecurityHeader(connection, "Content-Security-Policy")) {
                System.out.println("Content-Security-Policy header is present.");
            } else {
                System.out.println("Content-Security-Policy header is missing. This is a potential vulnerability.");
            }

            if (hasSecurityHeader(connection, "X-XSS-Protection")) {
                System.out.println("X-XSS-Protection header is present.");
            } else {
                System.out.println("X-XSS-Protection header is missing. This is a potential vulnerability.");
            }

            // SQL Injection Check
            if (detectSQLInjection(url)) {
                System.out.println("Potential SQL Injection vulnerability detected!");
            } else {
                System.out.println("No SQL Injection vulnerabilities found.");
            }

            // XSS Check
            if (detectXSS(url)) {
                System.out.println("Potential XSS vulnerability detected!");
            } else {
                System.out.println("No XSS vulnerabilities found.");
            }

        } catch (Exception e) {
            System.out.println("Error scanning website: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        
        Scanner scan = new Scanner(System.in);
        System.out.println("Enter Website to scan: ");

        String websiteUrl = scan.nextLine();
        scanWebsite(websiteUrl);
    }
}


