from flask import Flask, request, render_template_string
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

@app.route('/')
def index():
    return '''
    <html>
        <head><title>Vulnerability Test Application</title></head>
        <body>
            <h2>Vulnerability Test Application</h2>
            <p>This page is used to test for various web vulnerabilities.</p>
            <ul>
                <li><a href="/test-xss">Test for XSS</a></li>
                <li><a href="/test-clickjacking">Test for Clickjacking</a></li>
            </ul>
        </body>
    </html>
    '''

@app.route('/test-xss')
def test_xss():
    user_input = request.args.get('input', '')
    if "<script>" in user_input:
        logging.warning(f"Simulated Reflected XSS detected with input: {user_input}")
        return render_template_string(f"<html><body>Reflected XSS with input: {user_input}</body></html>")
    elif "onerror" in user_input:
        logging.warning(f"Simulated DOM-based XSS detected with input: {user_input}")
        return render_template_string(f"<html><body>DOM-based XSS with input: <img src=x {user_input}></body></html>")
    else:
        return "<html><body><p>Input received.</p></body></html>"

@app.route('/test-clickjacking')
def test_clickjacking():
    user_input = request.args.get('input', '')
    if "iframe" in user_input:
        logging.warning(f"Simulated Clickjacking detected with input: {user_input}")
        clickjacking_test_page = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Clickjacking Test Page</title>
        </head>
        <body>
            <h1>Clickjacking Test</h1>
            <p>This page simulates a Clickjacking scenario based on the input: {user_input}</p>
            <button onclick="alert('Button Clicked')">Test Button</button>
        </body>
        </html>
        '''
        return render_template_string(clickjacking_test_page)
    else:
        return "<html><body><p>Input received, no clickjacking scenario triggered.</p></body></html>"

if __name__ == "__main__":
    app.run(debug=True, port=5002)
