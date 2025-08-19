ReadMeFirst

Key files and folders you will find:

app.py: The main Flask application file containing backend logic and API endpoints.
index.html: ( Folder containing frontend assets like index.html, script.js, and style.css.
uploads/: A temporary directory created by the Flask app for file processing. (This folder should be empty or non-existent in the provided archive as files are deleted after processing).
requirements.txt: A file listing all Python dependencies required for the backend.
venv/ or .venv/: (Might be excluded for smaller archive size) The virtual environment folder.


Setup Instructions for the Recipient:
To get this project up and running on your local machine, please follow these steps:

Step 1: Extract the Archive

Unzip the SteganographyProject.zip file to a desired location on your computer.

Step 2: Create and Activate a Python Virtual Environment

-Open your Terminal or Command Prompt.
-Navigate to the extracted project directory.
-Example: cd path/to/your/extracted/Professional_Steganography_Tool
-Create a virtual environment:
    python -m venv venv (On Windows, you might use py -m venv venv)
    (You can name venv something else if you prefer, e.g., .venv)
-Activate the virtual environment:
   Windows: .\venv\Scripts\activate
   macOS/Linux: source venv/bin/activate

Step 3: Install Required Python Dependencies

With the virtual environment activated, install all necessary libraries using pip:
pip install -r requirements.txt

Step 4: Obtain a VirusTotal API Key (Optional but Recommended)

The project includes a malware scanning feature that integrates with the VirusTotal API. To use this feature, you will need your own API key. 

(Note: an API key is already included since this is a test project.) 


Sign up for a free VirusTotal account at https://www.virustotal.com/.
Once logged in, you can usually find your API key in your profile settings.
Update the API Key in the Code:
Open steganography_app.py in a text editor or VS Code.
Locate the line: VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', 'YOUR_VIRUSTOTAL_API_KEY_HERE')
For quick testing: Replace 'YOUR_VIRUSTOTAL_API_KEY_HERE' with your actual VirusTotal API key (e.g., 'VIRUSTOTAL_API_KEY = "your_actual_key_here").
Recommended (more secure): Set an environment variable named VIRUSTOTAL_API_KEY on your system. The code will then automatically pick it up. (e.g., on Linux/macOS export VIRUSTOTAL_API_KEY="your_actual_key_here", on Windows set VIRUSTOTAL_API_KEY="your_actual_key_here")

Step 5: Run the Flask Application

Ensure your virtual environment is still activated.
Run the Flask application from the project's root directory:
python app.py
The terminal will display a message indicating that the Flask server is running, usually at http://127.0.0.1:5000.

Step 6: Access the Application in Your Browser

Open your web browser.
Go to the address displayed in your terminal (e.g., http://127.0.0.1:5000).
Usage:
Once the application is running in your browser:

Text Steganography Tab:

Select a "Cover Image" (PNG recommended for best results).
Enter your "Secret Message" in the text area.
Click "Embed Text" to hide the message, or "Extract Text" to reveal it from a stego image.
Use the "Download Stego Image" button to save the result.
Click "Scan Extracted Text for Malware" after extraction to check for malicious content.

Image Steganography Tab:

Select a "Cover Image."
Select a "Secret Image to Embed" (smaller than the cover image for best results).
Click "Embed Image" or "Extract Image."
Use the "Download" buttons to save results.
Click "Scan Extracted Image for Malware" after extraction.


Important Notes:
Temporary Files: The backend creates temporary files in an uploads/ folder during processing, but these are immediately deleted after the operation completes. No persistent data is stored.

Image Formats: PNG images generally work best for LSB steganography due to their lossless compression. JPEG images can introduce artifacts that interfere with LSB.
Secret Data Capacity: The amount of secret data you can hide depends on the size and color depth of the cover image. Attempting to embed too much data will result in an error.
VirusTotal API Usage: Be mindful of VirusTotal's API rate limits if you perform many scans in a short period.

Development Server: The Flask server started by python steganography_app.py is a development server. It is not suitable for production deployment.


Troubleshooting:
"pip" or "python" command not found: Ensure Python is installed and added to your system's PATH.

Dependencies not installing: Make sure your virtual environment is activated before running pip install -r requirements.txt.

"Address already in use" error: The port 5000 might be in use by another application. You can try changing the port in steganography_app.py (e.g., app.run(debug=True, port=5001)).
"VirusTotal API key is not configured" error: Double-check that you have correctly set the VIRUSTOTAL_API_KEY in steganography_app.py or as an environment variable.

Images not displaying/processing: Check the browser console for JavaScript errors and the terminal running Flask for backend errors.