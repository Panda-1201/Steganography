'''

import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from text_steganography import embed_text, extract_text
from image_steganography import embed_image, extract_image
from PIL import Image # Import PIL for image handling
import io
import base64

app = Flask(__name__)
CORS(app) # Enable CORS for all routes

# Define upload folder for temporary files
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Set the maximum content length for requests (e.g., 1024 MB = 1 GB)
# This is crucial for handling large image uploads, especially after base64 encoding.
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024 # 1024 megabytes = 1 gigabyte

@app.route('/')
def home():
    """
    A simple home route to confirm the backend is running.
    """
    return "Steganography Backend is Running! (Text and Image features enabled)"

# --- Helper Functions (Backend specific) ---
def decode_base64_to_image(base64_string):
    """
    Decodes a base64 image string (e.g., 'data:image/png;base64,...') into a PIL Image object.
    """
    if not base64_string or not base64_string.startswith('data:image'):
        raise ValueError("Invalid base64 image string format.")
    
    # Split the header (e.g., 'data:image/png;base64,') from the actual encoded data
    header, encoded = base64_string.split(',', 1)
    data = base64.b64decode(encoded)
    return Image.open(io.BytesIO(data))

def encode_image_to_base64(image):
    """
    Encodes a PIL Image object into a base64 string with a PNG data URL prefix.
    """
    buffered = io.BytesIO()
    # Always save as PNG to avoid lossy compression issues with steganography
    image.save(buffered, format="PNG") 
    return "data:image/png;base64," + base64.b64encode(buffered.getvalue()).decode('latin-1')


# --- Text Steganography Endpoints ---

@app.route('/api/text/embed', methods=['POST'])
def text_embed_api():
    # Expects JSON body with 'coverImage' (base64) and 'textToEmbed'
    data = request.json
    cover_image_b64 = data.get('coverImage')
    text_to_embed = data.get('textToEmbed')

    if not cover_image_b64 or not text_to_embed:
        return jsonify({"error": "Missing cover image data or text to embed"}), 400

    temp_cover_path = None
    temp_stego_path = None
    try:
        cover_image_pil = decode_base64_to_image(cover_image_b64)
        
        # Save the PIL Image object directly to a temporary file
        temp_cover_path = os.path.join(app.config['UPLOAD_FOLDER'], f"cover_text_embed_{os.urandom(8).hex()}.png")
        cover_image_pil.save(temp_cover_path)
        
        temp_stego_path = os.path.join(app.config['UPLOAD_FOLDER'], f"stego_text_output_{os.urandom(8).hex()}.png")
        
        # embed_text now returns a boolean indicating success or failure
        success = embed_text(temp_cover_path, text_to_embed, temp_stego_path)
        
        if not success:
            # If embedding failed (e.g., text too large), report error
            return jsonify({'error': 'Failed to embed text: Text too large for cover image or other internal error.'}), 500

        stego_image_pil = Image.open(temp_stego_path)
        stego_image_b64 = encode_image_to_base64(stego_image_pil)
        
        return jsonify({'stegoImage': stego_image_b64, 'message': 'Text embedded successfully!'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        # Clean up temp files
        if temp_cover_path and os.path.exists(temp_cover_path):
            os.remove(temp_cover_path)
        if temp_stego_path and os.path.exists(temp_stego_path):
            os.remove(temp_stego_path)


@app.route('/api/text/extract', methods=['POST'])
def text_extract_api():
    # Expects JSON body with 'stegoImage' (base64)
    data = request.json
    stego_image_b64 = data.get('stegoImage')

    if not stego_image_b64:
        return jsonify({"error": "Missing stego image data"}), 400

    temp_stego_path = None
    try:
        stego_image_pil = decode_base64_to_image(stego_image_b64)
        temp_stego_path = os.path.join(app.config['UPLOAD_FOLDER'], f"stego_text_extract_{os.urandom(8).hex()}.png")
        stego_image_pil.save(temp_stego_path)

        extracted_text = extract_text(temp_stego_path)
        
        return jsonify({'extractedText': extracted_text, 'message': 'Text extracted successfully!'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if temp_stego_path and os.path.exists(temp_stego_path):
            os.remove(temp_stego_path)

# --- Image Steganography Endpoints ---

@app.route('/api/image/embed', methods=['POST'])
def image_embed_api():
    # Now expects JSON body with 'coverImage' (base64) and 'secretImage' (base64)
    data = request.json
    cover_image_b64 = data.get('coverImage')
    secret_image_b64 = data.get('secretImage')

    if not cover_image_b64 or not secret_image_b64:
        return jsonify({"error": "Missing cover image data or secret image file"}), 400

    temp_cover_path = None
    temp_secret_path = None
    temp_stego_path = None
    try:
        cover_image_pil = decode_base64_to_image(cover_image_b64)
        secret_image_pil = decode_base64_to_image(secret_image_b64)

        temp_cover_path = os.path.join(app.config['UPLOAD_FOLDER'], f"cover_image_embed_{os.urandom(8).hex()}.png")
        cover_image_pil.save(temp_cover_path)
        
        temp_secret_path = os.path.join(app.config['UPLOAD_FOLDER'], f"secret_image_embed_{os.urandom(8).hex()}.png")
        secret_image_pil.save(temp_secret_path)
        
        temp_stego_path = os.path.join(app.config['UPLOAD_FOLDER'], f"stego_image_output_{os.urandom(8).hex()}.png")
        
        # Call embed_image and check if it returned True (success) or False/None (failure)
        # Note: We need to modify embed_image in image_steganography.py to return a boolean.
        success = embed_image(temp_cover_path, temp_secret_path, temp_stego_path)
        
        if not success:
            # If embedding failed (e.g., secret image too large), report specific error
            # We assume embed_image prints its own specific error to backend console
            return jsonify({'error': 'Failed to embed image: Secret image too large for cover image, or other internal error.'}), 500

        # If we reached here, embedding was successful and the file should exist
        stego_image_pil = Image.open(temp_stego_path)
        stego_image_b64 = encode_image_to_base64(stego_image_pil)
        
        return jsonify({'stegoImage': stego_image_b64, 'message': 'Image embedded successfully!'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        # Clean up temp files
        if temp_cover_path and os.path.exists(temp_cover_path):
            os.remove(temp_cover_path)
        if temp_secret_path and os.path.exists(temp_secret_path):
            os.remove(temp_secret_path)
        if temp_stego_path and os.path.exists(temp_stego_path):
            os.remove(temp_stego_path)


@app.route('/api/image/extract', methods=['POST'])
def image_extract_api():
    # Expects JSON body with 'stegoImage' (base64)
    data = request.json
    stego_image_b64 = data.get('stegoImage')

    if not stego_image_b64:
        return jsonify({"error": "Missing stego image data"}), 400

    temp_stego_path = None
    temp_extracted_image_path = None
    try:
        stego_image_pil = decode_base64_to_image(stego_image_b64)
        temp_stego_path = os.path.join(app.config['UPLOAD_FOLDER'], f"stego_image_extract_{os.urandom(8).hex()}.png")
        stego_image_pil.save(temp_stego_path)

        extracted_image_filename = f"extracted_secret_{os.urandom(8).hex()}.png"
        temp_extracted_image_path = os.path.join(app.config['UPLOAD_FOLDER'], extracted_image_filename)

        # extract_image also needs to return a boolean indicating success/failure
        success = extract_image(temp_stego_path, temp_extracted_image_path)
        
        if not success:
            return jsonify({"error": "Failed to extract secret image or no image found."}), 500

        # Check if the extracted image file actually exists before trying to open it
        if not os.path.exists(temp_extracted_image_path):
            raise Exception("Extracted image file was not created by steganography module.")

        extracted_image_pil = Image.open(temp_extracted_image_path)
        extracted_image_b64 = encode_image_to_base64(extracted_image_pil)
        
        return jsonify({'extractedImage': extracted_image_b64, 'message': 'Image extracted successfully!'})
    except Exception as e:
        return jsonify({"error": f"Failed to extract secret image or no image found. Details: {str(e)}"}), 500
    finally:
        if temp_stego_path and os.path.exists(temp_stego_path):
            os.remove(temp_stego_path)
        if temp_extracted_image_path and os.path.exists(temp_extracted_image_path):
            os.remove(temp_extracted_image_path)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
      '''


import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import io
import base64
import uuid # For generating unique filenames
import hashlib # For calculating file hashes (SHA256)
import requests # For making HTTP requests to VirusTotal API
import json # For handling JSON responses

# Import steganography modules (assuming these are in the same directory or accessible)
# Make sure these files (text_steganography.py, image_steganography.py, utils.py) exist
# and contain the necessary functions.
try:
    from text_steganography import embed_text, extract_text
    from image_steganography import embed_image, extract_image
    from utils import load_image, save_image, binary_to_bytes 
except ImportError as e:
    print(f"Error importing steganography modules: {e}")
    print("Please ensure 'text_steganography.py', 'image_steganography.py', and 'utils.py' are in the same directory.")
    # Exit or handle gracefully if core modules are missing
    exit(1)

from PIL import Image # Import PIL for image handling

app = Flask(__name__)
CORS(app) # Enable CORS for all routes

# Define upload folder for temporary files
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Set the maximum content length for requests (e.g., 1024 MB = 1 GB)
# This is crucial for handling large file uploads, especially after base64 encoding.
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024 # 1024 megabytes = 1 gigabyte

# --- VirusTotal API Configuration ---
# IMPORTANT: In a real production app, store this securely (e.g., environment variable)
# DO NOT hardcode it directly in source code if this app goes public.
# Replace "YOUR_VIRUSTOTAL_API_KEY_HERE" with your actual API key.
VIRUSTOTAL_API_KEY = "c0429649bd05cbb34656b478db83c15d72bbf95f6a337d40f7d0d585340e3e12" # <--- !!! IMPORTANT: SET YOUR VIRUSTOTAL API KEY HERE !!!
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"

# --- Define the directory for frontend static files ---
# Assuming index.html and other static files are in the same directory as app.py
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR)


# --- Helper Functions (Backend specific) ---
def decode_base64_to_image(base64_string):
    """
    Decodes a base64 image string (e.g., 'data:image/png;base64,...') into a PIL Image object.
    """
    if not base64_string or not base64_string.startswith('data:image'):
        raise ValueError("Invalid base64 image string format.")
    
    # Split the header (e.g., 'data:image/png;base64,') from the actual encoded data
    header, encoded = base64_string.split(',', 1)
    data = base64.b64decode(encoded)
    return Image.open(io.BytesIO(data))

def encode_image_to_base64(image):
    """
    Encodes a PIL Image object into a base64 string with a PNG data URL prefix.
    """
    buffered = io.BytesIO()
    # Always save as PNG to avoid lossy compression issues with steganography
    image.save(buffered, format="PNG") 
    return "data:image/png;base64," + base64.b64encode(buffered.getvalue()).decode('latin-1')

def save_base64_data_to_temp_file(base64_data, filename_prefix, data_type='image'):
    """
    Saves base64 encoded data (image data URL or text) to a temporary file.
    Returns the path to the saved file.
    Note: This function is not directly used by the malware detection endpoint,
    as it processes bytes directly. It's kept for other steganography operations.
    """
    try:
        if data_type == 'image':
            # For image data URLs, decode to bytes and then save
            img_bytes = base64.b64decode(base64_data.split(',', 1)[1])
            file_extension = ".png" # Default to PNG for images
            if "image/jpeg" in base64_data:
                file_extension = ".jpeg"
            elif "image/gif" in base64_data:
                file_extension = ".gif" # Add more if needed
            
            unique_filename = f"{filename_prefix}_{uuid.uuid4().hex}{file_extension}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            with open(filepath, 'wb') as f:
                f.write(img_bytes)
            return filepath
        elif data_type == 'text':
            # For text, directly encode to bytes. Assuming frontend sends raw text.
            text_bytes = base64_data.encode('utf-8') 
            
            unique_filename = f"{filename_prefix}_{uuid.uuid4().hex}.txt"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            with open(filepath, 'wb') as f: # Write as binary for hash calculation
                f.write(text_bytes)
            return filepath
        else:
            raise ValueError("Unsupported data type for saving to temp file.")
    except Exception as e:
        print(f"ERROR: Failed to save base64 data to temp file: {e}")
        return None

# --- Frontend Serving Routes ---
@app.route('/')
def serve_index():
    """
    Serves the index.html file from the frontend directory.
    """
    return send_from_directory(FRONTEND_DIR, 'index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    """
    Serves other static files (like CSS, JS, images) from the frontend directory.
    """
    return send_from_directory(FRONTEND_DIR, filename)


# --- Text Steganography Endpoints ---

@app.route('/api/text/embed', methods=['POST'])
def text_embed_api():
    """
    Embeds text into a cover image using steganography.
    """
    data = request.json
    cover_image_b64 = data.get('coverImage')
    text_to_embed = data.get('textToEmbed')

    if not cover_image_b64 or not text_to_embed:
        return jsonify({"error": "Missing cover image data or text to embed"}), 400

    temp_cover_path = None
    temp_stego_path = None
    try:
        cover_image_pil = decode_base64_to_image(cover_image_b64)
        
        # Save original cover image temporarily for steganography function
        temp_cover_path = os.path.join(app.config['UPLOAD_FOLDER'], f"cover_text_embed_{os.urandom(8).hex()}.png")
        cover_image_pil.save(temp_cover_path)
        
        temp_stego_path = os.path.join(app.config['UPLOAD_FOLDER'], f"stego_text_output_{os.urandom(8).hex()}.png")
        
        # Call the external embed_text function
        success = embed_text(temp_cover_path, text_to_embed, temp_stego_path)
        
        if not success:
            return jsonify({'error': 'Failed to embed text: Text too large for cover image or other internal error.'}), 500

        # Load the stego image and encode it back to base64 for the response
        stego_image_pil = Image.open(temp_stego_path)
        stego_image_b64 = encode_image_to_base64(stego_image_pil)
        
        return jsonify({'stegoImage': stego_image_b64, 'message': 'Text embedded successfully!'})
    except Exception as e:
        print(f"ERROR in text_embed_api: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        # Clean up temporary files
        if temp_cover_path and os.path.exists(temp_cover_path):
            os.remove(temp_cover_path)
        if temp_stego_path and os.path.exists(temp_stego_path):
            os.remove(temp_stego_path)


@app.route('/api/text/extract', methods=['POST'])
def text_extract_api():
    """
    Extracts hidden text from a steganographic image.
    """
    data = request.json
    stego_image_b64 = data.get('stegoImage')

    if not stego_image_b64:
        return jsonify({"error": "Missing stego image data"}), 400

    temp_stego_path = None
    try:
        stego_image_pil = decode_base64_to_image(stego_image_b64)
        temp_stego_path = os.path.join(app.config['UPLOAD_FOLDER'], f"stego_text_extract_{os.urandom(8).hex()}.png")
        stego_image_pil.save(temp_stego_path)

        # Call the external extract_text function
        extracted_text = extract_text(temp_stego_path) # This returns a string ("" on failure)
        
        if extracted_text is None: # If extract_text explicitly returns None for an error
             return jsonify({'error': 'Failed to extract text. Image might not contain hidden data or is corrupted.'}), 500

        return jsonify({'extractedText': extracted_text, 'message': 'Text extracted successfully!'})
    except Exception as e:
        print(f"ERROR in text_extract_api: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        # Clean up temporary files
        if temp_stego_path and os.path.exists(temp_stego_path):
            os.remove(temp_stego_path)

# --- Image Steganography Endpoints ---

@app.route('/api/image/embed', methods=['POST'])
def image_embed_api():
    """
    Embeds a secret image into a cover image using steganography.
    """
    data = request.json
    cover_image_b64 = data.get('coverImage')
    secret_image_b64 = data.get('secretImage')

    if not cover_image_b64 or not secret_image_b64:
        return jsonify({"error": "Missing cover image data or secret image file"}), 400

    temp_cover_path = None
    temp_secret_path = None
    temp_stego_path = None
    try:
        cover_image_pil = decode_base64_to_image(cover_image_b64)
        secret_image_pil = decode_base64_to_image(secret_image_b64)

        # Save original cover and secret images temporarily
        temp_cover_path = os.path.join(app.config['UPLOAD_FOLDER'], f"cover_image_embed_{os.urandom(8).hex()}.png")
        cover_image_pil.save(temp_cover_path)
        
        temp_secret_path = os.path.join(app.config['UPLOAD_FOLDER'], f"secret_image_embed_{os.urandom(8).hex()}.png")
        secret_image_pil.save(temp_secret_path)
        
        temp_stego_path = os.path.join(app.config['UPLOAD_FOLDER'], f"stego_image_output_{os.urandom(8).hex()}.png")
        
        # Call the external embed_image function
        success = embed_image(temp_cover_path, temp_secret_path, temp_stego_path)
        
        if not success:
            return jsonify({'error': 'Failed to embed image: Secret image too large for cover image, or other internal error.'}), 500

        # Load the stego image and encode it back to base64 for the response
        stego_image_pil = Image.open(temp_stego_path)
        stego_image_b64 = encode_image_to_base64(stego_image_pil)
        
        return jsonify({'stegoImage': stego_image_b64, 'message': 'Image embedded successfully!'})
    except Exception as e:
        print(f"ERROR in image_embed_api: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        # Clean up temporary files
        if temp_cover_path and os.path.exists(temp_cover_path):
            os.remove(temp_cover_path)
        if temp_secret_path and os.path.exists(temp_secret_path):
            os.remove(temp_secret_path)
        if temp_stego_path and os.path.exists(temp_stego_path):
            os.remove(temp_stego_path)

@app.route('/api/image/extract', methods=['POST']) # Ensure this line is correct
def image_extract_api():
    """
    Extracts hidden image from a steganographic image.
    """
    print("DEBUG: Image extract API route was hit!") # <-- Added debug print
    data = request.json
    stego_image_b64 = data.get('stegoImage')

    if not stego_image_b64:
        return jsonify({"error": "Missing stego image data"}), 400

    temp_stego_path = None
    extracted_image_path = None
    try:
        stego_image_pil = decode_base64_to_image(stego_image_b64)
        temp_stego_path = os.path.join(app.config['UPLOAD_FOLDER'], f"stego_image_extract_{os.urandom(8).hex()}.png")
        stego_image_pil.save(temp_stego_path)

        extracted_image_path = os.path.join(app.config['UPLOAD_FOLDER'], f"extracted_secret_image_{os.urandom(8).hex()}.png")

        # Call the external extract_image function
        # This function should save the extracted image to extracted_image_path
        success = extract_image(temp_stego_path, extracted_image_path)
        
        if not success or not os.path.exists(extracted_image_path):
            # Check if the extracted file exists and has content (e.g., > 1KB)
            # A very small file might indicate extraction failure or an empty image
            if not os.path.exists(extracted_image_path) or os.path.getsize(extracted_image_path) < 1024:
                return jsonify({'error': 'Failed to extract image. Image might not contain hidden data, is corrupted, or extraction failed.'}), 500
            
        # Load the extracted image and encode it back to base64 for the response
        extracted_image_pil = Image.open(extracted_image_path)
        extracted_image_b64 = encode_image_to_base64(extracted_image_pil)
        
        return jsonify({'extractedImage': extracted_image_b64, 'message': 'Image extracted successfully!'})
    except Exception as e:
        print(f"ERROR in image_extract_api: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        # Clean up temporary files
        if temp_stego_path and os.path.exists(temp_stego_path):
            os.remove(temp_stego_path)
        if extracted_image_path and os.path.exists(extracted_image_path):
            os.remove(extracted_image_path)


# --- MALWARE DETECTION ENDPOINT ---
@app.route('/api/detect/malware', methods=['POST'])
def detect_malware():
    """
    Detects malware in extracted data (text or image) using the VirusTotal API.
    It calculates the SHA256 hash and checks against VirusTotal's database.
    If the hash is unknown, it uploads the file for analysis.
    """
    data = request.json
    extracted_data_b64 = data.get('extractedData')
    data_type = data.get('dataType') # 'text' or 'image'

    # Validate input
    if not extracted_data_b64 or not data_type:
        return jsonify({"error": "Missing extracted data or data type."}), 400

    # Validate VirusTotal API Key
    if not VIRUSTOTAL_API_KEY:
        return jsonify({"error": "VirusTotal API key is not configured. Please set VIRUTOTAL_API_KEY in the backend."}), 500

    try:
        # Convert base64 data to bytes for hashing and uploading
        if data_type == 'text':
            # Assuming extracted_data_b64 is the raw text string, not base64 encoded text.
            # If the frontend sends base64 encoded text, change this to:
            # extracted_bytes = base64.b64decode(extracted_data_b64.encode('utf-8'))
            extracted_bytes = extracted_data_b64.encode('utf-8')
        elif data_type == 'image':
            # Correctly decode image data URL (e.g., 'data:image/png;base64,...')
            if ',' in extracted_data_b64:
                header, encoded_data = extracted_data_b64.split(',', 1)
                extracted_bytes = base64.b64decode(encoded_data)
            else:
                # If it's just raw base64 without the data URL prefix
                extracted_bytes = base64.b64decode(extracted_data_b64)
        else:
            return jsonify({"error": "Unsupported data type for detection. Must be 'text' or 'image'."}), 400

        # Calculate SHA256 hash of the extracted data
        sha256_hash = hashlib.sha256(extracted_bytes).hexdigest()

        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }

        # 1. Check if the hash is already known by VirusTotal
        # This avoids re-uploading files that have already been scanned.
        response = requests.get(f"{VIRUSTOTAL_API_URL}/files/{sha256_hash}", headers=headers)
        vt_data = response.json()

        if response.status_code == 200:
            # Hash found, get analysis results
            attributes = vt_data['data']['attributes']
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            
            malicious_count = last_analysis_stats.get('malicious', 0)
            suspicious_count = last_analysis_stats.get('suspicious', 0)
            undetected_count = last_analysis_stats.get('undetected', 0)
            harmless_count = last_analysis_stats.get('harmless', 0)
            total_engines = sum(last_analysis_stats.values()) 

            analysis_url = f"https://www.virustotal.com/gui/file/{sha256_hash}/detection"

            status = "Harmless"
            if malicious_count > 0:
                status = "Malicious"
            elif suspicious_count > 0:
                status = "Suspicious"
            elif undetected_count == total_engines and total_engines > 0:
                status = "Undetected (all engines)" # All engines didn't detect anything
            elif total_engines == 0:
                status = "No analysis data yet" # Should ideally not happen for 200 OK

            return jsonify({
                "message": "Scan complete.",
                "status": status,
                "detections": f"{malicious_count}/{total_engines} engines detected malicious.",
                "analysis_url": analysis_url,
                "raw_response": vt_data # For debugging, can be removed in production
            }), 200

        elif response.status_code == 404:
            # Hash not found, need to upload for scan
            files = {'file': (f"extracted_data.{'png' if data_type == 'image' else 'txt'}", extracted_bytes)}
            upload_response = requests.post(f"{VIRUSTOTAL_API_URL}/files", headers=headers, files=files)
            upload_data = upload_response.json()

            if upload_response.status_code == 200:
                # --- ADDED DEBUG PRINT STATEMENTS ---
                print(f"DEBUG: Raw upload_response JSON from VirusTotal: {json.dumps(upload_data, indent=2)}")
                analysis_id = upload_data['data']['id']
                print(f"DEBUG: Extracted analysis_id: {analysis_id}")
                # --- END ADDED DEBUG PRINT STATEMENTS ---
                
                # Corrected URL for new analysis reports
                analysis_url = f"https://www.virustotal.com/gui/analyses/{analysis_id}/overview" 
                print(f"DEBUG: Generated analysis_url: {analysis_url}") # Already there, keep it.

                return jsonify({
                    "message": "File uploaded for analysis. Please check the provided link in a moment.",
                    "status": "Scanning...",
                    "analysis_url": analysis_url
                }), 202 # Accepted (file received, analysis pending)
            else: # This 'else' belongs to the 'if upload_response.status_code == 200:'
                print(f"ERROR: VirusTotal file upload failed: {upload_response.status_code}, {upload_data.get('error', {})}")
                error_message = upload_data.get('error', {}).get('message', 'Unknown error during upload.')
                if upload_response.status_code == 429:
                    return jsonify({"error": "VirusTotal API rate limit exceeded. Please wait a moment and try again."}), 429
                elif upload_response.status_code == 400 and "limit" in str(error_message).lower():
                    return jsonify({"error": "Extracted data too large for VirusTotal API upload. Try scanning manually."}), 400
                return jsonify({"error": f"Failed to upload file to VirusTotal: {error_message}"}), upload_response.status_code

        # Corrected Indentation: These 'elif' and 'else' blocks should align with the main 'if/elif' chain
        elif response.status_code == 429:
            return jsonify({"error": "VirusTotal API rate limit exceeded. Please wait a moment and try again."}), 429
        else:
            # Handle other VirusTotal API errors (e.g., authentication issues, invalid requests)
            print(f"ERROR: VirusTotal API general error: {response.status_code}, {vt_data.get('error', {})}")
            error_message = vt_data.get('error', {}).get('message', 'Unknown API error.')
            return jsonify({"error": f"VirusTotal API error: {error_message}"}), response.status_code

    except requests.exceptions.RequestException as e:
        # Catch network-related errors (e.g., DNS failure, connection refused)
        print(f"ERROR: Network error during VirusTotal API call: {e}")
        return jsonify({"error": f"Network error connecting to VirusTotal: {e}"}), 500
    except Exception as e:
        # Catch any other unexpected errors during processing
        print(f"ERROR: Internal server error during malware detection: {e}")
        return jsonify({"error": f"Internal server error: {e}"}), 500


if __name__ == '__main__':
    # Run the Flask app in debug mode.
    # In a production environment, use a production-ready WSGI server like Gunicorn or uWSGI.
    app.run(debug=True, port=5000)
