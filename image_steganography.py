''''

# image_steganography.py
# Handles embedding and extracting one image into/from another image.

import struct
from utils import load_image, save_image, bytes_to_binary, binary_to_bytes, get_pixel_data_capacity, embed_data_into_image, extract_data_from_image
from PIL import Image # Explicitly import Image for creating new image

# Metadata for secret image: width, height
# Each dimension is stored as a 16-bit integer (2 bytes each). Total 4 bytes = 32 bits.
IMAGE_METADATA_BITS = 16 * 2 # 16 bits for width, 16 for height

# The number of bits used to store the length of the hidden image data.
# This prefix is crucial for knowing how many bits to extract during decoding.
LENGTH_PREFIX_BITS = 32 # Same as text, 32 bits for data length

def embed_image(cover_image_path, secret_image_path, output_path):
    """
    Embeds a secret image into a cover image using LSB steganography.
    The secret image's dimensions and data length are prepended as binary headers.
    Returns True on success, False on failure.
    """
    cover_img = load_image(cover_image_path)
    if not cover_img:
        print(f"ERROR: embed_image: Failed to load cover image at {cover_image_path}")
        return False # Return False on failure

    secret_img = load_image(secret_image_path)
    if not secret_img:
        print(f"ERROR: embed_image: Failed to load secret image at {secret_image_path}")
        return False # Return False on failure

    # Convert secret image pixel data (RGB channels) to a continuous binary string.
    # Each R, G, B value (0-255) is converted to an 8-bit binary string.
    secret_img_pixels = secret_img.load()
    secret_img_binary_data = []
    for y in range(secret_img.height):
        for x in range(secret_img.width):
            r, g, b = secret_img_pixels[x, y]
            secret_img_binary_data.append(format(r, '08b'))
            secret_img_binary_data.append(format(g, '08b'))
            secret_img_binary_data.append(format(b, '08b'))
    secret_img_binary = "".join(secret_img_binary_data)

    # Prepare metadata: width and height of the secret image.
    # Pack them into a binary string using struct for consistent byte order ('>HH' for unsigned short)
    metadata_bytes = struct.pack('>HH', secret_img.width, secret_img.height)
    metadata_binary = bytes_to_binary(metadata_bytes)

    # Prepend the length of the secret image binary data as a 32-bit binary string
    secret_img_len_bits = len(secret_img_binary)
    length_binary = format(secret_img_len_bits, f'0{LENGTH_PREFIX_BITS}b') # Ensure 32 bits

    # Combine all binary data: length prefix + image metadata + actual image pixel data
    full_data_binary = length_binary + metadata_binary + secret_img_binary

    # Get the maximum capacity of the cover image for hidden data
    capacity = get_pixel_data_capacity(cover_img)

    # Check if the total data fits within the cover image's capacity
    if len(full_data_binary) > capacity:
        print(f"Error: Secret image is too large for the cover image. Required bits: {len(full_data_binary)}, Available bits: {capacity}")
        return False # Return False on failure

    # Embed the combined binary data into the cover image
    stego_img = embed_data_into_image(cover_img, full_data_binary)
    
    # Check if stego_img is valid before attempting to save
    if not stego_img:
        print("ERROR: embed_image: stego_img is None after embedding data.")
        return False # Return False if stego_img is None after embedding

    # Save the resulting stego image. save_image also returns True/False now.
    if save_image(stego_img, output_path):
        return True # Return True on success
    else:
        print(f"ERROR: embed_image: Failed to save stego image to {output_path}")
        return False # Return False if saving failed

def extract_image(stego_image_path, output_image_path):
    """
    Extracts a secret image from a stego image.
    It first reads the data length and image dimensions from the stego image's LSBs.
    Returns True on success, False on failure.
    """
    stego_img = load_image(stego_image_path)
    if not stego_img:
        print(f"ERROR: extract_image: Failed to load stego image at {stego_image_path}")
        return False # Return False on failure

    # First, extract the length prefix (32 bits) of the secret image's data
    length_binary_str = extract_data_from_image(stego_img, LENGTH_PREFIX_BITS)
    if not length_binary_str:
        print("Error: Could not extract length prefix. Image might not contain hidden image.")
        return False # Return False on failure

    try:
        secret_img_len_bits = int(length_binary_str, 2)
    except ValueError:
        print("Error: Invalid length prefix extracted. Image might not contain hidden image.")
        return False # Return False on failure

    # If the extracted length is zero, no secret image was embedded
    if secret_img_len_bits == 0:
        print("No secret image data found.")
        return False # Return False if no data found

    # Calculate the total bits to extract: length prefix + image metadata + actual image data
    total_bits_to_extract = LENGTH_PREFIX_BITS + IMAGE_METADATA_BITS + secret_img_len_bits

    # Extract all the combined binary data from the stego image
    full_extracted_binary = extract_data_from_image(stego_img, total_bits_to_extract)

    # Check if the extracted data length matches the expected total length
    if len(full_extracted_binary) < total_bits_to_extract:
        print(f"Error: Not enough data extracted. Image might be truncated or corrupted. Expected {total_bits_to_extract}, got {len(full_extracted_binary)}")
        return False # Return False on failure

    # Separate the metadata binary string from the actual image data binary string
    metadata_binary_str = full_extracted_binary[LENGTH_PREFIX_BITS : LENGTH_PREFIX_BITS + IMAGE_METADATA_BITS]
    extracted_secret_img_binary = full_extracted_binary[LENGTH_PREFIX_BITS + IMAGE_METADATA_BITS:]

    try:
        # Unpack the metadata (width and height) from its binary string
        metadata_bytes = binary_to_bytes(metadata_binary_str)
        secret_img_width, secret_img_height = struct.unpack('>HH', metadata_bytes)

        # Validate extracted dimensions
        if not (secret_img_width > 0 and secret_img_height > 0):
            print("Error: Extracted image dimensions are invalid.")
            return False # Return False on failure

        # Reconstruct the secret image from its binary pixel data
        # Each pixel needs 3 bytes (R, G, B) or 24 bits.
        extracted_pixels_data = bytearray()
        data_index = 0
        
        # Loop through the binary data, taking 8 bits for R, 8 for G, 8 for B
        # and converting them back to integer pixel values.
        for _ in range(secret_img_width * secret_img_height):
            r_binary = extracted_secret_img_binary[data_index : data_index + 8]
            g_binary = extracted_secret_img_binary[data_index + 8 : data_index + 16]
            b_binary = extracted_secret_img_binary[data_index + 16 : data_index + 24]

            r = int(r_binary, 2)
            g = int(g_binary, 2)
            b = int(b_binary, 2)

            extracted_pixels_data.extend([r, g, b]) # Add RGB values

            data_index += 24 # Move to the next pixel's data (3 channels * 8 bits/channel)

        # Create a new Pillow Image object from the reconstructed pixel data
        # The 'frombytes' method is efficient for this.
        extracted_img = Image.frombytes("RGB", (secret_img_width, secret_img_height), bytes(extracted_pixels_data))
        
        # Save the extracted image to the specified output path
        if save_image(extracted_img, output_image_path):
            return True # Return True on success
        else:
            print(f"ERROR: extract_image: Failed to save extracted image to {output_image_path}")
            return False # Return False if saving failed

    except Exception as e:
        print(f"Error processing extracted image: {e}")
        return False # Return False on general exception

'''

# image_steganography.py
# Handles embedding and extracting one image into/from another image.

import struct
import numpy as np # Added numpy for efficient pixel manipulation
from PIL import Image # Explicitly import Image for creating new image
from utils import load_image, save_image, bytes_to_binary, binary_to_bytes, get_pixel_data_capacity, embed_data_into_image, extract_data_from_image

# Metadata for secret image: width, height
# Each dimension is stored as a 16-bit integer (2 bytes each). Total 4 bytes = 32 bits.
IMAGE_METADATA_BITS = 16 * 2 # 16 bits for width, 16 for height

# The number of bits used to store the length of the hidden image data.
# This prefix is crucial for knowing how many bits to extract during decoding.
LENGTH_PREFIX_BITS = 32 # Same as text, 32 bits for data length

def embed_image(cover_image_path, secret_image_path, output_path):
    """
    Embeds a secret image into a cover image using LSB steganography.
    The secret image's dimensions and data length are prepended as binary headers.
    Returns True on success, False on failure.
    """
    cover_img = load_image(cover_image_path)
    if not cover_img:
        print(f"ERROR: embed_image: Failed to load cover image at {cover_image_path}")
        return False # Return False on failure

    secret_img = load_image(secret_image_path)
    if not secret_img:
        print(f"ERROR: embed_image: Failed to load secret image at {secret_image_path}")
        return False # Return False on failure

    # Convert secret image pixel data (RGB channels) to a continuous binary string.
    # Each R, G, B value (0-255) is converted to an 8-bit binary string.
    secret_img_pixels = secret_img.load()
    secret_img_binary_data = []
    for y in range(secret_img.height):
        for x in range(secret_img.width):
            r, g, b = secret_img_pixels[x, y]
            secret_img_binary_data.append(format(r, '08b'))
            secret_img_binary_data.append(format(g, '08b'))
            secret_img_binary_data.append(format(b, '08b'))
    secret_img_binary = "".join(secret_img_binary_data)

    # Prepare metadata: width and height of the secret image.
    # Pack them into a binary string using struct for consistent byte order ('>HH' for unsigned short)
    metadata_bytes = struct.pack('>HH', secret_img.width, secret_img.height)
    metadata_binary = bytes_to_binary(metadata_bytes)

    # Prepend the length of the secret image binary data as a 32-bit binary string
    secret_img_len_bits = len(secret_img_binary)
    length_binary = format(secret_img_len_bits, f'0{LENGTH_PREFIX_BITS}b') # Ensure 32 bits

    # Combine all binary data: length prefix + image metadata + actual image pixel data
    full_data_binary = length_binary + metadata_binary + secret_img_binary

    # Get the maximum capacity of the cover image for hidden data
    capacity = get_pixel_data_capacity(cover_img)

    # Check if the total data fits within the cover image's capacity
    if len(full_data_binary) > capacity:
        print(f"Error: Secret image is too large for the cover image. Required bits: {len(full_data_binary)}, Available bits: {capacity}")
        return False # Return False on failure

    # Embed the combined binary data into the cover image
    stego_img = embed_data_into_image(cover_img, full_data_binary)
    
    # Check if stego_img is valid before attempting to save
    if not stego_img:
        print("ERROR: embed_image: stego_img is None after embedding data.")
        return False # Return False if stego_img is None after embedding

    # Save the resulting stego image. save_image also returns True/False now.
    if save_image(stego_img, output_path):
        return True # Return True on success
    else:
        print(f"ERROR: embed_image: Failed to save stego image to {output_path}")
        return False # Return False if saving failed

def extract_image(stego_image_path, output_image_path):
    """
    Extracts a secret image from a stego image.
    It first reads the data length and image dimensions from the stego image's LSBs.
    Returns True on success, False on failure.
    """
    stego_img = load_image(stego_image_path)
    if not stego_img:
        print(f"ERROR: extract_image: Failed to load stego image at {stego_image_path}")
        return False # Return False on failure

    # First, extract the length prefix (32 bits) of the secret image's data
    length_binary_str = extract_data_from_image(stego_img, LENGTH_PREFIX_BITS)
    if not length_binary_str:
        print("Error: Could not extract length prefix. Image might not contain hidden image.")
        return False # Return False on failure

    try:
        secret_img_len_bits = int(length_binary_str, 2)
    except ValueError:
        print("Error: Invalid length prefix extracted. Image might not contain hidden image.")
        return False # Return False on failure

    # If the extracted length is zero, no secret image was embedded
    if secret_img_len_bits == 0:
        print("No secret image data found.")
        return False # Return False if no data found

    # Calculate the total bits to extract: length prefix + image metadata + actual image data
    total_bits_to_extract = LENGTH_PREFIX_BITS + IMAGE_METADATA_BITS + secret_img_len_bits

    # Extract all the combined binary data from the stego image
    full_extracted_binary = extract_data_from_image(stego_img, total_bits_to_extract)

    # Check if the extracted data length matches the expected total length
    if len(full_extracted_binary) < total_bits_to_extract:
        print(f"Error: Not enough data extracted. Image might be truncated or corrupted. Expected {total_bits_to_extract}, got {len(full_extracted_binary)}")
        return False # Return False on failure

    # Separate the metadata binary string from the actual image data binary string
    metadata_binary_str = full_extracted_binary[LENGTH_PREFIX_BITS : LENGTH_PREFIX_BITS + IMAGE_METADATA_BITS]
    extracted_secret_img_binary = full_extracted_binary[LENGTH_PREFIX_BITS + IMAGE_METADATA_BITS:]

    try:
        # Unpack the metadata (width and height) from its binary string
        metadata_bytes = binary_to_bytes(metadata_binary_str)
        secret_img_width, secret_img_height = struct.unpack('>HH', metadata_bytes)

        # Validate extracted dimensions
        if not (secret_img_width > 0 and secret_img_height > 0):
            print("Error: Extracted image dimensions are invalid.")
            return False # Return False on failure

        # Reconstruct the secret image from its binary pixel data
        # Each pixel needs 3 bytes (R, G, B) or 24 bits.
        extracted_pixels_data = bytearray()
        data_index = 0
        
        # Loop through the binary data, taking 8 bits for R, 8 for G, 8 for B
        # and converting them back to integer pixel values.
        for _ in range(secret_img_width * secret_img_height):
            r_binary = extracted_secret_img_binary[data_index : data_index + 8]
            g_binary = extracted_secret_img_binary[data_index + 8 : data_index + 16]
            b_binary = extracted_secret_img_binary[data_index + 16 : data_index + 24]

            r = int(r_binary, 2)
            g = int(g_binary, 2)
            b = int(b_binary, 2)

            extracted_pixels_data.extend([r, g, b]) # Add RGB values

            data_index += 24 # Move to the next pixel's data (3 channels * 8 bits/channel)

        # Create a new Pillow Image object from the reconstructed pixel data
        # The 'frombytes' method is efficient for this.
        extracted_img = Image.frombytes("RGB", (secret_img_width, secret_img_height), bytes(extracted_pixels_data))
        
        # Save the extracted image to the specified output path
        if save_image(extracted_img, output_image_path):
            return True # Return True on success
        else:
            print(f"ERROR: extract_image: Failed to save extracted image to {output_image_path}")
            return False # Return False if saving failed

    except Exception as e:
        print(f"Error processing extracted image: {e}")
        return False # Return False on general exception
