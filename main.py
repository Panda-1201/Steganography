''''

# main.py
# This script provides a command-line interface for performing
# text and image steganography operations.

import argparse
import os
from text_steganography import embed_text, extract_text
from image_steganography import embed_image, extract_image
from utils import save_image # Ensure utils is imported for general utilities

def main():
    """
    Main function to parse command-line arguments and execute steganography operations.
    """
    parser = argparse.ArgumentParser(description="Perform text or image steganography.")
    
    # Subparsers for different steganography types (text, image)
    subparsers = parser.add_subparsers(dest='type', help='Type of steganography (text or image)')

    # --- Text Steganography Subparser ---
    text_parser = subparsers.add_parser('text', help='Text steganography operations')
    text_subparsers = text_parser.add_subparsers(dest='operation', help='Text steganography operation (embed or extract)')

    # Text Embed Parser
    text_embed_parser = text_subparsers.add_parser('embed', help='Embed text into an image')
    text_embed_parser.add_argument('--image', required=True, help='Path to the cover image file.')
    text_embed_parser.add_argument('--text', required=True, help='Text to hide.')
    text_embed_parser.add_argument('--output', required=True, help='Path to save the output stego image.')

    # Text Extract Parser
    text_extract_parser = text_subparsers.add_parser('extract', help='Extract text from a stego image')
    text_extract_parser.add_argument('--image', required=True, help='Path to the stego image file.')

    # --- Image Steganography Subparser ---
    image_parser = subparsers.add_parser('image', help='Image steganography operations')
    image_subparsers = image_parser.add_subparsers(dest='operation', help='Image steganography operation (embed or extract)')

    # Image Embed Parser
    image_embed_parser = image_subparsers.add_parser('embed', help='Embed a secret image into a cover image')
    image_embed_parser.add_argument('--cover-image', required=True, help='Path to the cover image file.')
    image_embed_parser.add_argument('--secret-image', required=True, help='Path to the secret image file to hide.')
    image_embed_parser.add_argument('--output', required=True, help='Path to save the output stego image.')

    # Image Extract Parser
    image_extract_parser = image_subparsers.add_parser('extract', help='Extract a secret image from a stego image')
    image_extract_parser.add_argument('--image', required=True, help='Path to the stego image file.')
    image_extract_parser.add_argument('--output', required=True, help='Path to save the extracted secret image.')

    args = parser.parse_args()

    # --- Execute Operations ---
    if args.type == 'text':
        if args.operation == 'embed':
            print(f"Embedding text '{args.text}' into '{args.image}'...")
            embed_text(args.image, args.text, args.output)
            if os.path.exists(args.output):
                print(f"Text embedded successfully. Stego image saved to: {args.output}")
            else:
                print("Text embedding failed.")
        elif args.operation == 'extract':
            print(f"Extracting text from '{args.image}'...")
            extracted_text = extract_text(args.image)
            if extracted_text:
                print("Extracted Text:")
                print(extracted_text)
            else:
                print("No text found or extraction failed.")
        else:
            text_parser.print_help() # If no operation specified for text

    elif args.type == 'image':
        if args.operation == 'embed':
            print(f"Embedding '{args.secret_image}' into '{args.cover_image}'...")
            embed_image(args.cover_image, args.secret_image, args.output)
            if os.path.exists(args.output):
                print(f"Image embedded successfully. Stego image saved to: {args.output}")
            else:
                print("Image embedding failed.")
        elif args.operation == 'extract':
            print(f"Extracting secret image from '{args.image}'...")
            # The extract_image function saves directly to the output path
            extract_image(args.image, args.output)
            if os.path.exists(args.output):
                print(f"Secret image extracted successfully. Saved to: {args.output}")
            else:
                print("Image extraction failed.")
        else:
            image_parser.print_help() # If no operation specified for image

    else:
        parser.print_help() # If no type specified (text or image)

if __name__ == '__main__':
    main()

    '''
# main.py
# This script provides a command-line interface for performing
# text and image steganography operations.

import argparse
import os
from text_steganography import embed_text, extract_text
from image_steganography import embed_image, extract_image
from utils import save_image # Ensure utils is imported for general utilities

def main():
    """
    Main function to parse command-line arguments and execute steganography operations.
    """
    parser = argparse.ArgumentParser(description="Perform text or image steganography.")
    
    # Subparsers for different steganography types (text, image)
    subparsers = parser.add_subparsers(dest='type', help='Type of steganography (text or image)')

    # --- Text Steganography Subparser ---
    text_parser = subparsers.add_parser('text', help='Text steganography operations')
    text_subparsers = text_parser.add_subparsers(dest='operation', help='Text steganography operation (embed or extract)')

    # Text Embed Parser
    text_embed_parser = text_subparsers.add_parser('embed', help='Embed text into an image')
    text_embed_parser.add_argument('--image', required=True, help='Path to the cover image file.')
    text_embed_parser.add_argument('--text', required=True, help='Text to hide.')
    text_embed_parser.add_argument('--output', required=True, help='Path to save the output stego image.')

    # Text Extract Parser
    text_extract_parser = text_subparsers.add_parser('extract', help='Extract text from a stego image')
    text_extract_parser.add_argument('--image', required=True, help='Path to the stego image file.')

    # --- Image Steganography Subparser ---
    image_parser = subparsers.add_parser('image', help='Image steganography operations')
    image_subparsers = image_parser.add_subparsers(dest='operation', help='Image steganography operation (embed or extract)')

    # Image Embed Parser
    image_embed_parser = image_subparsers.add_parser('embed', help='Embed a secret image into a cover image')
    image_embed_parser.add_argument('--cover-image', required=True, help='Path to the cover image file.')
    image_embed_parser.add_argument('--secret-image', required=True, help='Path to the secret image file to hide.')
    image_embed_parser.add_argument('--output', required=True, help='Path to save the output stego image.')

    # Image Extract Parser
    image_extract_parser = image_subparsers.add_parser('extract', help='Extract a secret image from a stego image')
    image_extract_parser.add_argument('--image', required=True, help='Path to the stego image file.')
    image_extract_parser.add_argument('--output', required=True, help='Path to save the extracted secret image.')

    args = parser.parse_args()

    # --- Execute Operations ---
    if args.type == 'text':
        if args.operation == 'embed':
            print(f"Embedding text '{args.text}' into '{args.image}'...")
            success = embed_text(args.image, args.text, args.output)
            if success:
                print(f"Text embedded successfully. Stego image saved to: {args.output}")
            else:
                print("Text embedding failed. Check error messages above.")
        elif args.operation == 'extract':
            print(f"Extracting text from '{args.image}'...")
            extracted_text = extract_text(args.image)
            if extracted_text is not None: # Check for None which signifies an error
                if extracted_text == "": # Check for empty string which means no text found
                    print("No hidden text found.")
                else:
                    print("Extracted Text:")
                    print(extracted_text)
            else:
                print("Text extraction failed. Check error messages above.")
        else:
            text_parser.print_help() # If no operation specified for text

    elif args.type == 'image':
        if args.operation == 'embed':
            print(f"Embedding '{args.secret_image}' into '{args.cover_image}'...")
            success = embed_image(args.cover_image, args.secret_image, args.output)
            if success:
                print(f"Image embedded successfully. Stego image saved to: {args.output}")
            else:
                print("Image embedding failed. Check error messages above.")
        elif args.operation == 'extract':
            print(f"Extracting secret image from '{args.image}'...")
            success = extract_image(args.image, args.output)
            if success:
                print(f"Secret image extracted successfully. Saved to: {args.output}")
            else:
                print("Image extraction failed. Check error messages above.")
        else:
            image_parser.print_help() # If no operation specified for image

    else:
        parser.print_help() # If no type specified (text or image)

if __name__ == '__main__':
    main()

