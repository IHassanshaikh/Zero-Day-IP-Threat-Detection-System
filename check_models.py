import google.generativeai as genai
import os

GOOGLE_API_KEY = "AIzaSyDYOQrqt6xggbWm6NNNuT8rtf0XhIf-TU4"
genai.configure(api_key=GOOGLE_API_KEY)

print("Listing available models...")
try:
    for m in genai.list_models():
        if 'generateContent' in m.supported_generation_methods:
            print(m.name)
except Exception as e:
    print(f"Error: {e}")
