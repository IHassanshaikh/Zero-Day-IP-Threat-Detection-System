import google.generativeai as genai
import os

key = "AIzaSyDYOQrqt6xggbWm6NNNuT8rtf0XhIf-TU4"
genai.configure(api_key=key)

print(f"Testing API Key: {key[:4]}...{key[-4:]}")

try:
    model = genai.GenerativeModel('gemini-1.5-flash')
    response = model.generate_content("Say hello")
    print("SUCCESS: Gemini 1.5 Flash responded:")
    print(response.text)
except Exception as e:
    print(f"\nFAILED: {e}")
