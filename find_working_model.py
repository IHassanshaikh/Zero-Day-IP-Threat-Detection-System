import google.generativeai as genai
import os

key = "AIzaSyDYOQrqt6xggbWm6NNNuT8rtf0XhIf-TU4"
genai.configure(api_key=key)

print(f"Testing API Key with available models...")

candidates = [
    'gemini-1.5-flash',
    'gemini-1.5-pro',
    'gemini-1.0-pro',
    'gemini-pro',
    'gemini-1.5-flash-latest',
    'gemini-flash-latest',
    'gemini-pro-vision'
]

# First, try to list models to get 'official' names
try:
    print("Fetching server-supported models...")
    server_models = []
    for m in genai.list_models():
        if 'generateContent' in m.supported_generation_methods:
            name = m.name.replace('models/', '')
            server_models.append(name)
    print(f"Server returned {len(server_models)} models.")
    # Prioritize server models
    candidates = server_models + candidates
except Exception as e:
    print(f"List models failed: {e}")

working_model = None

for model_name in candidates:
    print(f"Attempting: {model_name} ... ", end="")
    try:
        model = genai.GenerativeModel(model_name)
        response = model.generate_content("test")
        print("SUCCESS!")
        working_model = model_name
        break
    except Exception as e:
        print(f"FAIL ({str(e)[:50]}...)")

if working_model:
    print(f"\n✅ FOUND WORKING MODEL: {working_model}")
    print(f"Please update app.py to use: '{working_model}'")
else:
    print("\n❌ NO WORKING MODELS FOUND WITH CURRENT LIBRARY.")
