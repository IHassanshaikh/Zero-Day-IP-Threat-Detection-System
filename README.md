# Zero-Day IP Threat Detection System

A simple, AI-powered system to analyze network traffic and detect threats using behavioral analysis (Isolation Forest).

## Project Structure
- `app.py`: The main Flask application (Back-end).
- `generate_dummy_pcap.py`: Script to generate synthetic sample data (`traffic.pcap`).
- `templates/index.html`: The modern web interface.
- `static/`: CSS and JS files.

## Setup & Run
1. **Install Dependencies** (if not already done):
   ```bash
   pip install -r requirements.txt
   ```

2. **Generate Data** (Required for first run):
   ```bash
   python generate_dummy_pcap.py
   ```
   This creates a `traffic.pcap` file with mixed normal and suspicious traffic.

3. **Run the System**:
   ```bash
   python app.py
   ```
   Open your browser and go to `http://127.0.0.1:5000`.

## How to Test
- Enter `10.0.0.12` to see a **Threat** result.
- Enter `192.168.1.5` to see a **Normal** result.
