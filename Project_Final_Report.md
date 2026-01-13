# Project Final Report

## 1. Project Title
**Zero-Day IP Threat Detection System**

## 2. Group Members Name
*   [Member Name 1]
*   [Member Name 2]
*   [Member Name 3]
*   [Member Name 4]

## 3. Problem Statement
In the rapidly evolving landscape of cybersecurity, traditional signature-based detection systems are often too slow to react to new, unknown threats (Zero-Day attacks). Attackers constantly change their methods to bypass static firewalls and antivirus software. 

The core problem is the inability of conventional systems to identify malicious intent based solely on **behavior** without a prior known "fingerprint" of the attack. Security analysts need a tool that can look at raw network traffic patterns—like how fast data is being sent or which ports are being accessed—and intelligently decide if an IP address represents a threat, even if that specific threat has never been seen before.

## 4. Explanation

### 4.1. Project Overview
This project is an AI-powered cybersecurity dashboard that analyzes network traffic to detect potential threats. It serves as an intelligent layer on top of raw network data, providing a user-friendly interface for assessing the risk level of any given IP address.

### 4.2. Tools & Technologies Used
*   **Backend (Logic & Processing):**
    *   **Python:** The core programming language used for all data processing.
    *   **Flask:** A lightweight web framework used to run the server and handle API requests.
    *   **Scapy:** A powerful library used to read, dissect, and analyze network packets (PCAP files).
    *   **Google Gemini AI:** The "Brain" of the system. We use Google's advanced Large Language Models (LLM) to perform the final complex decision-making.
    *   **Pandas & NumPy:** Used for statistical calculations (averages, ratios).

*   **Frontend (User Interface):**
    *   **HTML5 & CSS3:** For a modern, responsive, and dark-themed design ("Glassmorphism" aesthetic).
    *   **JavaScript:** Handles user interactions, API calls, and dynamic updates of the results without reloading the page.

### 4.3. Working Principle (Technical)
The system operates in a three-step pipeline:

1.  **Data Ingestion:**
    *   The user enters an IP address.
    *   The system first checks a captured network traffic file (`traffic.pcap`) to see if we have historical data for that IP.
    *   **Fallback Mechanism:** If the IP is not in our records, the system performs a **Live Scan** using standard Ping and Socket connection attempts to verify if the host is alive and which ports are open.

2.  **Feature Extraction:**
    The system calculates key mathematical "Features" from the raw data:
    *   **Packet Rate:** How many packets per second (high rate = potential flood attack).
    *   **Unique Ports:** How many different services it is trying to access (high count = port scanning).
    *   **Average Packet Size:** Using non-standard sizes can indicate data exfiltration or command-and-control signals.
    *   **TCP/UDP Ratio:** The balance of connection protocols.

3.  **AI Analysis:**
    These technical features are formatted into a prompt and sent to **Google Gemini**. The AI acts as a cybersecurity expert, analyzing the statistics to determine if the behavior is "Normal", "Suspicious", or a "Zero-Day Threat". It returns a risk score (0-100) and a textual explanation.

### 4.4. How It Works (Layman's Explanation)
Imagine your network is a building with many doors. A regular security guard (traditional antivirus) only stops people who are on a "Wanted" poster. If a new criminal comes in who isn't on the poster, the guard lets them in.

**Our system is like a smart detective.** Instead of looking for a specific face, it watches **behavior**.
*   Is this person running from door to door trying to open them all? (Port Scanning)
*   Are they carrying an unusually large amount of luggage out of the building? (Data Theft)
*   Are they moving faster than humanly possible? (DoS Attack)

Even if the detective has never seen this person before, they can tell something is wrong based on these actions. Our "detective" is the Google Gemini AI, which gives you a simple Report Card: **Safe**, **Suspicious**, or **Danger**, effectively catching "Zero-Day" (brand new) criminals.

## 5. Solution Statement
The **Zero-Day IP Threat Detection System** solves the problem of identifying unknown threats by combining low-level network analysis with high-level Artificial Intelligence. 

It provides a comprehensive solution that:
1.  **Simplifies Security:** Turns complex network logs into a simple "Threat Score".
2.  **Detects Unknowns:** Does not rely on a database of known viruses; it finds bad *behavior*.
3.  **Adapts:** Can handle both historical data (PCAP) and real-time targets (Live Scan).
4.  **Explains:** Unlike "Black Box" AI, our system tells the user *why* an IP was flagged (e.g., "High variance in port usage indicates port scanning"), empowering the analyst to take action.

## 6. Link to Code
*   **GitHub Repository:** [Insert Link Here]
*   **Local Project Path:** `d:/IS project`
