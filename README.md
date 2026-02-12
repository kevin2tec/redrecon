# RedRecon

[![Python Version](https://img.shields.io/badge/python-3.10-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)


## Description
RedRecon is a powerful passive and active web reconnaissance tool that discovers endpoints, JavaScript files, exposed secrets, and technology stacks, with results displayed directly in the terminal. It's designed for security researchers, bug bounty hunters, and penetration testers to quickly analyze web targets.


## Features
- Discover live endpoints, JS files, and external resources  
- Detect exposed secrets like API keys, JWTs, and database tokens  
- Analyze security headers and potential DOM XSS sources/sinks  
- Detect technology stacks (Supabase, Firebase, Stripe, Sentry, etc.)  
- Optional active scanning:  
  - Port scanning  
  - Brute-forcing endpoints  
  - Key validation & RLS bypass attempts  
  - Exploitation logic for testing  
- Fully terminal-based results (no external storage required)  


## Screenshot
![RedRecon in Action](./assets/redrecon.jpg)

> The above image showcases RedRecon scanning a target and displaying results in the terminal.


## Installation

1. Clone the repository:
```bash
git clone https://github.com/kevin2tec/redrecon.git
Navigate into the project directory:

cd redrecon
Create a virtual environment and activate it:

# Linux/macOS
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
Install dependencies:

pip install -r requirements.txt
Usage
Run RedRecon from the terminal:

python redrecon.py
Enter the target URL when prompted.

Watch as RedRecon discovers endpoints, JS files, secrets, tech stacks, and more.

Optional features like port scanning or endpoint brute-forcing can be enabled in the script.
