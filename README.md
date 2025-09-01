
# Phishing Detector

A modern Flask web application for detecting phishing URLs and suspicious emails using pattern matching, ML, and threat intelligence APIs.

---

## 🚀 How to Run

1. **Clone the repository**
    ```sh
    git clone <your-repo-url>
    cd phishing-detector
    ```

2. **Create and activate a virtual environment**
    ```sh
    python -m venv venv
    # On Windows:
    venv\Scripts\activate
    # On Linux/Mac:
    source venv/bin/activate
    ```

3. **Install dependencies**
    ```sh
    pip install -r requirements.txt
    ```

4. **Set environment variables** (optional, for production)
    - `VIRUSTOTAL_API_KEY` (for VirusTotal integration)
    - `PHISHTANK_API_KEY` (for PhishTank integration)
    - `FLASK_SECRET_KEY` (for session security)

5. **Run the app**
    ```sh
    python app_clean.py
    ```
    The app will be available at [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## 📡 API Usage

### `POST /scan`
Scan a URL or email for phishing indicators.

**Request:**
- Content-Type: `application/json`
- Body:
   ```json
   {
      "type": "url" | "email",
      "input": "<url-or-email-content>"
   }
   ```

**Response:**
- Success:
   ```json
   {
      "success": true,
      "result": "Safe" | "Phishing" | "Suspicious",
      "confidence": 0-100,
      "threats_detected": ["..."],
      ...
   }
   ```
- Error:
   ```json
   {
      "success": false,
      "error": "..."
   }
   ```

---

## 🏗️ System Architecture & Flow

```
User (Web/REST) ──▶ Flask App
                                 │
                                 ├─▶ Regex/Pattern Checks
                                 ├─▶ ML Model (background)
                                 ├─▶ VirusTotal API (optional)
                                 ├─▶ PhishTank API (optional)
                                 │
                           [Combine Results]
                                 │
                           [Store in SQLite DB]
                                 │
                           [Return verdict to user]
```

### **Flow Description**
1. **User submits** a URL or email via the web UI or `/scan` API.
2. **Input is sanitized** and rate-limited.
3. **Detection logic** runs:
    - Regex/pattern matching for common phishing traits
    - (Optional) ML model for advanced detection
    - (Optional) VirusTotal/PhishTank API lookups
4. **Results are combined** for a final verdict.
5. **Scan record is saved** to the database.
6. **User receives** a verdict, confidence score, and details.

---

## 🔒 Security
- All user input is sanitized.
- Rate limiting is enforced per IP.
- API keys are never exposed to the frontend.

---

## 📄 License
MIT

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for details."# python-app" 
