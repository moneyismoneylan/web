# SQLi Hunter: Advanced DAST Scanner

**SQLi Hunter** is a sophisticated Dynamic Application Security Testing (DAST) tool specifically engineered to uncover complex SQL injection vulnerabilities. It moves beyond simple pattern matching, employing an intelligent, multi-faceted approach to identify and analyze potential weaknesses in web applications.

![Build Status](https://img.shields.io/badge/build-stable-brightgreen)
![Version](https://img.shields.io/badge/version-3.0.0--final-blue)

## Core Features

This version of SQLi Hunter represents a significant leap in scanning philosophy, focusing on deep analysis and robust detection.

### 🧠 Anomaly-Based Detection Engine
The core of SQLi Hunter is its anomaly-based detection engine. Instead of relying on a static list of error messages, it establishes a baseline for a "normal" application response and then hunts for deviations. It scores every fuzzed response based on:
-   **Status Code Changes:** Identifies shifts from normal (e.g., 200 OK) to error states (e.g., 500 Internal Server Error).
-   **Content Similarity Analysis:** Uses the Simhash algorithm to intelligently detect subtle changes in page content, catching errors that don't trigger overt error messages.
-   **Error Pattern Inference:** A comprehensive library of database-specific error patterns is used to enhance the anomaly score and, more importantly, to automatically infer the backend database dialect (e.g., `mssql`, `mysql`, `oracle`) directly from the error text.

### 🕵️‍♂️ Intelligent Form Fuzzing
Modern applications often validate multiple fields. SQLi Hunter understands this. When fuzzing a form parameter, it doesn't just inject a payload into one field while leaving others blank. It intelligently populates all other form fields with sensible dummy data (e.g., `test`, `test@test.com`, `123456`). This technique dramatically increases the chances of bypassing rudimentary validation checks and allowing the payload to reach the vulnerable SQL query.

### 🛡️ Unified Session & WAF Handling
The entire request pipeline is built on a shared `cloudscraper` instance. This provides two key benefits:
1.  **Robust WAF Bypass:** It offers out-of-the-box handling for many common JavaScript-based WAF challenges (like Cloudflare's "I'm under attack mode").
2.  **Consistent Session Management:** It ensures that a single, consistent session is maintained across the crawler, scanner, and exploiter modules, which is critical for testing authenticated endpoints.

### 💥 Multi-Stage Exploitation Module (Experimental)
SQLi Hunter includes an advanced, experimental exploitation engine for MSSQL error-based vulnerabilities. It attempts to bypass WAFs and server-side defenses using a **multi-stage stacked query attack**. This technique involves:
1.  Declaring a variable on the database.
2.  Populating that variable with the result of a query (e.g., `SELECT DB_NAME()`).
3.  Forcing a data type conversion error on the variable to leak its contents in the error message.

**Note:** The success of this module is highly dependent on the target's WAF rules and server-side error reporting configuration. On hardened targets, it may fail even if the vulnerability is correctly identified.

## Usage

1.  **Installation**
    ```bash
    pip install -r requirements.txt
    playwright install
    playwright install-deps
    ```

2.  **Running a Scan**
    ```bash
    # Basic scan with crawling
    python main.py -u <target_url>

    # Scan with data dumping enabled (experimental)
    python main.py -u <target_url> --dump-db

    # Enable detailed debug logging
    python main.py -u <target_url> --dump-db --debug
    ```

## Project Summary & Final State

This project aimed to enhance SQLi Hunter to detect and exploit a vulnerability in a hardened target.
-   **Detection:** The tool was successfully upgraded to reliably **detect the error-based SQL injection vulnerability**. The implementation of the anomaly-based engine and intelligent form filler was crucial to this success.
-   **Exploitation:** A significant effort was made to build a "beyond its age" dumper. Three distinct, advanced exploitation techniques were developed: direct error-based, inverted boolean-based, and finally, multi-stage stacked query error-based. While these make the tool far more powerful, they were ultimately **unable to extract data from the specific, highly-resilient target**. The failures indicate the target is protected by multiple layers of defense that block known exfiltration patterns and suppress detailed error messages from stacked queries.

The final result is a powerful and intelligent scanner that successfully achieves the primary goal of vulnerability detection. The exploitation module, while advanced, serves as a proof-of-concept for modern exploitation techniques.
