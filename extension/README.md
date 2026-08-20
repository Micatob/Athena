# Athena Browser Extension

This Chrome extension provides a browser-based interface for the Athena penetration testing framework.

## Installation

1. Make sure you have the Athena Python tool installed and Flask available
2. Load this extension in Chrome:
   - Open Chrome and go to `chrome://extensions/`
   - Enable "Developer mode" in the top right
   - Click "Load unpacked" and select this `extension` folder
3. Start the Athena web server: `python athena.py 4`

## Usage

1. Click the Athena extension icon in Chrome
2. Enter the target URL/domain
3. Select the scan mode
4. Click "Start Scan"
5. The scan will run in the background and save results to the usual output files

## Requirements

- Chrome browser
- Python with Flask installed
- Athena framework running in web server mode

## Notes

- The extension communicates with the local Athena server on `http://127.0.0.1:5000`
- Make sure the Python server is running before using the extension
- Scan results are saved to the same files as CLI mode