# ZAP API Backend for VulTURE using Flask
This project is the API for VulTURE - a web security scanner using ZAP (Zed Attack Proxy) API integrated with Flask, a lightweight web framework in Python. The scanner performs both passive and active scanning on the specified target URL.
## Prerequisites

Before running the application, ensure you have the following installed:

- Python 3.x
- Flask (`pip install Flask`)
- ZAPv2 (`pip install zaproxy`)
- ZAP installed and running (Download from [here](https://www.zaproxy.org/download/))

## Setup

1. Clone this repository to your local machine.
2. Install the required dependencies using `pip install -r requirements.txt`.
3. Start ZAP Desktop/Daemon.
4. Run the Flask application by executing `python app.py`.
5. Access the application at `http://localhost:5000` in your web browser.

## Usage

The application provides the following endpoints:

1. `/spider`: Initiates a spider scan on the specified target URL.
2. `/passive`: Performs passive scanning on the specified target URL.
3. `/active`: Performs active scanning on the specified target URL.

### Parameters

- `target`: The URL of the website to be scanned.

### Example

To initiate a spider scan on `http://example.com`, you can use the following command:
1. Start Postman
2. Set `target : http://example.com`
3. Make a `GET` request to `localhost:5000/spider` with target enabled

### Screenshot

![Spider Scan on Google Gruyere](https://github.com/VulTURE-HackByte/vulture_ZAP/assets/116958420/d86177c3-2a94-4124-9a9d-356f6875f624)
