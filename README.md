# PhishDetect

A simple, explainable phishing URL detector written in Python.
It checks a link for common phishing signs and gives a risk score with the reasons.

## Features

- Detects raw IP addresses, punycode (look-alike) domains and URL shorteners
- Detects fake brand names (for example paypa1 instead of paypal)
- Flags suspicious words, risky endings (.tk, .xyz) and non-HTTPS links
- Shows the reason for every point added to the score
- Never opens the link (static analysis only), so it is safe to use

## How to use

Requires Python 3. No extra libraries needed.

    python phishdetect.py

Then paste a URL when asked.

## Example

![PhishDetect demo](screenshots/demo.png)

## What I learned

Python, URL parsing with `urllib.parse`, functions, lists and loops, string checks, the `ipaddress` module, and how common phishing tricks work (look-alike domains, punycode, suspicious TLDs, IP-based links).

## Disclaimer

This is a heuristic tool. It can make mistakes, so do not rely on it as your only protection.

## Author

Abdul Qadir