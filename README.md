# IEEE 802.11 Information Element Parser Comparison

This repository contains code and outputs used to evaluate a manual and LLM-generated parser for IEEE 802.11 beacon frame Information Elements.

## Contents

- `manual.py` – Manual parser implementation  
- `LLM.py` – Final LLM-generated parser  
- `comparison.py` – Script for field-level comparison against Wireshark  
- `parsed_beacons.json` – Output from manual parser for Packet 8 (MRK-P)  
- `parsed_beacons_LLM.json` – Output from LLM parser for Packet 8 (MRK-P)
- `MRKP_compare` – Example comparison output for Packet 8 (MRK-P)

## Key Example

The file `MRKP_compare` provides a representative field-level comparison between the LLM parser and Wireshark for Packet 8 (MRK-P), as referenced in Section 4.4 of the report.

Each field is evaluated and classified as:
- `MATCH` – Value matches Wireshark
- `MISMATCH` – Value differs from Wireshark

This example demonstrates the validation methodology used to compute quantitative results.
