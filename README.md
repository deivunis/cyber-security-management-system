# Cyber Security Management System for Smart Home Devices

This repository contains a research prototype developed as part of a Master's thesis project. The system is designed to improve the cyber security of smart home environments by monitoring connected devices, detecting suspicious behaviour, identifying anomalies, evaluating device risk, and supporting automated or administrator-approved response actions.

The project focuses on smart home and Internet of Things (IoT) devices, which often have limited built-in security mechanisms, restricted hardware resources, and inconsistent vendor support. Instead of installing additional software on each device, the system applies security monitoring and response mechanisms at the network level.

## Project Goal

The main goal of this project is to create an intrusion detection and prevention system for smart home devices that detects cyber intrusions based on identified anomalies and supports response actions to reduce the potential impact of threats.

## Main Features

- Automatic discovery of smart home devices in the local network
- Device identification and classification based on network metadata
- DNS query monitoring and filtering
- Integration with intrusion detection data sources
- Network flow collection and analysis
- GeoIP-based traffic visibility and risk evaluation
- Vulnerability assessment using public vulnerability data sources
- Device risk evaluation and prioritisation
- Security policy assignment by device or device category
- Access control using whitelist and blacklist rules
- UPnP/NAT-PMP monitoring
- Incident generation and management
- Correlation of security events from multiple sources
- Automated and manual response actions
- Packet capture support for incident investigation
- Notifications through enabled channels
- Audit logging and security reporting
- Home Assistant dashboard for centralised system monitoring

## System Architecture

The system follows a modular architecture and integrates several security and monitoring components into a unified management environment.

The main components include:

- **Security Core API** – central backend service for managing devices, incidents, policies, actions, and reports.
- **PostgreSQL database** – stores inventory data, security events, incidents, policies, vulnerabilities, audit logs, and system health information.
- **Home Assistant dashboard** – provides a visual interface for monitoring and controlling the system.
- **OPNsense integration** – used for firewall, network flow, alias, and policy enforcement functions.
- **AdGuard Home integration** – used for DNS filtering and DNS query analysis.
- **Suricata integration** – used for intrusion detection alerts.
- **GeoIP module** – enriches external network connections with geographical information.
- **Vulnerability mirror** – stores and synchronises vulnerability data from public sources.
- **Anomaly engine** – identifies unusual device behaviour based on observed network activity.
- **Correlation engine** – correlates multiple security signals related to the same device.
- **Response engine** – creates and applies response actions such as quarantine, DNS-only mode, rate limiting, or dynamic firewall blocking.
- **Report and capture modules** – support incident documentation, audit exports, and PCAP capture for further analysis.

## Technologies Used

- Python
- FastAPI
- PostgreSQL
- Home Assistant
- OPNsense
- AdGuard Home
- Suricata
- Nmap
- GeoIP / MMDB
- systemd timers and services
- YAML, JSON, SQL


## License

All rights reserved.

Copyright © 2026 Deividas Kurmis.

This repository contains proprietary code, configuration files, documentation, and other confidential information developed as part of a Master's thesis project. Unauthorized copying, distribution, modification, publication, or use of any part of this repository is strictly prohibited.

If you wish to use, modify, reproduce, or distribute this code or any related materials, you must obtain explicit written approval from the repository owner.
