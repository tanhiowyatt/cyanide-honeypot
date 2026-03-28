# Security Policy

## Supported Versions

We provide security updates for the latest version of Cyanide available on the `main` branch. If you are using an older version, we recommend upgrading to the latest release to ensure you have the most recent security fixes.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability within Cyanide, we want to address it as quickly as possible. Please report it privately to the maintainers:

- **Primary Contact**: tanhiowyatt (via GitHub profile contact)

Please include the following in your report:
- A description of the vulnerability.
- Steps to reproduce the issue (PoC).
- Potential impact and any suggested mitigations.

We will acknowledge receipt of your report within 48 hours and provide a timeline for a fix and public disclosure.

## Honeypot Safety & Risks

Running a honeypot inherently involves exposure to malicious actors. While Cyanide is designed with strong isolation mechanisms (such as the VFS layer and Dockerization), users should be aware of the following:

1.  **Isolation**: Always run Cyanide in a dedicated, isolated environment (VLAN/Cloud VPC) to prevent lateral movement if a container escape occurs.
2.  **Resources**: Monitor resource usage (CPU/Memory) to prevent Denial of Service (DoS) attacks from impacting your host.
3.  **Data Exposure**: Do not place real credentials or sensitive production data inside the honeypot's virtual filesystem (OS Profiles).

## Our Commitment

We are committed to providing a secure and reliable tool for the research community. We perform regular security scans, dependency audits, and follow secure coding practices.

**Thank you for helping keep Cyanide and its users safe!**
