import json


def gen_alert(result):
    alerts = []
    high_risk = {23: "telnet", 445: "SMB", 3389: "RDP", 3306: "MYSQL"}

    medium_risk = {21: "FTP", 25: "SMTP", 22: "SSH"}
    for port in result["open_ports"]:
        if port in high_risk:
            alerts.append(
                {
                    "severity": "High",
                    "port": port,
                    "service": high_risk[port],
                    "host": result["host"],
                }
            )
        elif port in medium_risk:
            alerts.append(
                {
                    "severity": "medium",
                    "port": port,
                    "service": medium_risk[port],
                    "host": result["host"],
                }
            )

    return alerts
