import re
import json


def fingerprint_service(port, banner):

    original_banner = banner

    with open("services.json", "r") as file:
        services = json.load(file)

    service = "Unknown"
    vendor = "Unknown"
    version = "Unknown"

    if not banner:
        service = services.get(str(port), "Unknown")
        pass

    else:
        banner = banner.lower()
        # ---------- OpenSSH ----------
        if "openssh" in banner:
            service = "SSH"
            vendor = "OpenSSH"

            match = re.search(r"openssh[_/ ]([\d\.p]+)", banner)
            if match:
                version = match.group(1)

        # ---------- Apache ----------
        elif "apache" in banner:
            service = "HTTP"
            vendor = "Apache"

            match = re.search(r"apache/?([\d\.]+)", banner)
            if match:
                version = match.group(1)

        # ---------- Nginx ----------
        elif "nginx" in banner:
            service = "HTTP"
            vendor = "Nginx"

            match = re.search(r"nginx/?([\d\.]+)", banner)
            if match:
                version = match.group(1)

        # ---------- MySQL ----------
        elif "mysql" in banner:
            service = "MySQL"
            vendor = "Oracle"

            match = re.search(r"([\d\.]+).*mysql", banner)
            if match:
                version = match.group(1)

        # ---------- Microsoft IIS ----------
        elif "microsoft-iis" in banner:
            service = "HTTP"
            vendor = "Microsoft"

            match = re.search(r"microsoft-iis/?([\d\.]+)", banner)
            if match:
                version = match.group(1)

        # ---------- ProFTPD ----------
        elif "proftpd" in banner:
            service = "FTP"
            vendor = "ProFTPD"

            match = re.search(r"proftpd/?([\d\.]+)", banner)
            if match:
                version = match.group(1)

        # ---------- vsFTPd ----------
        elif "vsftpd" in banner:
            service = "FTP"
            vendor = "vsFTPd"

            match = re.search(r"vsftpd/?([\d\.]+)", banner)
            if match:
                version = match.group(1)

        # ---------- Postfix ----------
        elif "postfix" in banner:
            service = "SMTP"
            vendor = "Postfix"

            match = re.search(r"postfix/?([\d\.]+)", banner)
            if match:
                version = match.group(1)

        # ---------- Exim ----------
        elif "exim" in banner:
            service = "SMTP"
            vendor = "Exim"

            match = re.search(r"exim/?([\d\.]+)", banner)
            if match:
                version = match.group(1)

    return {
        "port": port,
        "service": service,
        "vendor": vendor,
        "version": version,
        "banner": original_banner,
    }
