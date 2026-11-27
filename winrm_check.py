"""Optional pywinrm adapter. No shell creation or command execution."""
import json
import sys
import xml.etree.ElementTree as ET

try:
    import requests
    from winrm.protocol import Protocol
    from winrm.exceptions import InvalidCredentialsError
except ImportError:
    print("MISSING")
    sys.exit(0)

# Keep all requests on the specified endpoint, including negotiation requests.
original_send = requests.Session.send

def no_redirect_send(self, request, **kwargs):
    kwargs["allow_redirects"] = False
    return original_send(self, request, **kwargs)

requests.Session.send = no_redirect_send

try:
    cfg = json.load(sys.stdin)
    timeout = max(2, int(cfg["timeout"]))
    protocol = Protocol(
        endpoint=cfg["endpoint"],
        transport="ntlm",
        username=cfg["username"],
        password=cfg["password"],
        server_cert_validation="validate",
        message_encryption="auto",
        operation_timeout_sec=max(1, timeout - 1),
        read_timeout_sec=timeout,
    )
    response = protocol.send_message(cfg["envelope"])
    root = ET.fromstring(response)
    ns = {"s": "http://www.w3.org/2003/05/soap-envelope", "a": "http://schemas.xmlsoap.org/ws/2004/08/addressing"}
    action = root.findtext("s:Header/a:Action", default="", namespaces=ns)
    body = root.find("s:Body", ns)
    if action.endswith("/GetResponse") and body is not None and len(body) and body.find("s:Fault", ns) is None:
        print("VALID")
    else:
        print("UNVERIFIED")
except InvalidCredentialsError:
    print("DENIED")
except Exception as exc:
    # Do not print remote response content or credentials.
    message = str(exc).upper()
    if "ACCOUNT_LOCKED_OUT" in message or "0XC0000234" in message:
        print("LOCKED")
    else:
        print("UNVERIFIED")
