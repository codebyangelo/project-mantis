import json
import ipaddress
import re
from pathlib import Path

class BaselineEngine:
    def __init__(self, kb_path: str):
        self.kb = {}
        if Path(kb_path).exists():
            with open(kb_path, 'r') as f:
                self.kb = json.load(f)

    def evaluate(self, artifact_str: str) -> list:
        tags = []
        try:
            artifact = json.loads(artifact_str)
        except:
            return tags

        # Network baselines
        ip_addresses = self._extract_ips(artifact_str)
        for ip in ip_addresses:
            try:
                addr = ipaddress.ip_address(ip)
                if addr.is_private:
                    tags.append(f"NET_BASELINE_RFC1918:{ip}")
                for corp_net in self.kb.get("corporate_subnets", []):
                    if addr in ipaddress.ip_network(corp_net):
                        tags.append(f"NET_BASELINE_CORPORATE:{ip}")
            except ValueError:
                pass

        # Software JIT Baselines
        artifact_str_lower = artifact_str.lower()
        for jit in self.kb.get("jit_compilers", []):
            if jit in artifact_str_lower:
                tags.append(f"SW_BASELINE_JIT:{jit}")

        # Cloud sync mounts
        for cloud_path in self.kb.get("cloud_sync_paths", []):
            if re.search(cloud_path, artifact_str, re.IGNORECASE):
                tags.append(f"PATH_BASELINE_CLOUD:{cloud_path}")

        return list(set(tags))

    def _extract_ips(self, text: str) -> list:
        return re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
