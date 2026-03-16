import hashlib
from typing import Optional

import aiohttp


class VTScanner:
    """
    Asynchronous VirusTotal Scanner.
    Checks file hash against VT database. If unknown, uploads the file.
    """

    # Function 98: Initializes the class instance and its attributes.
    def __init__(self, api_key: str, logger=None):
        self.api_key = api_key
        self.logger = logger
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key}
        self.enabled = bool(api_key and api_key != "YOUR_API_KEY")

    # Function 99: Performs operations related to scan.
    async def scan(self, content: bytes, filename: str) -> Optional[dict]:
        """
        Scan a file.
        Returns a simplified dict of results:
        {
            "sha256": "...",
            "malicious": 5,
            "suspicious": 1,
            "label": "trojan.linux.bot/mirai",
            "link": "..."
        }
        """
        if not self.enabled:
            return None

        sha256 = hashlib.sha256(content).hexdigest()
        result = {
            "sha256": sha256,
            "malicious": 0,
            "suspicious": 0,
            "label": "unknown",
            "link": f"https://www.virustotal.com/gui/file/{sha256}",
            "status": "checked",
        }

        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.base_url}/files/{sha256}"
                async with session.get(url, headers=self.headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        attributes = data.get("data", {}).get("attributes", {})
                        stats = attributes.get("last_analysis_stats", {})

                        result["malicious"] = stats.get("malicious", 0)
                        result["suspicious"] = stats.get("suspicious", 0)

                        threat_info = attributes.get("popular_threat_classification", {})
                        if threat_info:
                            result["label"] = threat_info.get("suggested_threat_label", "detected")
                        elif int(str(result["malicious"])) > 0:
                            result["label"] = "generic_malware"
                        else:
                            result["label"] = "clean"

                        return result

                    elif resp.status == 404:
                        result["status"] = "uploaded_queued"

                        upload_url = f"{self.base_url}/files"
                        form = aiohttp.FormData()
                        form.add_field("utils", content, filename=filename)

                        async with session.post(
                            upload_url, headers=self.headers, data=form
                        ) as upload_resp:
                            if upload_resp.status == 200:
                                upload_data = await upload_resp.json()
                                analysis_id = upload_data.get("data", {}).get("id")
                                result["analysis_id"] = analysis_id
                                result["info"] = "File uploaded to VirusTotal. Analysis pending."
                                return result
                            else:
                                result["error"] = f"Upload failed: {upload_resp.status}"
                                return result
                    elif resp.status == 401:
                        if self.logger:
                            self.logger.log_event(
                                "system", "vt_error", {"status": 401, "message": "Unauthorized"}
                            )
                        self.enabled = False
                        return None
                    elif resp.status == 429:
                        if self.logger:
                            self.logger.log_event(
                                "system", "vt_error", {"status": 429, "message": "Quota Exceeded"}
                            )
                        return None
                    else:
                        if self.logger:
                            self.logger.log_event(
                                "system",
                                "vt_error",
                                {"status": resp.status, "message": "Other error"},
                            )
                        return None

        except Exception as e:
            if self.logger:
                self.logger.log_event("system", "vt_exception", {"error": str(e)})
            return None

        return result
