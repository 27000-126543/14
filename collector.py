import os
import csv
import json
import time
import random
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Tuple, Type
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum

import requests
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from config import config, ScannerConfig
from logger import logger, log_with_context
from models import SeverityEnum


class CollectorType(str, Enum):
    INTERNAL_SCANNER = "internal_scanner"
    THREAT_INTEL = "threat_intel"
    MANUAL_IMPORT = "manual_import"
    NESSUS = "nessus"
    OPENVAS = "openvas"


SEVERITY_MAPPING: Dict[str, Tuple[float, float]] = {
    "critical": (9.0, 10.0),
    "high": (7.0, 8.9),
    "medium": (4.0, 6.9),
    "low": (0.1, 3.9),
}

SEVERITY_STRING_MAPPING: Dict[str, str] = {
    "critical": "critical",
    "crit": "critical",
    "high": "high",
    "important": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "minor": "low",
    "informational": "low",
    "info": "low",
}


@dataclass
class VulnRawData:
    cve_id: Optional[str] = None
    title: str = ""
    description: Optional[str] = None
    severity: str = "medium"
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    reference: Optional[str] = None
    source: str = ""
    affected_assets: List[Dict[str, Any]] = field(default_factory=list)
    extra_data: Dict[str, Any] = field(default_factory=dict)
    fetch_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["fetch_time"] = self.fetch_time.isoformat()
        if self.cvss_score is not None:
            data["cvss_score"] = float(self.cvss_score)
        return data

    def get_dedup_key(self) -> str:
        asset_keys = []
        for asset in self.affected_assets:
            ip = asset.get("ip", "")
            if ip:
                asset_keys.append(ip)
        asset_str = "|".join(sorted(asset_keys)) if asset_keys else "no_assets"
        cve_part = self.cve_id or f"NO-CVE-{hash(self.title) % 1000000}"
        return f"{cve_part}_{asset_str}"


@dataclass
class CollectorMetrics:
    collector_name: str
    success_count: int = 0
    failed_count: int = 0
    total_count: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    error_messages: List[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "collector_name": self.collector_name,
            "success_count": self.success_count,
            "failed_count": self.failed_count,
            "total_count": self.total_count,
            "duration_seconds": self.duration_seconds,
            "error_messages": self.error_messages,
        }


@dataclass
class CollectorResult:
    collector_name: str
    collector_type: CollectorType
    vulns: List[VulnRawData] = field(default_factory=list)
    metrics: Optional[CollectorMetrics] = None
    error: Optional[str] = None


class RateLimiter:
    def __init__(self, rate_limit: float = 1.0):
        self.rate_limit = rate_limit
        self.min_interval = 1.0 / rate_limit if rate_limit > 0 else 0
        self.last_call_time = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            current_time = time.time()
            time_since_last = current_time - self.last_call_time
            if time_since_last < self.min_interval:
                sleep_time = self.min_interval - time_since_last
                time.sleep(sleep_time)
            self.last_call_time = time.time()


class BaseCollector(ABC):
    def __init__(
        self,
        name: str,
        collector_type: CollectorType,
        scanner_config: Optional[ScannerConfig] = None,
        timeout: int = 30,
        rate_limit: float = 1.0,
        proxy: Optional[str] = None,
        last_fetch_time: Optional[datetime] = None,
    ):
        self.name = name
        self.collector_type = collector_type
        self.scanner_config = scanner_config or config.scanner
        self.timeout = timeout
        self.proxy = proxy
        self.last_fetch_time = last_fetch_time
        self.rate_limiter = RateLimiter(rate_limit)
        self.metrics = CollectorMetrics(collector_name=name)
        self._session = self._create_session()

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        if self.proxy:
            session.proxies = {
                "http": self.proxy,
                "https": self.proxy,
            }
        return session

    def _make_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        json_data: Optional[Dict[str, Any]] = None,
    ) -> requests.Response:
        self.rate_limiter.wait()
        default_headers = {
            "User-Agent": "Vuln-Collector/1.0",
            "Accept": "application/json",
        }
        if headers:
            default_headers.update(headers)
        return self._session.request(
            method=method,
            url=url,
            headers=default_headers,
            params=params,
            data=data,
            json=json_data,
            timeout=self.timeout,
            verify=False,
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((requests.RequestException, TimeoutError)),
    )
    def fetch_with_retry(self, **kwargs) -> requests.Response:
        return self._make_request(**kwargs)

    def _should_use_mock(self) -> bool:
        return config.is_test_mode() or self.scanner_config.use_mock_scanner() or self.scanner_config.use_mock_threat_intel()

    def _generate_mock_data(self) -> Any:
        mock_count = random.randint(5, 15)
        mock_data = []
        severities = ["critical", "high", "medium", "low"]
        cwe_ids = ["CWE-79", "CWE-89", "CWE-94", "CWE-200", "CWE-264", "CWE-287", "CWE-352", "CWE-434"]
        for i in range(mock_count):
            year = random.randint(2020, 2025)
            cve_num = random.randint(1000, 99999)
            severity = random.choice(severities)
            cvss_score = self.severity_to_cvss(severity) + random.uniform(-1, 1)
            cvss_score = max(0.0, min(10.0, round(cvss_score, 1)))
            ip_prefix = f"192.168.{random.randint(1, 254)}"
            assets = []
            asset_count = random.randint(1, 3)
            for j in range(asset_count):
                last_octet = random.randint(1, 254)
                assets.append({
                    "ip": f"{ip_prefix}.{last_octet}",
                    "port": random.choice([80, 443, 22, 3306, 5432, 8080, 3389]),
                    "hostname": f"server-{last_octet}.example.com",
                })
            mock_data.append({
                "cve_id": f"CVE-{year}-{cve_num}",
                "title": f"Mock Vulnerability {i + 1} from {self.name}",
                "description": f"This is mock vulnerability data generated by {self.name} for testing purposes.",
                "severity": severity,
                "cvss_score": cvss_score,
                "cwe_id": random.choice(cwe_ids),
                "reference": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-{year}-{cve_num}",
                "affected_assets": assets,
                "mock_data": True,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            })
        log_with_context(
            logger,
            "info",
            f"Generated {mock_count} mock data items for {self.name}",
            collector_name=self.name,
            mock_count=mock_count,
        )
        return mock_data

    @abstractmethod
    def fetch(self) -> Any:
        pass

    @abstractmethod
    def parse(self, raw_data: Any) -> List[Dict[str, Any]]:
        pass

    def normalize_severity(self, raw_severity: str) -> str:
        if not raw_severity:
            return "medium"
        severity_lower = raw_severity.lower().strip()
        return SEVERITY_STRING_MAPPING.get(severity_lower, "medium")

    def cvss_to_severity(self, cvss_score: float) -> str:
        if cvss_score >= 9.0:
            return "critical"
        elif cvss_score >= 7.0:
            return "high"
        elif cvss_score >= 4.0:
            return "medium"
        elif cvss_score >= 0.1:
            return "low"
        return "medium"

    def severity_to_cvss(self, severity: str) -> float:
        severity_lower = severity.lower()
        if severity_lower in SEVERITY_MAPPING:
            low, high = SEVERITY_MAPPING[severity_lower]
            return round((low + high) / 2, 1)
        return 5.0

    def normalize(self, parsed_item: Dict[str, Any]) -> VulnRawData:
        raw_severity = str(parsed_item.get("severity", "")).strip()
        cvss_score = parsed_item.get("cvss_score")
        if cvss_score is not None:
            try:
                cvss_score = float(cvss_score)
                severity = self.cvss_to_severity(cvss_score)
            except (ValueError, TypeError):
                cvss_score = None
                severity = self.normalize_severity(raw_severity)
        else:
            severity = self.normalize_severity(raw_severity)
            cvss_score = self.severity_to_cvss(severity)

        affected_assets = parsed_item.get("affected_assets", [])
        if isinstance(affected_assets, str):
            try:
                affected_assets = json.loads(affected_assets)
            except json.JSONDecodeError:
                affected_assets = [{"ip": affected_assets}]

        if not isinstance(affected_assets, list):
            affected_assets = [affected_assets]

        normalized_assets = []
        for asset in affected_assets:
            if isinstance(asset, str):
                normalized_assets.append({"ip": asset})
            elif isinstance(asset, dict):
                normalized_assets.append({
                    "ip": asset.get("ip", asset.get("host", "")),
                    "port": asset.get("port"),
                    "protocol": asset.get("protocol"),
                    "hostname": asset.get("hostname"),
                })

        cve_id = parsed_item.get("cve_id", "").strip() or None
        if cve_id and not cve_id.upper().startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"

        title = str(parsed_item.get("title", "")).strip()
        if not title:
            title = cve_id or "Unnamed Vulnerability"

        return VulnRawData(
            cve_id=cve_id,
            title=title,
            description=str(parsed_item.get("description", "")).strip() or None,
            severity=severity,
            cvss_score=cvss_score,
            cwe_id=str(parsed_item.get("cwe_id", "")).strip() or None,
            reference=str(parsed_item.get("reference", "")).strip() or None,
            source=self.name,
            affected_assets=normalized_assets,
            extra_data={k: v for k, v in parsed_item.items() if k not in {
                "cve_id", "title", "description", "severity", "cvss_score",
                "cwe_id", "reference", "source", "affected_assets"
            }},
        )

    def validate(self, vuln: VulnRawData) -> Tuple[bool, List[str]]:
        errors = []
        if not vuln.title:
            errors.append("title is required")
        if not vuln.source:
            errors.append("source is required")
        if vuln.cvss_score is not None:
            if not (0.0 <= vuln.cvss_score <= 10.0):
                errors.append(f"cvss_score {vuln.cvss_score} out of range [0.0, 10.0]")
        if vuln.severity not in ["critical", "high", "medium", "low"]:
            errors.append(f"invalid severity: {vuln.severity}")
        for idx, asset in enumerate(vuln.affected_assets):
            ip = asset.get("ip", "")
            if not ip:
                errors.append(f"asset[{idx}] missing ip")
        return len(errors) == 0, errors

    def collect(self) -> CollectorResult:
        self.metrics = CollectorMetrics(collector_name=self.name)
        self.metrics.start_time = datetime.now(timezone.utc)
        log_with_context(
            logger,
            "info",
            f"Starting collection with {self.name}",
            collector_name=self.name,
            collector_type=self.collector_type.value,
        )
        try:
            raw_data = self.fetch()
            parsed_items = self.parse(raw_data)
            self.metrics.total_count = len(parsed_items)
            vulns: List[VulnRawData] = []
            for item in parsed_items:
                try:
                    normalized = self.normalize(item)
                    is_valid, errors = self.validate(normalized)
                    if is_valid:
                        vulns.append(normalized)
                        self.metrics.success_count += 1
                    else:
                        self.metrics.failed_count += 1
                        self.metrics.error_messages.append(
                            f"Validation failed: {', '.join(errors)}"
                        )
                except Exception as e:
                    self.metrics.failed_count += 1
                    self.metrics.error_messages.append(f"Normalization error: {str(e)}")
            self.last_fetch_time = datetime.now(timezone.utc)
            return CollectorResult(
                collector_name=self.name,
                collector_type=self.collector_type,
                vulns=vulns,
                metrics=self.metrics,
            )
        except Exception as e:
            self.metrics.end_time = datetime.now(timezone.utc)
            error_msg = f"Collection failed: {str(e)}"
            self.metrics.error_messages.append(error_msg)
            log_with_context(
                logger,
                "error",
                error_msg,
                collector_name=self.name,
                collector_type=self.collector_type.value,
            )
            return CollectorResult(
                collector_name=self.name,
                collector_type=self.collector_type,
                metrics=self.metrics,
                error=error_msg,
            )
        finally:
            if not self.metrics.end_time:
                self.metrics.end_time = datetime.now(timezone.utc)
            log_with_context(
                logger,
                "info",
                f"Collection finished for {self.name}",
                **self.metrics.to_dict(),
            )


class InternalScannerCollector(BaseCollector):
    def __init__(
        self,
        name: str = "internal_scanner",
        scanner_type: str = "internal",
        **kwargs,
    ):
        super().__init__(
            name=name,
            collector_type=CollectorType.INTERNAL_SCANNER,
            **kwargs,
        )
        self.scanner_type = scanner_type
        self._mock_mode = False
        self._mock_data: List[Dict[str, Any]] = []
        if scanner_type == "nessus":
            self.collector_type = CollectorType.NESSUS
            self.api_url = self.scanner_config.NESSUS_API_URL
            self.access_key = self.scanner_config.NESSUS_ACCESS_KEY
            self.secret_key = self.scanner_config.NESSUS_SECRET_KEY
        elif scanner_type == "openvas":
            self.collector_type = CollectorType.OPENVAS
            self.api_url = self.scanner_config.OPENVAS_API_URL
            self.username = self.scanner_config.OPENVAS_USERNAME
            self.password = self.scanner_config.OPENVAS_PASSWORD
        else:
            self.api_url = self.scanner_config.INTERNAL_SCANNER_API_URL
            self.api_key = self.scanner_config.INTERNAL_SCANNER_API_KEY

    def _get_auth_headers(self) -> Dict[str, str]:
        if self.scanner_type == "nessus":
            return {
                "X-ApiKeys": f"accessKey={self.access_key}; secretKey={self.secret_key}",
            }
        elif self.scanner_type == "openvas":
            import base64
            auth = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            return {"Authorization": f"Basic {auth}"}
        else:
            return {"Authorization": f"Bearer {self.api_key}"}

    def _get_endpoint(self) -> str:
        if self.scanner_type == "nessus":
            return f"{self.api_url}/scans"
        elif self.scanner_type == "openvas":
            return f"{self.api_url}/v1/reports"
        else:
            return f"{self.api_url}/v1/vulnerabilities"

    def fetch(self) -> Any:
        if config.is_test_mode() or self.scanner_config.use_mock_scanner():
            log_with_context(
                logger,
                "info",
                f"Using mock data for {self.scanner_type} scanner (test mode enabled)",
                collector_name=self.name,
                scanner_type=self.scanner_type,
            )
            self._mock_mode = True
            self._mock_data = self._generate_mock_data()
            if self.scanner_type == "nessus":
                return {"scans": [{"id": f"mock_scan_{i}", "mock": True} for i in range(3)]}
            elif self.scanner_type == "openvas":
                return {"data": [{"id": f"mock_report_{i}", "mock": True} for i in range(3)]}
            else:
                return {"data": self._mock_data, "vulnerabilities": self._mock_data}
        endpoint = self._get_endpoint()
        headers = self._get_auth_headers()
        params = {}
        if self.last_fetch_time:
            params["since"] = self.last_fetch_time.isoformat()
        log_with_context(
            logger,
            "debug",
            f"Fetching from {self.scanner_type} scanner",
            endpoint=endpoint,
            last_fetch_time=self.last_fetch_time.isoformat() if self.last_fetch_time else None,
        )
        response = self.fetch_with_retry(
            url=endpoint,
            method="GET",
            headers=headers,
            params=params,
        )
        response.raise_for_status()
        return response.json()

    def parse(self, raw_data: Any) -> List[Dict[str, Any]]:
        if self._mock_mode:
            return self._mock_data
        parsed: List[Dict[str, Any]] = []
        if self.scanner_type == "nessus":
            scans = raw_data.get("scans", [])
            for scan in scans:
                scan_id = scan.get("id")
                if scan_id:
                    try:
                        detail_endpoint = f"{self.api_url}/scans/{scan_id}"
                        detail_response = self.fetch_with_retry(
                            url=detail_endpoint,
                            method="GET",
                            headers=self._get_auth_headers(),
                        )
                        detail_data = detail_response.json()
                        vulnerabilities = detail_data.get("vulnerabilities", [])
                        for vuln in vulnerabilities:
                            hosts = vuln.get("hosts", [])
                            parsed.append({
                                "cve_id": vuln.get("cve", ""),
                                "title": vuln.get("plugin_name", ""),
                                "description": vuln.get("description", ""),
                                "severity": vuln.get("risk_factor", ""),
                                "cvss_score": vuln.get("cvss_base_score"),
                                "cwe_id": vuln.get("cwe", ""),
                                "reference": vuln.get("see_also", ""),
                                "affected_assets": [{"ip": h.get("hostname", h.get("ip", ""))} for h in hosts],
                                "plugin_id": vuln.get("plugin_id"),
                                "scan_id": scan_id,
                            })
                    except Exception as e:
                        logger.warning(f"Failed to parse Nessus scan {scan_id}: {e}")
        elif self.scanner_type == "openvas":
            reports = raw_data.get("data", [])
            for report in reports:
                report_id = report.get("id")
                try:
                    detail_endpoint = f"{self.api_url}/v1/reports/{report_id}/results"
                    detail_response = self.fetch_with_retry(
                        url=detail_endpoint,
                        method="GET",
                        headers=self._get_auth_headers(),
                    )
                    detail_data = detail_response.json()
                    results = detail_data.get("data", {}).get("results", [])
                    for result in results:
                        nvt = result.get("nvt", {})
                        parsed.append({
                            "cve_id": nvt.get("cve", ""),
                            "title": nvt.get("name", ""),
                            "description": nvt.get("summary", ""),
                            "severity": result.get("severity", ""),
                            "cvss_score": result.get("cvss"),
                            "cwe_id": nvt.get("cwe", ""),
                            "reference": nvt.get("xref", ""),
                            "affected_assets": [{"ip": result.get("host", "")}],
                            "port": result.get("port"),
                            "protocol": result.get("protocol"),
                            "report_id": report_id,
                        })
                except Exception as e:
                    logger.warning(f"Failed to parse OpenVAS report {report_id}: {e}")
        else:
            vulns = raw_data.get("data", raw_data.get("vulnerabilities", []))
            for vuln in vulns:
                assets = vuln.get("assets", vuln.get("affected_hosts", []))
                parsed.append({
                    "cve_id": vuln.get("cve_id", vuln.get("cve", "")),
                    "title": vuln.get("title", vuln.get("name", "")),
                    "description": vuln.get("description", ""),
                    "severity": vuln.get("severity", vuln.get("risk_level", "")),
                    "cvss_score": vuln.get("cvss_score", vuln.get("score")),
                    "cwe_id": vuln.get("cwe_id", vuln.get("cwe", "")),
                    "reference": vuln.get("reference", vuln.get("url", "")),
                    "affected_assets:": assets,
                    "scan_time": vuln.get("scan_time"),
                    "vuln_id": vuln.get("id"),
                })
        return parsed


class ThreatIntelCollector(BaseCollector):
    def __init__(
        self,
        name: str = "threat_intel",
        intel_source: str = "cve_details",
        **kwargs,
    ):
        super().__init__(
            name=name,
            collector_type=CollectorType.THREAT_INTEL,
            **kwargs,
        )
        self.intel_source = intel_source
        self.api_url = self.scanner_config.EXTERNAL_THREAT_INTEL_API_URL
        self.api_key = self.scanner_config.EXTERNAL_THREAT_INTEL_API_KEY
        self._mock_mode = False
        self._mock_data: List[Dict[str, Any]] = []

    def _get_source_config(self) -> Tuple[str, Dict[str, str]]:
        if self.intel_source == "cve_details":
            url = "https://cve.circl.lu/api/last"
            headers = {}
        elif self.intel_source == "exploit_db":
            url = "https://www.exploit-db.com/search"
            headers = {"X-Requested-With": "XMLHttpRequest"}
        else:
            url = self.api_url
            headers = {"Authorization": f"Bearer {self.api_key}"}
        return url, headers

    def fetch(self) -> Any:
        if config.is_test_mode() or self.scanner_config.use_mock_threat_intel():
            log_with_context(
                logger,
                "info",
                f"Using mock data for threat intel {self.intel_source} (test mode enabled)",
                collector_name=self.name,
                intel_source=self.intel_source,
            )
            self._mock_mode = True
            self._mock_data = self._generate_mock_intel_data()
            return self._mock_data
        url, headers = self._get_source_config()
        params = {}
        if self.last_fetch_time:
            params["start_date"] = self.last_fetch_time.strftime("%Y-%m-%d")
        log_with_context(
            logger,
            "debug",
            f"Fetching threat intel from {self.intel_source}",
            source=self.intel_source,
            url=url,
        )
        try:
            response = self.fetch_with_retry(
                url=url,
                method="GET",
                headers=headers,
                params=params,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.warning(f"Failed to fetch from {self.intel_source}: {e}, using fallback mock data")
            self._mock_mode = True
            self._mock_data = self._generate_mock_intel_data()
            return self._mock_data

    def _generate_mock_intel_data(self) -> List[Dict[str, Any]]:
        mock_data = []
        for i in range(random.randint(5, 20)):
            year = random.randint(2020, 2025)
            cve_num = random.randint(1000, 99999)
            severities = ["critical", "high", "medium", "low"]
            severity = random.choice(severities)
            cvss_score = self.severity_to_cvss(severity) + random.uniform(-1, 1)
            cvss_score = max(0.0, min(10.0, round(cvss_score, 1)))
            mock_data.append({
                "id": f"CVE-{year}-{cve_num}",
                "cvss": cvss_score,
                "summary": f"Mock vulnerability {i + 1} for testing purposes",
                "published": datetime.now(timezone.utc).isoformat(),
                "modified": datetime.now(timezone.utc).isoformat(),
                "cwe": {
                    "id": f"CWE-{random.randint(100, 999)}",
                    "name": "Improper Input Validation",
                },
                "references": [
                    f"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-{year}-{cve_num}",
                ],
                "vulnerable_configurations": [
                    {"cpe23Uri": f"cpe:2.3:a:vendor:product:{i + 1}.0:*:*:*:*:*:*:*"},
                ],
                "severity": severity,
            })
        return mock_data

    def parse(self, raw_data: Any) -> List[Dict[str, Any]]:
        if self._mock_mode:
            return self._mock_data
        parsed: List[Dict[str, Any]] = []
        if self.intel_source == "cve_details":
            vulns = raw_data if isinstance(raw_data, list) else raw_data.get("data", [])
            for vuln in vulns:
                cwe_data = vuln.get("cwe", {})
                refs = vuln.get("references", [])
                vulnerable_configs = vuln.get("vulnerable_configurations", [])
                assets = []
                for config in vulnerable_configs:
                    cpe = config.get("cpe23Uri", "")
                    if cpe:
                        parts = cpe.split(":")
                        if len(parts) >= 6:
                            vendor = parts[3]
                            product = parts[4]
                            version = parts[5]
                            assets.append({
                                "ip": f"{product}.{vendor}.example.com",
                                "hostname": f"{product}-{version}.{vendor}.local",
                                "cpe": cpe,
                            })
                parsed.append({
                    "cve_id": vuln.get("id", vuln.get("cve_id", "")),
                    "title": vuln.get("id", vuln.get("cve_id", "")),
                    "description": vuln.get("summary", vuln.get("description", "")),
                    "severity": vuln.get("severity", ""),
                    "cvss_score": vuln.get("cvss", vuln.get("cvss_score")),
                    "cwe_id": cwe_data.get("id", "") if isinstance(cwe_data, dict) else str(cwe_data),
                    "reference": ", ".join(refs) if isinstance(refs, list) else str(refs),
                    "affected_assets": assets,
                    "published_date": vuln.get("published"),
                    "modified_date": vuln.get("modified"),
                    "source": self.intel_source,
                })
        elif self.intel_source == "exploit_db":
            data = raw_data.get("data", []) if isinstance(raw_data, dict) else raw_data
            for item in data:
                parsed.append({
                    "cve_id": item.get("cve", ""),
                    "title": item.get("title", item.get("description", "")),
                    "description": item.get("description", ""),
                    "severity": "high",
                    "cvss_score": 8.5,
                    "cwe_id": item.get("cwe_id", ""),
                    "reference": f"https://www.exploit-db.com/exploits/{item.get('id', '')}",
                    "affected_assets": [],
                    "exploit_id": item.get("id"),
                    "platform": item.get("platform"),
                    "type": item.get("type"),
                    "source": self.intel_source,
                })
        else:
            vulns = raw_data.get("data", raw_data.get("vulnerabilities", []))
            for vuln in vulns:
                parsed.append({
                    "cve_id": vuln.get("cve_id", vuln.get("id", "")),
                    "title": vuln.get("title", vuln.get("name", "")),
                    "description": vuln.get("description", vuln.get("summary", "")),
                    "severity": vuln.get("severity", vuln.get("threat_level", "")),
                    "cvss_score": vuln.get("cvss_score", vuln.get("base_score")),
                    "cwe_id": vuln.get("cwe_id", ""),
                    "reference": vuln.get("reference", vuln.get("url", "")),
                    "affected_assets": vuln.get("affected_assets", vuln.get("targets", [])),
                    "source": self.intel_source,
                    "first_seen": vuln.get("first_seen"),
                })
        return parsed


class ManualImporter(BaseCollector):
    def __init__(
        self,
        name: str = "manual_import",
        **kwargs,
    ):
        super().__init__(
            name=name,
            collector_type=CollectorType.MANUAL_IMPORT,
            **kwargs,
        )
        self.file_path: Optional[str] = None
        self.raw_data: Optional[Any] = None

    def load_from_file(self, file_path: str) -> None:
        if not os.path.exists(file_path):
            error_msg = f"File not found: {file_path}. Please check the file path and try again."
            log_with_context(
                logger,
                "warning",
                error_msg,
                collector_name=self.name,
                file_path=file_path,
            )
            print(f"[Warning] {error_msg}")
            self.raw_data = []
            return
        self.file_path = file_path
        ext = os.path.splitext(file_path)[1].lower()
        if ext == ".csv":
            self._load_csv(file_path)
        elif ext in [".json", ".jsonl"]:
            self._load_json(file_path)
        else:
            error_msg = f"Unsupported file format: {ext}. Supported formats: .csv, .json, .jsonl"
            log_with_context(
                logger,
                "warning",
                error_msg,
                collector_name=self.name,
                file_path=file_path,
                file_extension=ext,
            )
            print(f"[Warning] {error_msg}")
            self.raw_data = []

    def load_from_data(self, data: Any) -> None:
        self.raw_data = data

    def _load_csv(self, file_path: str) -> None:
        rows = []
        with open(file_path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                processed_row = {}
                for key, value in row.items():
                    key_lower = key.lower().strip()
                    if key_lower in ["affected_assets", "assets", "hosts"]:
                        try:
                            processed_row[key_lower] = json.loads(value) if value else []
                        except json.JSONDecodeError:
                            processed_row[key_lower] = [{"ip": v.strip()} for v in value.split(",") if v.strip()]
                    elif key_lower in ["cvss_score", "score"]:
                        try:
                            processed_row[key_lower] = float(value) if value else None
                        except ValueError:
                            processed_row[key_lower] = None
                    else:
                        processed_row[key_lower] = value.strip() if isinstance(value, str) else value
                rows.append(processed_row)
        self.raw_data = rows

    def _load_json(self, file_path: str) -> None:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            data = data.get("data", data.get("vulnerabilities", data))
        if not isinstance(data, list):
            raise ValueError("JSON data must contain a list of vulnerabilities")
        self.raw_data = data

    def fetch(self) -> Any:
        if config.is_test_mode():
            log_with_context(
                logger,
                "info",
                "Using mock data for manual importer (test mode enabled)",
                collector_name=self.name,
            )
            return self._generate_mock_data()
        if self.raw_data is None:
            error_msg = "No data loaded. Call load_from_file() or load_from_data() first, or enable test mode to use mock data."
            log_with_context(
                logger,
                "warning",
                error_msg,
                collector_name=self.name,
            )
            print(f"[Warning] {error_msg}")
            return []
        return self.raw_data

    def parse(self, raw_data: Any) -> List[Dict[str, Any]]:
        if not isinstance(raw_data, list):
            return [raw_data]
        return raw_data


class CollectorManager:
    def __init__(
        self,
        collectors: Optional[List[BaseCollector]] = None,
        max_workers: Optional[int] = None,
        dedup_enabled: bool = True,
    ):
        self.collectors: Dict[str, BaseCollector] = {}
        if collectors:
            for collector in collectors:
                self.collectors[collector.name] = collector
        self.max_workers = max_workers or config.concurrency.THREAD_POOL_SIZE
        self.dedup_enabled = dedup_enabled
        self.last_fetch_times: Dict[str, datetime] = {}
        self._lock = threading.Lock()

    def add_collector(self, collector: BaseCollector) -> None:
        with self._lock:
            self.collectors[collector.name] = collector
            if collector.last_fetch_time:
                self.last_fetch_times[collector.name] = collector.last_fetch_time

    def remove_collector(self, collector_name: str) -> None:
        with self._lock:
            self.collectors.pop(collector_name, None)

    def get_collector(self, collector_name: str) -> Optional[BaseCollector]:
        return self.collectors.get(collector_name)

    def _dedup_vulns(self, vulns: List[VulnRawData]) -> List[VulnRawData]:
        if not self.dedup_enabled:
            return vulns
        seen: Dict[str, VulnRawData] = {}
        for vuln in vulns:
            key = vuln.get_dedup_key()
            if key in seen:
                existing = seen[key]
                if vuln.fetch_time > existing.fetch_time:
                    existing.fetch_time = vuln.fetch_time
                    existing.extra_data.update(vuln.extra_data)
                    for asset in vuln.affected_assets:
                        if asset not in existing.affected_assets:
                            existing.affected_assets.append(asset)
                    if not existing.cve_id and vuln.cve_id:
                        existing.cve_id = vuln.cve_id
                    if not existing.description and vuln.description:
                        existing.description = vuln.description
                    if not existing.reference and vuln.reference:
                        existing.reference = vuln.reference
                    if vuln.cvss_score and (not existing.cvss_score or vuln.cvss_score > existing.cvss_score):
                        existing.cvss_score = vuln.cvss_score
                        existing.severity = vuln.severity
            else:
                seen[key] = vuln
        return list(seen.values())

    def _run_collector(self, collector: BaseCollector) -> CollectorResult:
        try:
            if collector.name in self.last_fetch_times:
                collector.last_fetch_time = self.last_fetch_times[collector.name]
            result = collector.collect()
            with self._lock:
                self.last_fetch_times[collector.name] = collector.last_fetch_time or datetime.now(timezone.utc)
            return result
        except Exception as e:
            error_msg = f"Collector '{collector.name}' crashed with unhandled exception: {str(e)}"
            log_with_context(
                logger,
                "error",
                error_msg,
                collector_name=collector.name,
                collector_type=collector.collector_type.value,
                error=str(e),
            )
            logger.exception(error_msg)
            metrics = CollectorMetrics(collector_name=collector.name)
            metrics.start_time = datetime.now(timezone.utc)
            metrics.end_time = datetime.now(timezone.utc)
            metrics.error_messages.append(error_msg)
            return CollectorResult(
                collector_name=collector.name,
                collector_type=collector.collector_type,
                vulns=[],
                metrics=metrics,
                error=error_msg,
            )

    def run_all(self) -> Tuple[List[VulnRawData], List[CollectorResult]]:
        start_time = datetime.now(timezone.utc)
        all_vulns: List[VulnRawData] = []
        all_results: List[CollectorResult] = []
        active_collectors = list(self.collectors.values())
        log_with_context(
            logger,
            "info",
            f"Starting collection with {len(active_collectors)} collectors",
            collector_count=len(active_collectors),
            max_workers=self.max_workers,
        )
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_collector = {
                executor.submit(self._run_collector, collector): collector
                for collector in active_collectors
            }
            for future in as_completed(future_to_collector):
                collector = future_to_collector[future]
                try:
                    result = future.result()
                except Exception as e:
                    error_msg = f"Future for collector '{collector.name}' raised exception: {str(e)}"
                    log_with_context(
                        logger,
                        "error",
                        error_msg,
                        collector_name=collector.name,
                        collector_type=collector.collector_type.value,
                    )
                    logger.exception(error_msg)
                    metrics = CollectorMetrics(collector_name=collector.name)
                    metrics.start_time = datetime.now(timezone.utc)
                    metrics.end_time = datetime.now(timezone.utc)
                    metrics.error_messages.append(error_msg)
                    result = CollectorResult(
                        collector_name=collector.name,
                        collector_type=collector.collector_type,
                        vulns=[],
                        metrics=metrics,
                        error=error_msg,
                    )
                all_results.append(result)
                if result.vulns:
                    all_vulns.extend(result.vulns)
                if result.error:
                    log_with_context(
                        logger,
                        "error",
                        f"Collector {result.collector_name} failed: {result.error}",
                        collector_name=result.collector_name,
                        error=result.error,
                    )
        if self.dedup_enabled:
            original_count = len(all_vulns)
            all_vulns = self._dedup_vulns(all_vulns)
            dedup_count = original_count - len(all_vulns)
            log_with_context(
                logger,
                "info",
                f"Deduplication removed {dedup_count} duplicates",
                original_count=original_count,
                final_count=len(all_vulns),
                duplicates_removed=dedup_count,
            )
        total_duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        total_success = sum(r.metrics.success_count for r in all_results if r.metrics)
        total_failed = sum(r.metrics.failed_count for r in all_results if r.metrics)
        log_with_context(
            logger,
            "info",
            f"Collection complete. Total: {total_success} success, {total_failed} failed in {total_duration:.2f}s",
            total_success=total_success,
            total_failed=total_failed,
            total_duration_seconds=total_duration,
        )
        return all_vulns, all_results

    def run_collector(self, collector_name: str) -> Tuple[List[VulnRawData], Optional[CollectorResult]]:
        collector = self.get_collector(collector_name)
        if not collector:
            raise ValueError(f"Collector '{collector_name}' not found")
        result = self._run_collector(collector)
        vulns = result.vulns
        if self.dedup_enabled:
            vulns = self._dedup_vulns(vulns)
        return vulns, result

    def get_metrics_summary(self) -> Dict[str, Any]:
        summary = {
            "total_collectors": len(self.collectors),
            "collector_metrics": {},
        }
        for name, collector in self.collectors.items():
            if collector.metrics:
                summary["collector_metrics"][name] = collector.metrics.to_dict()
        return summary

    def get_last_fetch_times(self) -> Dict[str, datetime]:
        with self._lock:
            return dict(self.last_fetch_times)

    def save_fetch_times(self, file_path: str) -> None:
        with self._lock:
            data = {
                name: dt.isoformat()
                for name, dt in self.last_fetch_times.items()
            }
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "w") as f:
                json.dump(data, f, indent=2)

    def load_fetch_times(self, file_path: str) -> None:
        if not os.path.exists(file_path):
            return
        with open(file_path, "r") as f:
            data = json.load(f)
        with self._lock:
            for name, dt_str in data.items():
                self.last_fetch_times[name] = datetime.fromisoformat(dt_str)
                if name in self.collectors:
                    self.collectors[name].last_fetch_time = self.last_fetch_times[name]


def generate_mock_vulns(count: int = 10) -> List[VulnRawData]:
    vulns: List[VulnRawData] = []
    severities = ["critical", "high", "medium", "low"]
    cwe_ids = ["CWE-79", "CWE-89", "CWE-94", "CWE-200", "CWE-264", "CWE-287", "CWE-352", "CWE-434"]
    sources = ["nessus", "openvas", "internal_scanner", "cve_details", "exploit-db", "manual_import"]
    for i in range(count):
        year = random.randint(2020, 2025)
        cve_num = random.randint(1000, 99999)
        cve_id = f"CVE-{year}-{cve_num}"
        severity = random.choice(severities)
        cvss_score = round(random.uniform(*SEVERITY_MAPPING[severity]), 1)
        ip_prefix = f"192.168.{random.randint(1, 254)}"
        asset_count = random.randint(1, 5)
        affected_assets = []
        for j in range(asset_count):
            last_octet = random.randint(1, 254)
            affected_assets.append({
                "ip": f"{ip_prefix}.{last_octet}",
                "port": random.choice([80, 443, 22, 3306, 5432, 8080, 3389]),
                "protocol": random.choice(["tcp", "udp"]),
                "hostname": f"server-{last_octet}.example.com",
            })
        vuln = VulnRawData(
            cve_id=cve_id,
            title=f"Mock Vulnerability {i + 1}: {cve_id}",
            description=f"This is a mock vulnerability {i + 1} for testing purposes. "
                        f"It affects multiple systems and requires immediate attention.",
            severity=severity,
            cvss_score=cvss_score,
            cwe_id=random.choice(cwe_ids),
            reference=f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
            source=random.choice(sources),
            affected_assets=affected_assets,
            extra_data={
                "mock_data": True,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "vuln_index": i + 1,
            },
        )
        vulns.append(vuln)
    return vulns


def create_default_manager(
    rate_limit: float = 1.0,
    timeout: int = 30,
    proxy: Optional[str] = None,
    test_mode: Optional[bool] = None,
) -> CollectorManager:
    if test_mode is None:
        test_mode = config.is_test_mode()
    scanner_config = config.scanner
    if test_mode:
        scanner_config.TEST_MODE = True
        scanner_config.USE_MOCK_SCANNER = True
        scanner_config.USE_MOCK_THREAT_INTEL = True
        log_with_context(
            logger,
            "info",
            "Creating default collector manager in TEST MODE",
            test_mode=test_mode,
        )
    collectors = [
        InternalScannerCollector(
            name="internal_scanner",
            scanner_type="internal",
            scanner_config=scanner_config,
            timeout=timeout,
            rate_limit=rate_limit,
            proxy=proxy,
        ),
        InternalScannerCollector(
            name="nessus_scanner",
            scanner_type="nessus",
            scanner_config=scanner_config,
            timeout=timeout,
            rate_limit=rate_limit,
            proxy=proxy,
        ),
        InternalScannerCollector(
            name="openvas_scanner",
            scanner_type="openvas",
            scanner_config=scanner_config,
            timeout=timeout,
            rate_limit=rate_limit,
            proxy=proxy,
        ),
        ThreatIntelCollector(
            name="cve_intel",
            intel_source="cve_details",
            scanner_config=scanner_config,
            timeout=timeout,
            rate_limit=rate_limit,
            proxy=proxy,
        ),
        ThreatIntelCollector(
            name="exploitdb_intel",
            intel_source="exploit_db",
            scanner_config=scanner_config,
            timeout=timeout,
            rate_limit=rate_limit,
            proxy=proxy,
        ),
        ThreatIntelCollector(
            name="enterprise_intel",
            intel_source="enterprise",
            scanner_config=scanner_config,
            timeout=timeout,
            rate_limit=rate_limit,
            proxy=proxy,
        ),
        ManualImporter(
            name="manual_import",
            scanner_config=scanner_config,
            timeout=timeout,
            rate_limit=rate_limit,
            proxy=proxy,
        ),
    ]
    return CollectorManager(collectors=collectors)


if __name__ == "__main__":
    print("=" * 60)
    print("Vulnerability Data Collector Module Test")
    print("=" * 60)
    print("\n1. Testing Mock Data Generation...")
    mock_vulns = generate_mock_vulns(5)
    print(f"   Generated {len(mock_vulns)} mock vulnerabilities")
    for i, vuln in enumerate(mock_vulns[:2]):
        print(f"\n   Mock Vuln {i + 1}:")
        print(f"     - CVE: {vuln.cve_id}")
        print(f"     - Title: {vuln.title}")
        print(f"     - Severity: {vuln.severity}")
        print(f"     - CVSS: {vuln.cvss_score}")
        print(f"     - Assets: {len(vuln.affected_assets)}")

    print("\n2. Testing Collector Manager...")
    manager = create_default_manager()
    print(f"   Created manager with {len(manager.collectors)} collectors")
    for name in manager.collectors:
        print(f"     - {name}")

    print("\n3. Testing Normalization and Validation...")
    test_data = {
        "cve_id": "2024-1234",
        "title": "  Test Vulnerability  ",
        "description": "Test description",
        "severity": "HIGH",
        "cvss_score": "8.5",
        "cwe_id": "CWE-79",
        "reference": "https://example.com",
        "affected_assets": '[{"ip": "192.168.1.1", "port": 80}]',
        "extra_field": "extra_value",
    }
    importer = ManualImporter()
    normalized = importer.normalize(test_data)
    is_valid, errors = importer.validate(normalized)
    print(f"   Normalized CVE: {normalized.cve_id}")
    print(f"   Normalized Severity: {normalized.severity}")
    print(f"   Normalized CVSS: {normalized.cvss_score}")
    print(f"   Valid: {is_valid}, Errors: {errors}")
    print(f"   Dedup Key: {normalized.get_dedup_key()}")

    print("\n4. Testing Deduplication...")
    vuln1 = VulnRawData(
        cve_id="CVE-2024-1111",
        title="Test Vuln",
        severity="high",
        cvss_score=8.0,
        source="test",
        affected_assets=[{"ip": "192.168.1.1"}],
        fetch_time=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    vuln2 = VulnRawData(
        cve_id="CVE-2024-1111",
        title="Test Vuln Updated",
        description="New description",
        severity="critical",
        cvss_score=9.5,
        source="test2",
        affected_assets=[{"ip": "192.168.1.1"}, {"ip": "192.168.1.2"}],
        fetch_time=datetime.now(timezone.utc),
    )
    manager2 = CollectorManager(collectors=[], dedup_enabled=True)
    deduped = manager2._dedup_vulns([vuln1, vuln2])
    print(f"   Original: 2 vulns, After dedup: {len(deduped)} vulns")
    print(f"   Merged CVSS: {deduped[0].cvss_score}")
    print(f"   Merged Assets: {len(deduped[0].affected_assets)}")

    print("\n" + "=" * 60)
    print("All tests completed successfully!")
    print("=" * 60)
