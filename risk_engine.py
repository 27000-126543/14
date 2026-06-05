from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from decimal import Decimal
from difflib import SequenceMatcher
import ipaddress

from config import config, RiskAssessmentConfig
from models import (
    Asset,
    Vulnerability,
    VulnerabilityInstance,
    SeverityEnum,
    VulnStatusEnum,
    FixStatusEnum,
)
from database import db_manager
from logger import logger, log_with_context
from collector import VulnRawData


@dataclass
class ProcessingResult:
    total: int = 0
    new: int = 0
    updated: int = 0
    duplicate: int = 0
    high_risk: int = 0
    new_assets: int = 0
    errors: List[str] = field(default_factory=list)
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None

    @property
    def duration_seconds(self) -> float:
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total": self.total,
            "new": self.new,
            "updated": self.updated,
            "duplicate": self.duplicate,
            "high_risk": self.high_risk,
            "new_assets": self.new_assets,
            "errors": self.errors,
            "duration_seconds": self.duration_seconds,
        }


class Deduplicator:
    def __init__(self, time_window_days: int = 7, title_similarity_threshold: float = 0.85):
        self.time_window_days = time_window_days
        self.title_similarity_threshold = title_similarity_threshold
        self.logger = logger

    def _get_exact_key(self, vuln_data: Dict[str, Any], asset_id: int, source: str) -> str:
        cve_id = vuln_data.get("cve_id", "") or ""
        return f"exact_{cve_id}_{asset_id}_{source}"

    def _get_fuzzy_key(self, vuln_data: Dict[str, Any], asset_ip: str) -> str:
        cvss = vuln_data.get("cvss_score", 0) or 0
        cvss_floor = int(float(cvss))
        return f"fuzzy_{asset_ip}_{cvss_floor}"

    def _calc_title_similarity(self, title1: str, title2: str) -> float:
        if not title1 or not title2:
            return 0.0
        return SequenceMatcher(None, title1.lower(), title2.lower()).ratio()

    def _is_within_time_window(self, last_seen: datetime) -> bool:
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.time_window_days)
        return last_seen >= cutoff

    def _merge_vuln_data(
        self, existing: Dict[str, Any], new: Dict[str, Any]
    ) -> Dict[str, Any]:
        existing_cvss = float(existing.get("cvss_score") or 0)
        new_cvss = float(new.get("cvss_score") or 0)

        if new_cvss > existing_cvss:
            existing["cvss_score"] = Decimal(str(new_cvss))
            existing["severity"] = new.get("severity", existing["severity"])

        existing_refs = existing.get("reference", "") or ""
        new_refs = new.get("reference", "") or ""
        if new_refs and new_refs not in existing_refs:
            merged_refs = existing_refs + ", " + new_refs if existing_refs else new_refs
            existing["reference"] = merged_refs[:4000]

        existing["last_seen"] = datetime.now(timezone.utc)

        existing_extra = existing.get("extra_data", {}) or {}
        new_extra = new.get("extra_data", {}) or {}
        if new_extra:
            merged_extra = {**existing_extra, **new_extra}
            existing["extra_data"] = merged_extra

        return existing

    def deduplicate_batch(
        self,
        vuln_asset_pairs: List[Tuple[Dict[str, Any], Optional[Asset]]],
        existing_vulns: List[Vulnerability],
        existing_instances: List[VulnerabilityInstance],
    ) -> Tuple[List[Tuple[Dict[str, Any], Optional[Asset]]], List[Dict[str, Any]], int]:
        exact_map: Dict[str, Tuple[Vulnerability, VulnerabilityInstance]] = {}
        fuzzy_map: Dict[str, List[Tuple[Vulnerability, VulnerabilityInstance]]] = {}

        for vuln in existing_vulns:
            for inst in existing_instances:
                if inst.vuln_id == vuln.id:
                    exact_key = self._get_exact_key(
                        {"cve_id": vuln.cve_id}, inst.asset_id, vuln.source
                    )
                    exact_map[exact_key] = (vuln, inst)

                    fuzzy_key = None
                    for asset in [a for a in [] if a.id == inst.asset_id]:
                        pass
                    fuzzy_key = self._get_fuzzy_key(
                        {"cvss_score": float(vuln.cvss_score or 0)}, "unknown"
                    )
                    if fuzzy_key not in fuzzy_map:
                        fuzzy_map[fuzzy_key] = []
                    fuzzy_map[fuzzy_key].append((vuln, inst))

        new_vulns: List[Tuple[Dict[str, Any], Optional[Asset]]] = []
        update_vulns: List[Dict[str, Any]] = []
        duplicate_count = 0

        for vuln_data, asset in vuln_asset_pairs:
            if asset is None:
                new_vulns.append((vuln_data, asset))
                continue

            is_duplicate = False

            exact_key = self._get_exact_key(vuln_data, asset.id, vuln_data.get("source", ""))
            if exact_key in exact_map:
                existing_vuln, existing_inst = exact_map[exact_key]
                if self._is_within_time_window(existing_vuln.last_seen):
                    merged = self._merge_vuln_data(
                        {
                            "id": existing_vuln.id,
                            "cvss_score": existing_vuln.cvss_score,
                            "severity": existing_vuln.severity.value,
                            "reference": existing_vuln.reference,
                            "extra_data": existing_vuln.extra_data,
                        },
                        vuln_data,
                    )
                    update_vulns.append(merged)
                    duplicate_count += 1
                    is_duplicate = True
                    continue

            asset_ip = getattr(asset, "ip", "")
            fuzzy_key = self._get_fuzzy_key(vuln_data, asset_ip)
            if fuzzy_key in fuzzy_map:
                for existing_vuln, existing_inst in fuzzy_map[fuzzy_key]:
                    if existing_inst.asset_id != asset.id:
                        continue

                    title_sim = self._calc_title_similarity(
                        existing_vuln.title, vuln_data.get("title", "")
                    )
                    existing_cvss = float(existing_vuln.cvss_score or 0)
                    new_cvss = float(vuln_data.get("cvss_score") or 0)
                    cvss_close = abs(existing_cvss - new_cvss) <= 1.0

                    if (
                        title_sim >= self.title_similarity_threshold
                        and cvss_close
                        and self._is_within_time_window(existing_vuln.last_seen)
                    ):
                        merged = self._merge_vuln_data(
                            {
                                "id": existing_vuln.id,
                                "cvss_score": existing_vuln.cvss_score,
                                "severity": existing_vuln.severity.value,
                                "reference": existing_vuln.reference,
                                "extra_data": existing_vuln.extra_data,
                            },
                            vuln_data,
                        )
                        update_vulns.append(merged)
                        duplicate_count += 1
                        is_duplicate = True
                        break

            if not is_duplicate:
                new_vulns.append((vuln_data, asset))

        return new_vulns, update_vulns, duplicate_count


class RiskScorer:
    def __init__(self, risk_config: Optional[RiskAssessmentConfig] = None):
        self.risk_config = risk_config or config.risk_assessment
        self.asset_weight = self.risk_config.ASSET_IMPORTANCE_WEIGHT
        self.severity_weight = self.risk_config.VULN_SEVERITY_WEIGHT
        self.exploit_bonus = 10.0
        self.exposure_public = 15.0
        self.exposure_internal_core = 10.0
        self.logger = logger

    def _map_asset_importance(self, importance: int) -> float:
        importance = max(1, min(5, int(importance)))
        return (importance - 1) * 20.0 + 20.0

    def _get_severity_score(self, severity: str) -> float:
        severity_map = {
            "critical": 100.0,
            "high": 70.0,
            "medium": 40.0,
            "low": 10.0,
        }
        return severity_map.get(severity.lower(), 40.0)

    def _has_exploit(self, vuln_data: Dict[str, Any]) -> bool:
        extra_data = vuln_data.get("extra_data", {}) or {}
        if extra_data.get("has_exploit") or extra_data.get("has_poc"):
            return True
        reference = vuln_data.get("reference", "") or ""
        exploit_keywords = ["exploit-db", "exploitdb", "poc", "proof-of-concept", "exp"]
        return any(kw in reference.lower() for kw in exploit_keywords)

    def _get_exposure_factor(self, asset: Optional[Asset]) -> float:
        if asset is None:
            return 0.0
        asset_type = getattr(asset, "type", "").lower()
        importance = getattr(asset, "importance", 1)

        public_types = ["web", "dmz", "public", "internet", "外部", "公网"]
        if any(t in asset_type for t in public_types):
            return self.exposure_public

        core_types = ["database", "core", "critical", "数据库", "核心"]
        if any(t in asset_type for t in core_types) and importance >= 4:
            return self.exposure_internal_core

        return 0.0

    def calculate_risk_score(
        self, vuln_data: Dict[str, Any], asset: Optional[Asset]
    ) -> Tuple[Decimal, str]:
        asset_importance = getattr(asset, "importance", 3) if asset else 3
        asset_score = self._map_asset_importance(asset_importance)

        severity = vuln_data.get("severity", "medium")
        severity_score = self._get_severity_score(severity)

        exploit_available = 1.0 if self._has_exploit(vuln_data) else 0.0
        exploit_add = exploit_available * self.exploit_bonus

        exposure_factor = self._get_exposure_factor(asset)

        risk_score = (
            asset_score * self.asset_weight
            + severity_score * self.severity_weight
            + exploit_add
            + exposure_factor
        )

        risk_score = max(0.0, min(100.0, risk_score))
        risk_score = round(risk_score, 2)

        if risk_score >= 80:
            risk_level = "critical"
        elif risk_score >= 60:
            risk_level = "high"
        elif risk_score >= 30:
            risk_level = "medium"
        else:
            risk_level = "low"

        return Decimal(str(risk_score)), risk_level

    def get_formula_explanation(self) -> str:
        return (
            "风险评分计算公式:\n"
            f"risk_score = (asset_importance * {self.asset_weight}) "
            f"+ (vuln_severity_score * {self.severity_weight}) "
            f"+ (exploit_available * {self.exploit_bonus}) "
            f"+ (asset_exposure * factor)\n\n"
            "资产重要性映射:\n"
            "1→20, 2→40, 3→60, 4→80, 5→100\n\n"
            "漏洞严重程度评分:\n"
            "critical=100, high=70, medium=40, low=10\n\n"
            "Exploit加成: 有公开POC/EXP +10分\n\n"
            "资产暴露因子:\n"
            f"- 公网暴露: +{self.exposure_public}分\n"
            f"- 内网核心(重要性>=4): +{self.exposure_internal_core}分\n\n"
            "风险等级划分:\n"
            ">=80 → 高危(critical)\n"
            ">=60 → 中危(high)\n"
            ">=30 → 低危(medium)\n"
            "<30  → 信息类(low)"
        )


class AssetMatcher:
    def __init__(self):
        self.logger = logger
        self._asset_cache: Dict[str, Asset] = {}
        self._all_assets: List[Asset] = []

    def _load_all_assets(self, session) -> None:
        self._all_assets = session.query(Asset).all()
        self._asset_cache.clear()
        for asset in self._all_assets:
            if asset.ip:
                self._asset_cache[f"ip_{asset.ip}"] = asset
            if asset.name:
                self._asset_cache[f"name_{asset.name.lower()}"] = asset

    def _is_ip_in_network(self, ip_str: str, network_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            network = ipaddress.ip_network(network_str, strict=False)
            return ip in network
        except (ValueError, TypeError):
            return False

    def _fuzzy_match(
        self, vuln_data: Dict[str, Any], asset_info: Dict[str, Any]
    ) -> Optional[Asset]:
        hostname = asset_info.get("hostname", "") or ""
        ip = asset_info.get("ip", "") or ""

        for asset in self._all_assets:
            asset_name = getattr(asset, "name", "").lower()
            asset_ip = getattr(asset, "ip", "")

            if hostname and hostname.lower() in asset_name:
                return asset

            if asset_name and asset_name in hostname.lower():
                return asset

            if ip and asset_ip and "/" in asset_ip:
                if self._is_ip_in_network(ip, asset_ip):
                    return asset

        return None

    def match_asset(
        self, session, asset_info: Dict[str, Any], vuln_data: Dict[str, Any]
    ) -> Tuple[Optional[Asset], bool]:
        if not self._all_assets:
            self._load_all_assets(session)

        ip = asset_info.get("ip", "") or ""
        hostname = asset_info.get("hostname", "") or ""

        if ip:
            cached = self._asset_cache.get(f"ip_{ip}")
            if cached:
                return cached, False

        if hostname:
            cached = self._asset_cache.get(f"name_{hostname.lower()}")
            if cached:
                return cached, False

        fuzzy_match = self._fuzzy_match(vuln_data, asset_info)
        if fuzzy_match:
            return fuzzy_match, False

        new_asset = self._create_unregistered_asset(session, asset_info)
        return new_asset, True

    def _create_unregistered_asset(
        self, session, asset_info: Dict[str, Any]
    ) -> Asset:
        ip = asset_info.get("ip", "0.0.0.0")
        hostname = asset_info.get("hostname", "") or f"unregistered-{ip}"

        new_asset = Asset(
            name=hostname,
            ip=ip,
            type="未登记",
            importance=3,
            owner="unknown",
            department="unknown",
            description="自动创建的未登记资产",
        )
        session.add(new_asset)
        session.flush()

        self._asset_cache[f"ip_{ip}"] = new_asset
        if hostname:
            self._asset_cache[f"name_{hostname.lower()}"] = new_asset
        self._all_assets.append(new_asset)

        log_with_context(
            self.logger,
            "info",
            f"Created unregistered asset: {ip} ({hostname})",
            asset_ip=ip,
            asset_name=hostname,
        )

        return new_asset

    def match_assets_batch(
        self, session, vuln_raw_list: List[VulnRawData]
    ) -> Tuple[List[Tuple[Dict[str, Any], Optional[Asset]]], int]:
        self._load_all_assets(session)

        results: List[Tuple[Dict[str, Any], Optional[Asset]]] = []
        new_assets_count = 0

        for vuln_raw in vuln_raw_list:
            vuln_dict = {
                "cve_id": vuln_raw.cve_id,
                "title": vuln_raw.title,
                "description": vuln_raw.description,
                "severity": vuln_raw.severity,
                "cvss_score": vuln_raw.cvss_score,
                "cwe_id": vuln_raw.cwe_id,
                "reference": vuln_raw.reference,
                "source": vuln_raw.source,
                "extra_data": vuln_raw.extra_data,
            }

            for asset_info in vuln_raw.affected_assets:
                asset, is_new = self.match_asset(session, asset_info, vuln_dict)
                if is_new:
                    new_assets_count += 1

                vuln_copy = vuln_dict.copy()
                vuln_copy["port"] = asset_info.get("port")
                vuln_copy["protocol"] = asset_info.get("protocol")
                vuln_copy["location"] = asset_info.get("hostname")

                results.append((vuln_copy, asset))

        return results, new_assets_count


class HighRiskDetector:
    def __init__(self):
        self.logger = logger

    def _check_high_risk_rules(
        self,
        risk_score: Decimal,
        asset: Optional[Asset],
        vuln_data: Dict[str, Any],
    ) -> Tuple[bool, List[str]]:
        reasons: List[str] = []
        risk_score_float = float(risk_score)
        cvss_score = float(vuln_data.get("cvss_score") or 0)
        has_exploit = vuln_data.get("extra_data", {}).get("has_exploit", False)
        has_poc = vuln_data.get("extra_data", {}).get("has_poc", False)
        has_public_exploit = has_exploit or has_poc

        asset_importance = getattr(asset, "importance", 0) if asset else 0
        if risk_score_float >= 80 and asset_importance >= 4:
            reasons.append(
                f"风险分{risk_score_float:.1f}>=80且资产重要性{asset_importance}>=4（核心资产）"
            )

        if cvss_score >= 9.0 and has_public_exploit:
            reasons.append(f"CVSS={cvss_score:.1f}>=9.0且有公开EXP/POC")

        cve_id = vuln_data.get("cve_id", "")
        if not cve_id and cvss_score >= 7.0:
            reasons.append(f"0day漏洞（无CVE编号, CVSS={cvss_score:.1f}>=7.0）")

        asset_type = getattr(asset, "type", "") if asset else ""
        core_keywords = ["core", "critical", "database", "核心", "数据库", "业务系统"]
        if any(kw in asset_type.lower() for kw in core_keywords) and risk_score_float >= 60:
            reasons.append(f"影响核心业务系统（{asset_type}），风险分{risk_score_float:.1f}>=60")

        return len(reasons) > 0, reasons

    def detect(
        self,
        risk_score: Decimal,
        asset: Optional[Asset],
        vuln_data: Dict[str, Any],
    ) -> Tuple[bool, List[str]]:
        is_high_risk, reasons = self._check_high_risk_rules(
            risk_score, asset, vuln_data
        )

        if is_high_risk:
            log_with_context(
                self.logger,
                "warning",
                f"High risk vulnerability detected: {vuln_data.get('title', 'Unknown')}",
                risk_score=float(risk_score),
                reasons=reasons,
                cve_id=vuln_data.get("cve_id"),
                asset_ip=getattr(asset, "ip", "unknown") if asset else "unknown",
            )

        return is_high_risk, reasons


class VulnerabilityProcessor:
    def __init__(
        self,
        deduplicator: Optional[Deduplicator] = None,
        risk_scorer: Optional[RiskScorer] = None,
        asset_matcher: Optional[AssetMatcher] = None,
        high_risk_detector: Optional[HighRiskDetector] = None,
    ):
        self.deduplicator = deduplicator or Deduplicator()
        self.risk_scorer = risk_scorer or RiskScorer()
        self.asset_matcher = asset_matcher or AssetMatcher()
        self.high_risk_detector = high_risk_detector or HighRiskDetector()
        self.logger = logger

    def _get_deadline(self, risk_score: Decimal) -> datetime:
        score = float(risk_score)
        if score >= 80:
            hours = 24
        elif score >= 60:
            hours = 72
        elif score >= 30:
            hours = 168
        else:
            hours = 720
        return datetime.now(timezone.utc) + timedelta(hours=hours)

    def _convert_vuln_to_dict(
        self,
        vuln_data: Dict[str, Any],
        asset: Optional[Asset],
        is_high_priority: bool,
        reasons: List[str],
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        vuln_dict = {
            "cve_id": vuln_data.get("cve_id"),
            "title": vuln_data.get("title", ""),
            "description": vuln_data.get("description"),
            "severity": SeverityEnum(vuln_data.get("severity", "medium")),
            "cvss_score": (
                Decimal(str(vuln_data["cvss_score"]))
                if vuln_data.get("cvss_score") is not None
                else None
            ),
            "cwe_id": vuln_data.get("cwe_id"),
            "reference": vuln_data.get("reference"),
            "source": vuln_data.get("source", ""),
            "extra_data": {
                **(vuln_data.get("extra_data") or {}),
                "is_high_priority": is_high_priority,
                "high_risk_reasons": reasons,
            },
        }

        instance_dict = {
            "port": vuln_data.get("port"),
            "protocol": vuln_data.get("protocol"),
            "location": vuln_data.get("location"),
            "evidence": vuln_data.get("evidence"),
        }

        return vuln_dict, instance_dict

    def process_vulnerabilities(
        self, vuln_raw_list: List[VulnRawData]
    ) -> ProcessingResult:
        result = ProcessingResult(total=len(vuln_raw_list))

        if not vuln_raw_list:
            result.end_time = datetime.now(timezone.utc)
            return result

        try:
            with db_manager.get_session() as session:
                log_with_context(
                    self.logger,
                    "info",
                    f"Starting vulnerability processing: {len(vuln_raw_list)} raw items",
                    raw_count=len(vuln_raw_list),
                )

                matched_pairs, new_assets = self.asset_matcher.match_assets_batch(
                    session, vuln_raw_list
                )
                result.new_assets = new_assets

                existing_vulns = session.query(Vulnerability).filter(
                    Vulnerability.status == VulnStatusEnum.ACTIVE
                ).all()
                existing_instances = session.query(VulnerabilityInstance).all()

                new_vulns, update_vulns, duplicates = self.deduplicator.deduplicate_batch(
                    matched_pairs, existing_vulns, existing_instances
                )
                result.duplicate = duplicates

                vulns_to_insert: List[Dict[str, Any]] = []
                instances_to_insert: List[Dict[str, Any]] = []
                vuln_updates: List[Dict[str, Any]] = []

                for vuln_data, asset in new_vulns:
                    risk_score, _ = self.risk_scorer.calculate_risk_score(
                        vuln_data, asset
                    )
                    is_high_risk, reasons = self.high_risk_detector.detect(
                        risk_score, asset, vuln_data
                    )

                    if is_high_risk:
                        result.high_risk += 1

                    vuln_dict, inst_dict = self._convert_vuln_to_dict(
                        vuln_data, asset, is_high_risk, reasons
                    )
                    vuln_dict["first_seen"] = datetime.now(timezone.utc)
                    vuln_dict["last_seen"] = datetime.now(timezone.utc)
                    vuln_dict["status"] = VulnStatusEnum.ACTIVE

                    vulns_to_insert.append(vuln_dict)

                    instance = {
                        **inst_dict,
                        "asset_id": asset.id if asset else None,
                        "risk_score": risk_score,
                        "discovery_time": datetime.now(timezone.utc),
                        "fix_deadline": self._get_deadline(risk_score),
                        "fix_status": FixStatusEnum.PENDING,
                        "is_high_priority": is_high_risk,
                        "high_risk_reasons": "; ".join(reasons) if reasons else None,
                    }
                    instances_to_insert.append(instance)
                    result.new += 1

                for update_data in update_vulns:
                    vuln_updates.append({
                        "id": update_data["id"],
                        "cvss_score": update_data["cvss_score"],
                        "severity": SeverityEnum(update_data["severity"]),
                        "reference": update_data["reference"],
                        "last_seen": update_data.get("last_seen", datetime.now(timezone.utc)),
                        "extra_data": update_data.get("extra_data"),
                        "updated_at": datetime.now(timezone.utc),
                    })
                    result.updated += 1

                if vulns_to_insert:
                    db_manager.bulk_upsert(
                        session,
                        Vulnerability,
                        vulns_to_insert,
                        conflict_columns=["cve_id", "title", "source"],
                    )
                    session.flush()

                    vuln_map: Dict[str, int] = {}
                    for v in vulns_to_insert:
                        key = f"{v.get('cve_id', '')}_{v['title']}_{v['source']}"
                        db_vuln = (
                            session.query(Vulnerability)
                            .filter_by(
                                cve_id=v.get("cve_id"),
                                title=v["title"],
                                source=v["source"],
                            )
                            .first()
                        )
                        if db_vuln:
                            vuln_map[key] = db_vuln.id

                    final_instances = []
                    for v_data, inst in zip(vulns_to_insert, instances_to_insert):
                        key = f"{v_data.get('cve_id', '')}_{v_data['title']}_{v_data['source']}"
                        if key in vuln_map:
                            inst["vuln_id"] = vuln_map[key]
                            final_instances.append(inst)

                    if final_instances:
                        db_manager.bulk_upsert(
                            session,
                            VulnerabilityInstance,
                            final_instances,
                            conflict_columns=["vuln_id", "asset_id"],
                        )

                if vuln_updates:
                    db_manager.bulk_update(session, Vulnerability, vuln_updates)

                log_with_context(
                    self.logger,
                    "info",
                    f"Vulnerability processing completed",
                    **result.to_dict(),
                )

        except Exception as e:
            error_msg = f"Processing failed: {str(e)}"
            result.errors.append(error_msg)
            log_with_context(
                self.logger,
                "error",
                error_msg,
                exc_info=True,
            )
            raise

        result.end_time = datetime.now(timezone.utc)
        return result

    def get_risk_formula(self) -> str:
        return self.risk_scorer.get_formula_explanation()
