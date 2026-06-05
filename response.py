from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict
from decimal import Decimal
import json
import re

from sqlalchemy import and_, or_, func
from sqlalchemy.orm import Session

from config import config
from models import (
    ResponsePlan, PlanStatus, MeasureStatus, VulnType,
    VulnerabilityInstance, Vulnerability, Asset, Incident,
    IncidentTypeEnum, IncidentStatusEnum, SeverityEnum,
    Notification, NotificationTypeEnum, NotificationStatusEnum
)
from database import db_manager, with_session, with_read_session
from logger import logger, log_audit, with_log_context
from work_order import NotificationService


RANSOMWARE_KEYWORDS = [
    "ransomware", "勒索", "encrypt", "加密", "wannacry", "petya",
    "notpetya", "locky", "cerber", "crypto", "bitcoin", "赎金"
]

RCE_KEYWORDS = [
    "rce", "remote code execution", "远程代码执行", "command injection",
    "命令注入", "code execution", "arbitrary code", "任意代码"
]

DATA_BREACH_KEYWORDS = [
    "data breach", "数据泄露", "information disclosure", "信息泄露",
    "sensitive data", "敏感数据", "personal data", "个人信息",
    "privilege escalation", "提权", "unauthorized access", "未授权访问"
]

SQL_INJECTION_KEYWORDS = [
    "sql injection", "sql注入", "sqli", "sql注入漏洞"
]

XSS_KEYWORDS = [
    "xss", "cross site scripting", "跨站脚本", "cross-site scripting"
]

DOS_KEYWORDS = [
    "dos", "denial of service", "拒绝服务", "ddos", "distributed denial of service"
]

CSRF_KEYWORDS = [
    "csrf", "cross site request forgery", "跨站请求伪造", "cross-site request forgery"
]

SSRF_KEYWORDS = [
    "ssrf", "server side request forgery", "服务端请求伪造", "server-side request forgery"
]

PRIVILEGE_ESCALATION_KEYWORDS = [
    "privilege escalation", "提权", "权限提升", "escalation of privilege"
]

CWE_TO_VULN_TYPE = {
    "CWE-78": VulnType.RCE,
    "CWE-79": VulnType.XSS,
    "CWE-89": VulnType.SQL_INJECTION,
    "CWE-94": VulnType.RCE,
    "CWE-200": VulnType.INFO_DISCLOSURE,
    "CWE-201": VulnType.DATA_BREACH,
    "CWE-264": VulnType.PRIVILEGE_ESCALATION,
    "CWE-276": VulnType.PRIVILEGE_ESCALATION,
    "CWE-352": VulnType.CSRF,
    "CWE-862": VulnType.PRIVILEGE_ESCALATION,
    "CWE-863": VulnType.PRIVILEGE_ESCALATION,
    "CWE-918": VulnType.SSRF,
    "CWE-306": VulnType.PRIVILEGE_ESCALATION,
    "CWE-287": VulnType.PRIVILEGE_ESCALATION,
    "CWE-319": VulnType.DATA_BREACH,
    "CWE-326": VulnType.DATA_BREACH,
    "CWE-502": VulnType.RCE,
    "CWE-611": VulnType.RCE,
    "CWE-732": VulnType.PRIVILEGE_ESCALATION,
    "CWE-77": VulnType.RCE,
    "CWE-88": VulnType.RCE,
    "CWE-400": VulnType.DOS,
    "CWE-770": VulnType.DOS,
    "CWE-835": VulnType.DOS,
}

ASSET_TYPE_TO_CONTACT = {
    "web_server": "web_security_team",
    "database": "dba_team",
    "application": "app_security_team",
    "network": "network_security_team",
    "cloud": "cloud_security_team",
    "container": "container_security_team",
    "default": "general_security_team"
}

EMERGENCY_CONTACTS = {
    "response_team_leader": "security_leader@example.com",
    "security_team": "security_team@example.com",
    "it_operations": "it_ops@example.com",
    "legal_department": "legal@example.com",
    "ciso": "ciso@example.com"
}

MEETING_LINK = "https://meeting.example.com/emergency-response"
COMMUNICATION_CHANNEL = "应急响应钉钉群 / Slack #security-incident"

RESPONSE_SLA = {
    "confirmation_minutes": 15,
    "mitigation_hours": 1,
    "isolation_hours": 4
}

VULN_TYPE_PLANS = {
    VulnType.RCE: {
        "isolation": [
            "立即断开受影响服务器网络连接",
            "限制访问IP白名单，仅允许应急响应团队访问",
            "禁用相关服务端口（如SSH、RDP、Web服务端口）",
            "隔离受影响网段，防止横向移动"
        ],
        "mitigation": [
            "部署WAF规则拦截恶意攻击流量",
            "启用流量清洗设备清洗异常流量",
            "应用虚拟补丁（如ModSecurity规则）",
            "检查并清除可疑进程和后门",
            "审计最近24小时访问日志"
        ],
        "root_fix": [
            "升级受影响软件至最新安全版本",
            "修复漏洞对应的代码缺陷",
            "加强访问控制和身份认证",
            "部署入侵检测系统（IDS/IPS）"
        ]
    },
    VulnType.DATA_BREACH: {
        "isolation": [
            "立即限制数据库访问权限",
            "切断受影响系统出口流量",
            "禁用可疑用户账号",
            "隔离疑似被入侵的主机"
        ],
        "mitigation": [
            "启用数据脱敏机制保护敏感数据",
            "回收过度授权的访问权限",
            "启用完整的数据库审计日志",
            "检查并重置可能泄露的凭证",
            "通知受影响的客户（如需要）"
        ],
        "root_fix": [
            "修复数据泄露漏洞根源",
            "加强数据分类分级保护",
            "部署数据防泄漏（DLP）系统",
            "完善访问控制策略"
        ]
    },
    VulnType.DOS: {
        "isolation": [
            "启动流量牵引机制",
            "配置黑洞路由过滤攻击流量",
            "临时下线非核心服务",
            "隔离攻击源IP段"
        ],
        "mitigation": [
            "启用CDN加速服务分散流量",
            "启动流量清洗中心清洗DDoS流量",
            "紧急扩容服务器和带宽资源",
            "配置限流和速率限制规则"
        ],
        "root_fix": [
            "优化系统架构提升抗DDoS能力",
            "部署专业DDoS防护设备",
            "建立多可用区冗余架构",
            "完善容量规划和弹性伸缩"
        ]
    },
    VulnType.SQL_INJECTION: {
        "isolation": [
            "临时下线存在注入漏洞的页面",
            "限制数据库账号最小权限",
            "隔离WEB应用服务器",
            "拦截攻击源IP"
        ],
        "mitigation": [
            "部署WAF SQL注入防护规则",
            "启用数据库防火墙",
            "检查并修复受损数据",
            "审计数据库异常查询日志"
        ],
        "root_fix": [
            "使用参数化查询修复SQL注入漏洞",
            "进行代码安全审计",
            "部署数据库安全网关",
            "加强开发安全培训"
        ]
    },
    VulnType.XSS: {
        "isolation": [
            "临时下线存在XSS漏洞的功能模块",
            "清除已存储的恶意脚本"
        ],
        "mitigation": [
            "部署WAF XSS防护规则",
            "启用CSP（内容安全策略）",
            "检查并修复被篡改的页面"
        ],
        "root_fix": [
            "对用户输入进行严格的过滤和转义",
            "完善前端和后端输入验证",
            "统一安全的输出编码机制"
        ]
    },
    VulnType.RANSOMWARE: {
        "isolation": [
            "立即断开受感染主机网络连接",
            "隔离受感染网段",
            "关闭可疑的共享文件夹",
            "禁用远程桌面和SSH服务"
        ],
        "mitigation": [
            "断开备份系统与网络的连接",
            "扫描并清除勒索软件",
            "检查并禁用可疑计划任务",
            "阻断勒索软件C2通信IP"
        ],
        "root_fix": [
            "从干净备份恢复数据",
            "升级操作系统和应用补丁",
            "部署EDR（端点检测与响应）",
            "加强员工安全意识培训"
        ]
    },
    VulnType.SSRF: {
        "isolation": [
            "限制云服务器元数据访问",
            "隔离内网敏感服务",
            "下线存在SSRF漏洞的功能"
        ],
        "mitigation": [
            "部署WAF SSRF防护规则",
            "配置出口流量白名单",
            "检查内网服务访问日志"
        ],
        "root_fix": [
            "修复SSRF漏洞，限制可访问的协议和地址",
            "使用独立的安全网络区域",
            "加强云基础设施安全配置"
        ]
    },
    VulnType.CSRF: {
        "isolation": [
            "临时下线存在CSRF漏洞的敏感操作接口"
        ],
        "mitigation": [
            "部署WAF CSRF防护规则",
            "检查并撤销可疑的操作记录"
        ],
        "root_fix": [
            "添加CSRF Token验证机制",
            "验证请求来源Referer",
            "关键操作增加二次认证"
        ]
    },
    VulnType.PRIVILEGE_ESCALATION: {
        "isolation": [
            "禁用可疑的高权限账号",
            "限制特权操作访问源",
            "隔离疑似被入侵的主机"
        ],
        "mitigation": [
            "启动特权操作审计",
            "检查并重置高权限账号密码",
            "回收可疑的权限分配"
        ],
        "root_fix": [
            "修复权限提升漏洞",
            "遵循最小权限原则重新分配权限",
            "部署特权账号管理系统（PAM）"
        ]
    },
    VulnType.OTHER: {
        "isolation": [
            "根据漏洞具体情况采取相应隔离措施",
            "限制受影响系统访问"
        ],
        "mitigation": [
            "部署通用WAF防护规则",
            "加强日志监控和异常检测"
        ],
        "root_fix": [
            "分析漏洞根本原因并修复",
            "加强系统安全配置"
        ]
    }
}


class VulnClassifier:
    def __init__(self):
        self.cwe_map = CWE_TO_VULN_TYPE
        self.keyword_maps = [
            (RANSOMWARE_KEYWORDS, VulnType.RANSOMWARE),
            (RCE_KEYWORDS, VulnType.RCE),
            (SQL_INJECTION_KEYWORDS, VulnType.SQL_INJECTION),
            (XSS_KEYWORDS, VulnType.XSS),
            (DATA_BREACH_KEYWORDS, VulnType.DATA_BREACH),
            (DOS_KEYWORDS, VulnType.DOS),
            (CSRF_KEYWORDS, VulnType.CSRF),
            (SSRF_KEYWORDS, VulnType.SSRF),
            (PRIVILEGE_ESCALATION_KEYWORDS, VulnType.PRIVILEGE_ESCALATION),
        ]

    def classify(self, vulnerability: Vulnerability) -> VulnType:
        if vulnerability.cwe_id:
            vuln_type = self.cwe_map.get(vulnerability.cwe_id)
            if vuln_type:
                logger.info(f"Classified vulnerability {vulnerability.id} by CWE {vulnerability.cwe_id} as {vuln_type.value}")
                return vuln_type

        title = (vulnerability.title or "").lower()
        description = (vulnerability.description or "").lower()
        combined = f"{title} {description}"

        for keywords, vuln_type in self.keyword_maps:
            for keyword in keywords:
                if keyword.lower() in combined:
                    logger.info(f"Classified vulnerability {vulnerability.id} by keyword '{keyword}' as {vuln_type.value}")
                    return vuln_type

        if vulnerability.severity == SeverityEnum.CRITICAL and vulnerability.cvss_score:
            if vulnerability.cvss_score >= Decimal('9.0'):
                logger.info(f"Classified critical vulnerability {vulnerability.id} as RCE by default")
                return VulnType.RCE

        logger.info(f"Classified vulnerability {vulnerability.id} as OTHER")
        return VulnType.OTHER

    def classify_by_title(self, title: str, cwe_id: Optional[str] = None) -> VulnType:
        if cwe_id:
            vuln_type = self.cwe_map.get(cwe_id)
            if vuln_type:
                return vuln_type

        title_lower = title.lower()
        for keywords, vuln_type in self.keyword_maps:
            for keyword in keywords:
                if keyword.lower() in title_lower:
                    return vuln_type

        return VulnType.OTHER

    def is_data_breach_risk(self, vuln_type: VulnType, asset_type: str) -> bool:
        high_risk_types = [
            VulnType.DATA_BREACH,
            VulnType.SQL_INJECTION,
            VulnType.PRIVILEGE_ESCALATION,
            VulnType.RCE,
            VulnType.INFO_DISCLOSURE
        ]
        sensitive_assets = ["database", "application", "web_server"]

        if vuln_type in high_risk_types and asset_type in sensitive_assets:
            return True

        return False

    def is_compliance_risk(self, vuln_type: VulnType, asset_type: str) -> bool:
        compliance_types = [
            VulnType.DATA_BREACH,
            VulnType.PRIVILEGE_ESCALATION,
            VulnType.INFO_DISCLOSURE,
            VulnType.RANSOMWARE
        ]
        return vuln_type in compliance_types


vuln_classifier = VulnClassifier()


class ResponseTrigger:
    def __init__(self):
        self.classifier = vuln_classifier
        self.risk_threshold = 80
        self.asset_importance_threshold = 4
        self.cvss_threshold = Decimal('9.0')
        self.core_asset_count_threshold = 10

    def _check_condition_high_risk_core_asset(self, vuln_instance: VulnerabilityInstance) -> Tuple[bool, str]:
        vuln = vuln_instance.vulnerability
        asset = vuln_instance.asset

        if (vuln_instance.risk_score >= self.risk_threshold and
                asset.importance >= self.asset_importance_threshold):
            reason = (f"高危漏洞（风险分{float(vuln_instance.risk_score)}）影响核心资产"
                      f"（重要性{asset.importance}）：{asset.name}({asset.ip})")
            return True, reason

        return False, ""

    def _check_condition_critical_0day_with_exp(self, vuln_instance: VulnerabilityInstance) -> Tuple[bool, str]:
        vuln = vuln_instance.vulnerability

        if vuln.cvss_score and vuln.cvss_score >= self.cvss_threshold:
            has_exp = False
            if vuln.extra_data:
                has_exp = vuln.extra_data.get('has_public_exp', False)

            description = (vuln.description or "").lower()
            title = (vuln.title or "").lower()
            exp_indicators = ["exploit", "exp", "poc", "proof of concept", "利用代码", "公开利用"]
            for indicator in exp_indicators:
                if indicator in description or indicator in title:
                    has_exp = True
                    break

            if has_exp:
                reason = (f"CVSS {float(vuln.cvss_score)} 高危漏洞存在公开EXP："
                          f"{vuln.title}")
                return True, reason

        return False, ""

    def _check_condition_ransomware_chain(self, vuln_instance: VulnerabilityInstance) -> Tuple[bool, str]:
        vuln = vuln_instance.vulnerability
        vuln_type = self.classifier.classify(vuln)

        if vuln_type == VulnType.RANSOMWARE:
            reason = (f"漏洞属于主动勒索软件利用链：{vuln.title}，"
                      f"受影响资产：{vuln_instance.asset.name}")
            return True, reason

        return False, ""

    def _check_condition_mass_core_asset_impact(self, vuln_instance: VulnerabilityInstance,
                                                session: Session) -> Tuple[bool, str]:
        vuln = vuln_instance.vulnerability

        count = session.query(func.count(VulnerabilityInstance.id)).filter(
            VulnerabilityInstance.vuln_id == vuln.id,
            VulnerabilityInstance.fix_status != "fixed",
            Asset.importance >= self.asset_importance_threshold
        ).join(Asset).scalar()

        if count >= self.core_asset_count_threshold:
            reason = (f"同一高危漏洞 {vuln.title} 影响 {count} 台核心资产"
                      f"（>= {self.core_asset_count_threshold} 台）")
            return True, reason

        return False, ""

    def should_trigger(self, vuln_instance: VulnerabilityInstance,
                       session: Session) -> Tuple[bool, str, str]:
        checks = [
            (self._check_condition_high_risk_core_asset(vuln_instance), "high_risk_core_asset"),
            (self._check_condition_critical_0day_with_exp(vuln_instance), "critical_0day_with_exp"),
            (self._check_condition_ransomware_chain(vuln_instance), "ransomware_chain"),
            (self._check_condition_mass_core_asset_impact(vuln_instance, session), "mass_core_asset_impact"),
        ]

        for (triggered, reason), condition_name in checks:
            if triggered:
                logger.info(f"Response triggered for vuln_instance {vuln_instance.id}: {condition_name}")
                return True, reason, condition_name

        return False, "", ""

    @with_session
    def check_and_trigger_response(self, vuln_instance_ids: List[int],
                                   operator: str = "system",
                                   session: Session = None) -> List[ResponsePlan]:
        triggered_plans = []

        for vuln_instance_id in vuln_instance_ids:
            try:
                vuln_instance = session.query(VulnerabilityInstance).filter_by(
                    id=vuln_instance_id
                ).first()

                if not vuln_instance:
                    logger.error(f"Vulnerability instance {vuln_instance_id} not found")
                    continue

                existing_plan = session.query(ResponsePlan).filter(
                    ResponsePlan.vuln_instance_id == vuln_instance_id,
                    ResponsePlan.status.in_([
                        PlanStatus.CREATED,
                        PlanStatus.CONFIRMED,
                        PlanStatus.EXECUTING
                    ])
                ).first()

                if existing_plan:
                    logger.warning(
                        f"Active response plan already exists for vuln_instance {vuln_instance_id}: "
                        f"plan {existing_plan.id}"
                    )
                    continue

                should_trigger, reason, condition_name = self.should_trigger(vuln_instance, session)

                if should_trigger:
                    plan_generator = PlanGenerator()
                    plan = plan_generator.generate_response_plan(
                        vuln_instance_id, reason, condition_name, operator, session=session
                    )

                    if plan:
                        notification_manager = NotificationManager()
                        notification_manager.notify_response_team(plan.id, session=session)

                        vuln_type = self.classifier.classify(vuln_instance.vulnerability)
                        asset_type = vuln_instance.asset.type
                        if (self.classifier.is_data_breach_risk(vuln_type, asset_type) or
                                self.classifier.is_compliance_risk(vuln_type, asset_type)):
                            legal_reason = "涉及数据泄露风险或合规要求"
                            notification_manager.notify_legal_department(
                                plan.id, legal_reason, operator, session=session
                            )

                        self._create_incident(plan, vuln_instance, operator, session)

                        triggered_plans.append(plan)

                        log_audit(
                            action="response_triggered",
                            resource_type="response_plan",
                            resource_id=str(plan.id),
                            detail=f"触发应急响应：{condition_name}，原因：{reason}",
                            user=operator
                        )

            except Exception as e:
                logger.exception(
                    f"Failed to check/trigger response for vuln_instance {vuln_instance_id}: {e}"
                )
                continue

        logger.info(f"Triggered {len(triggered_plans)} response plans from {len(vuln_instance_ids)} instances")
        return triggered_plans

    def _create_incident(self, plan: ResponsePlan, vuln_instance: VulnerabilityInstance,
                         operator: str, session: Session) -> Incident:
        vuln = vuln_instance.vulnerability
        vuln_type = self.classifier.classify(vuln)

        incident_type_map = {
            VulnType.RANSOMWARE: IncidentTypeEnum.MALWARE,
            VulnType.DATA_BREACH: IncidentTypeEnum.DATA_BREACH,
            VulnType.PRIVILEGE_ESCALATION: IncidentTypeEnum.UNAUTHORIZED_ACCESS,
            VulnType.DOS: IncidentTypeEnum.DOS_ATTACK,
        }
        incident_type = incident_type_map.get(vuln_type, IncidentTypeEnum.OTHER)

        incident = Incident(
            title=f"【应急响应】{vuln.title}",
            description=(f"应急响应预案 #{plan.id} 关联安全事件\n"
                        f"触发条件: {plan.trigger_condition}\n"
                        f"触发原因: {plan.trigger_reason}"),
            type=incident_type,
            severity=vuln.severity,
            status=IncidentStatusEnum.INVESTIGATING,
            assets_affected=plan.affected_assets,
            created_by=operator,
            assigned_to=EMERGENCY_CONTACTS["response_team_leader"]
        )

        session.add(incident)
        session.flush()

        plan.incident_id = incident.id

        logger.info(f"Created incident {incident.id} linked to response plan {plan.id}")
        return incident


response_trigger = ResponseTrigger()


class PlanGenerator:
    def __init__(self):
        self.classifier = vuln_classifier
        self.vuln_type_plans = VULN_TYPE_PLANS
        self.emergency_contacts = EMERGENCY_CONTACTS
        self.meeting_link = MEETING_LINK
        self.communication_channel = COMMUNICATION_CHANNEL

    def _get_affected_assets(self, vuln_instance: VulnerabilityInstance,
                             session: Session) -> List[Dict[str, Any]]:
        vuln = vuln_instance.vulnerability
        assets = []

        instances = session.query(VulnerabilityInstance).filter(
            VulnerabilityInstance.vuln_id == vuln.id,
            VulnerabilityInstance.fix_status != "fixed"
        ).all()

        for inst in instances:
            assets.append({
                "id": inst.asset_id,
                "name": inst.asset.name,
                "ip": inst.asset.ip,
                "type": inst.asset.type,
                "importance": inst.asset.importance,
                "department": inst.asset.department,
                "owner": inst.asset.owner,
                "risk_score": float(inst.risk_score)
            })

        return assets

    def _get_plan_template(self, vuln_type: VulnType,
                           asset_type: str) -> Dict[str, Any]:
        template = self.vuln_type_plans.get(vuln_type, self.vuln_type_plans[VulnType.OTHER])
        return template

    def _generate_contacts(self, asset_type: str,
                           department: str) -> List[Dict[str, Any]]:
        contacts = []

        contacts.append({
            "role": "应急响应组组长",
            "name": "应急响应组组长",
            "contact": self.emergency_contacts["response_team_leader"]
        })

        contacts.append({
            "role": "安全团队",
            "name": "安全团队",
            "contact": self.emergency_contacts["security_team"]
        })

        contacts.append({
            "role": "IT运维团队",
            "name": "IT运维团队",
            "contact": self.emergency_contacts["it_operations"]
        })

        team_key = ASSET_TYPE_TO_CONTACT.get(asset_type, ASSET_TYPE_TO_CONTACT["default"])
        contacts.append({
            "role": f"{asset_type}安全团队",
            "name": team_key,
            "contact": f"{team_key}@example.com"
        })

        if department:
            contacts.append({
                "role": "受影响部门负责人",
                "name": f"{department}负责人",
                "contact": f"head_{department}@example.com"
            })

        return contacts

    def _generate_knowledge_references(self, vuln: Vulnerability,
                                       vuln_type: VulnType) -> List[Dict[str, Any]]:
        references = []

        if vuln.reference:
            refs = vuln.reference.split('\n')
            for i, ref in enumerate(refs, 1):
                if ref.strip():
                    references.append({
                        "title": f"漏洞参考链接 {i}",
                        "url": ref.strip()
                    })

        if vuln.cve_id:
            references.append({
                "title": f"CVE详情: {vuln.cve_id}",
                "url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln.cve_id}"
            })

        kb_links = {
            VulnType.RCE: "https://sec.example.com/kb/rce-response",
            VulnType.SQL_INJECTION: "https://sec.example.com/kb/sql-injection-response",
            VulnType.XSS: "https://sec.example.com/kb/xss-response",
            VulnType.DATA_BREACH: "https://sec.example.com/kb/data-breach-response",
            VulnType.DOS: "https://sec.example.com/kb/ddos-response",
            VulnType.RANSOMWARE: "https://sec.example.com/kb/ransomware-response",
        }

        if vuln_type in kb_links:
            references.append({
                "title": f"{vuln_type.value} 应急响应知识库",
                "url": kb_links[vuln_type]
            })

        references.append({
            "title": "应急响应手册",
            "url": "https://sec.example.com/emergency-response-handbook"
        })

        references.append({
            "title": "安全事件报告流程",
            "url": "https://sec.example.com/incident-reporting"
        })

        return references

    def _init_measure_status(self, measures: List[str]) -> List[Dict[str, Any]]:
        return [
            {
                "id": idx,
                "description": measure,
                "status": MeasureStatus.PENDING.value,
                "completed_at": None,
                "operator": None,
                "remark": None
            }
            for idx, measure in enumerate(measures)
        ]

    @with_session
    def generate_response_plan(self, vuln_instance_id: int,
                               trigger_reason: str,
                               trigger_condition: str,
                               operator: str = "system",
                               session: Session = None) -> Optional[ResponsePlan]:
        try:
            vuln_instance = session.query(VulnerabilityInstance).filter_by(
                id=vuln_instance_id
            ).first()

            if not vuln_instance:
                logger.error(f"Vulnerability instance {vuln_instance_id} not found")
                return None

            vuln = vuln_instance.vulnerability
            asset = vuln_instance.asset

            vuln_type = self.classifier.classify(vuln)
            template = self._get_plan_template(vuln_type, asset.type)

            affected_assets = self._get_affected_assets(vuln_instance, session)
            contacts = self._generate_contacts(asset.type, asset.department)
            knowledge_references = self._generate_knowledge_references(vuln, vuln_type)

            isolation_measures = template["isolation"]
            mitigation_measures = template["mitigation"]
            root_fix_plan = template["root_fix"]

            isolation_status = self._init_measure_status(isolation_measures)
            mitigation_status = self._init_measure_status(mitigation_measures)

            plan = ResponsePlan(
                vuln_instance_id=vuln_instance_id,
                vuln_id=vuln.id,
                status=PlanStatus.CREATED,
                vuln_type=vuln_type,
                trigger_reason=trigger_reason,
                trigger_condition=trigger_condition,
                affected_assets=json.dumps(affected_assets, ensure_ascii=False),
                isolation_measures=json.dumps(isolation_measures, ensure_ascii=False),
                mitigation_measures=json.dumps(mitigation_measures, ensure_ascii=False),
                root_fix_plan=json.dumps(root_fix_plan, ensure_ascii=False),
                contacts=json.dumps(contacts, ensure_ascii=False),
                knowledge_references=json.dumps(knowledge_references, ensure_ascii=False),
                isolation_status=json.dumps(isolation_status, ensure_ascii=False),
                mitigation_status=json.dumps(mitigation_status, ensure_ascii=False),
                executed_by=operator,
                execution_time=datetime.now(timezone.utc)
            )

            session.add(plan)
            session.flush()

            log_audit(
                action="response_plan_generate",
                resource_type="response_plan",
                resource_id=str(plan.id),
                detail=f"生成应急预案 #{plan.id}，漏洞类型: {vuln_type.value}，触发条件: {trigger_condition}",
                user=operator
            )

            logger.info(
                f"Response plan {plan.id} generated for vuln_instance {vuln_instance_id}, "
                f"type: {vuln_type.value}"
            )

            return plan

        except Exception as e:
            logger.exception(f"Failed to generate response plan for vuln_instance {vuln_instance_id}: {e}")
            raise


plan_generator = PlanGenerator()


class NotificationManager:
    def __init__(self):
        self.notification_service = NotificationService()
        self.emergency_contacts = EMERGENCY_CONTACTS
        self.channels = config.notification.NOTIFICATION_CHANNELS

    def _get_plan_summary(self, plan: ResponsePlan, session: Session) -> Dict[str, Any]:
        vuln_instance = session.query(VulnerabilityInstance).filter_by(
            id=plan.vuln_instance_id
        ).first()

        if not vuln_instance:
            return {}

        vuln = vuln_instance.vulnerability
        asset = vuln_instance.asset

        affected_assets = []
        if plan.affected_assets:
            try:
                affected_assets = json.loads(plan.affected_assets)
            except:
                pass

        return {
            "plan_id": plan.id,
            "vuln_title": vuln.title,
            "vuln_cve": vuln.cve_id,
            "vuln_severity": vuln.severity.value,
            "vuln_cvss": float(vuln.cvss_score) if vuln.cvss_score else None,
            "vuln_type": plan.vuln_type.value,
            "asset_name": asset.name,
            "asset_ip": asset.ip,
            "asset_type": asset.type,
            "asset_department": asset.department,
            "risk_score": float(vuln_instance.risk_score),
            "trigger_reason": plan.trigger_reason,
            "trigger_condition": plan.trigger_condition,
            "affected_assets_count": len(affected_assets),
            "isolation_measures": plan.isolation_measures,
            "mitigation_measures": plan.mitigation_measures,
            "meeting_link": MEETING_LINK,
            "communication_channel": COMMUNICATION_CHANNEL,
            "sla_confirmation": RESPONSE_SLA["confirmation_minutes"],
            "sla_mitigation": RESPONSE_SLA["mitigation_hours"],
            "sla_isolation": RESPONSE_SLA["isolation_hours"],
            "created_at": plan.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }

    def _generate_response_team_content(self, summary: Dict[str, Any]) -> Tuple[str, str]:
        subject = f"【紧急应急响应】预案 #{summary['plan_id']} - {summary['vuln_severity'].upper()} - {summary['vuln_title'][:50]}"

        severity_display = {
            "critical": "严重",
            "high": "高危",
            "medium": "中危",
            "low": "低危"
        }
        severity_cn = severity_display.get(summary['vuln_severity'], summary['vuln_severity'])

        content = f"""
{'=' * 60}
【紧急应急响应通知】
{'=' * 60}

预警级别：{severity_cn}
预案编号：{summary['plan_id']}
创建时间：{summary['created_at']}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
一、漏洞/事件概要
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
漏洞名称：{summary['vuln_title']}
CVE编号：{summary['vuln_cve'] or '无'}
CVSS评分：{summary['vuln_cvss'] if summary['vuln_cvss'] else '无'}
漏洞类型：{summary['vuln_type']}
风险分值：{summary['risk_score']}

触发条件：{summary['trigger_condition']}
触发原因：{summary['trigger_reason']}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
二、受影响资产信息
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
主要受影响资产：{summary['asset_name']} ({summary['asset_ip']})
资产类型：{summary['asset_type']}
所属部门：{summary['asset_department']}
受影响资产总数：{summary['affected_assets_count']} 台

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
三、应急预案摘要
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  请立即执行以下操作：

1. 确认收到本通知（15分钟内）
2. 加入应急会议
3. 按预案执行隔离和缓解措施

隔离措施（立即执行）：
"""

        if summary['isolation_measures']:
            try:
                measures = json.loads(summary['isolation_measures'])
                for i, measure in enumerate(measures, 1):
                    content += f"   {i}. {measure}\n"
            except:
                content += f"   {summary['isolation_measures']}\n"

        content += f"""
临时缓解措施（1小时内执行）：
"""

        if summary['mitigation_measures']:
            try:
                measures = json.loads(summary['mitigation_measures'])
                for i, measure in enumerate(measures, 1):
                    content += f"   {i}. {measure}\n"
            except:
                content += f"   {summary['mitigation_measures']}\n"

        content += f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
四、响应SLA要求
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅  通知确认：{summary['sla_confirmation']} 分钟内
✅  临时缓解：{summary['sla_mitigation']} 小时内完成
✅  完全隔离：{summary['sla_isolation']} 小时内完成

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
五、沟通渠道
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
应急会议：{summary['meeting_link']}
沟通群组：{summary['communication_channel']}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
请立即响应并加入应急处置！
{'=' * 60}
        """

        return subject, content.strip()

    def _generate_legal_content(self, summary: Dict[str, Any], reason: str) -> Tuple[str, str]:
        subject = f"【法务通知】数据安全事件 - 预案 #{summary['plan_id']} - {summary['vuln_title'][:30]}"

        severity_display = {
            "critical": "严重",
            "high": "高危",
            "medium": "中危",
            "low": "低危"
        }
        severity_cn = severity_display.get(summary['vuln_severity'], summary['vuln_severity'])

        content = f"""
{'=' * 60}
【法务部门安全事件通知】
{'=' * 60}

事件级别：{severity_cn}
预案编号：{summary['plan_id']}
通知时间：{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
一、事件概要
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
漏洞名称：{summary['vuln_title']}
CVE编号：{summary['vuln_cve'] or '无'}
CVSS评分：{summary['vuln_cvss'] if summary['vuln_cvss'] else '无'}
风险分值：{summary['risk_score']}
受影响资产数：{summary['affected_assets_count']} 台

通知原因：{reason}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
二、风险评估
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
涉及风险：
- 客户数据泄露风险：{'是' if 'data' in summary['vuln_type'] or summary['vuln_type'] in ['sql_injection', 'privilege_escalation'] else '否'}
- 合规要求影响：
  * 等保2.0：可能涉及
  * GDPR：可能涉及（如涉及欧盟用户数据）
  * 个人信息保护法：可能涉及
  * 网络安全法：可能涉及

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
三、已采取措施
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. 已启动应急响应预案
2. 已通知应急响应团队
3. 正在执行漏洞隔离和缓解措施
4. 安全事件已创建并在调查中

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
四、法务协助需求
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
请法务部门协助：
1. 评估事件的法律风险和合规影响
2. 如需，指导数据泄露通知流程
3. 提供监管上报的法律咨询
4. 如需，准备法律文件和声明

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
五、沟通渠道
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
应急会议：{summary['meeting_link']}
联系人：{self.emergency_contacts['response_team_leader']}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
请法务部门尽快介入！
{'=' * 60}
        """

        return subject, content.strip()

    @with_session
    def notify_response_team(self, plan_id: int,
                             operator: str = "system",
                             session: Session = None) -> bool:
        try:
            plan = session.query(ResponsePlan).filter_by(id=plan_id).first()
            if not plan:
                logger.error(f"Response plan {plan_id} not found")
                return False

            summary = self._get_plan_summary(plan, session)
            subject, content = self._generate_response_team_content(summary)

            notified_teams = []

            vuln_instance = session.query(VulnerabilityInstance).filter_by(
                id=plan.vuln_instance_id
            ).first()

            contacts = []
            if plan.contacts:
                try:
                    contact_list = json.loads(plan.contacts)
                    for contact in contact_list:
                        contacts.append(contact["contact"])
                        notified_teams.append(contact["role"])
                except:
                    pass

            contacts.append(self.emergency_contacts["response_team_leader"])
            contacts.append(self.emergency_contacts["security_team"])
            contacts.append(self.emergency_contacts["it_operations"])
            contacts.append(self.emergency_contacts["ciso"])

            contacts = list(set(contacts))

            success_count = 0
            for recipient in contacts:
                for channel in self.channels:
                    try:
                        notification_type = NotificationTypeEnum(channel)
                        notification = Notification(
                            type=notification_type,
                            recipient=recipient,
                            content=f"{subject}\n\n{content}",
                            status=NotificationStatusEnum.PENDING,
                            escalation_level=1
                        )
                        session.add(notification)
                        session.flush()

                        if channel == "email":
                            email_addr = recipient if "@" in recipient else f"{recipient}@example.com"
                            success, error = self.notification_service._send_with_retry(
                                self.notification_service._send_email,
                                email_addr, subject, content
                            )
                        elif channel == "dingtalk":
                            success, error = self.notification_service._send_with_retry(
                                self.notification_service._send_dingtalk,
                                config.notification.DINGTALK_WEBHOOK,
                                config.notification.DINGTALK_SECRET,
                                f"{subject}\n\n{content}"
                            )
                        elif channel == "wechat":
                            success, error = self.notification_service._send_with_retry(
                                self.notification_service._send_wechat,
                                config.notification.WECHAT_WEBHOOK,
                                f"{subject}\n\n{content}"
                            )
                        elif channel == "feishu":
                            success, error = self.notification_service._send_with_retry(
                                self.notification_service._send_feishu,
                                config.notification.FEISHU_WEBHOOK,
                                f"{subject}\n\n{content}"
                            )
                        else:
                            success, error = False, f"Unknown channel: {channel}"

                        if success:
                            notification.status = NotificationStatusEnum.SENT
                            notification.sent_at = datetime.now(timezone.utc)
                            success_count += 1
                        else:
                            notification.status = NotificationStatusEnum.FAILED
                            notification.error_message = error

                        notification.retry_count += 1
                        notification.updated_at = datetime.now(timezone.utc)

                    except Exception as e:
                        logger.exception(f"Failed to send {channel} notification to {recipient}: {e}")
                        continue

            plan.notified_teams = json.dumps(notified_teams, ensure_ascii=False)
            plan.updated_at = datetime.now(timezone.utc)

            log_audit(
                action="response_team_notified",
                resource_type="response_plan",
                resource_id=str(plan_id),
                detail=f"通知应急小组，接收人: {', '.join(contacts)}，成功: {success_count} 条",
                user=operator
            )

            logger.info(
                f"Response team notified for plan {plan_id}: "
                f"{success_count} notifications sent to {len(contacts)} recipients"
            )

            return success_count > 0

        except Exception as e:
            logger.exception(f"Failed to notify response team for plan {plan_id}: {e}")
            return False

    @with_session
    def notify_legal_department(self, plan_id: int, reason: str,
                                operator: str = "system",
                                session: Session = None) -> bool:
        try:
            plan = session.query(ResponsePlan).filter_by(id=plan_id).first()
            if not plan:
                logger.error(f"Response plan {plan_id} not found")
                return False

            summary = self._get_plan_summary(plan, session)
            subject, content = self._generate_legal_content(summary, reason)

            legal_contacts = [
                self.emergency_contacts["legal_department"],
                self.emergency_contacts["ciso"]
            ]

            success_count = 0
            for recipient in legal_contacts:
                for channel in self.channels:
                    try:
                        notification_type = NotificationTypeEnum(channel)
                        notification = Notification(
                            type=notification_type,
                            recipient=recipient,
                            content=f"{subject}\n\n{content}",
                            status=NotificationStatusEnum.PENDING,
                            escalation_level=1
                        )
                        session.add(notification)
                        session.flush()

                        if channel == "email":
                            email_addr = recipient if "@" in recipient else f"{recipient}@example.com"
                            success, error = self.notification_service._send_with_retry(
                                self.notification_service._send_email,
                                email_addr, subject, content
                            )
                        elif channel == "dingtalk":
                            success, error = self.notification_service._send_with_retry(
                                self.notification_service._send_dingtalk,
                                config.notification.DINGTALK_WEBHOOK,
                                config.notification.DINGTALK_SECRET,
                                f"{subject}\n\n{content}"
                            )
                        elif channel == "wechat":
                            success, error = self.notification_service._send_with_retry(
                                self.notification_service._send_wechat,
                                config.notification.WECHAT_WEBHOOK,
                                f"{subject}\n\n{content}"
                            )
                        elif channel == "feishu":
                            success, error = self.notification_service._send_with_retry(
                                self.notification_service._send_feishu,
                                config.notification.FEISHU_WEBHOOK,
                                f"{subject}\n\n{content}"
                            )
                        else:
                            success, error = False, f"Unknown channel: {channel}"

                        if success:
                            notification.status = NotificationStatusEnum.SENT
                            notification.sent_at = datetime.now(timezone.utc)
                            success_count += 1
                        else:
                            notification.status = NotificationStatusEnum.FAILED
                            notification.error_message = error

                        notification.retry_count += 1
                        notification.updated_at = datetime.now(timezone.utc)

                    except Exception as e:
                        logger.exception(f"Failed to send legal notification to {recipient}: {e}")
                        continue

            plan.legal_notified = True
            plan.legal_notify_reason = reason
            plan.legal_notified_at = datetime.now(timezone.utc)
            plan.updated_at = datetime.now(timezone.utc)

            log_audit(
                action="legal_department_notified",
                resource_type="response_plan",
                resource_id=str(plan_id),
                detail=f"通知法务部门，原因: {reason}，接收人: {', '.join(legal_contacts)}",
                user=operator
            )

            logger.info(
                f"Legal department notified for plan {plan_id}: "
                f"{success_count} notifications sent"
            )

            return success_count > 0

        except Exception as e:
            logger.exception(f"Failed to notify legal department for plan {plan_id}: {e}")
            return False


notification_manager = NotificationManager()


class ResponsePlanManager:
    def __init__(self):
        self.plan_status_flow = {
            PlanStatus.CREATED: [PlanStatus.CONFIRMED, PlanStatus.CLOSED],
            PlanStatus.CONFIRMED: [PlanStatus.EXECUTING, PlanStatus.CLOSED],
            PlanStatus.EXECUTING: [PlanStatus.COMPLETED, PlanStatus.CLOSED],
            PlanStatus.COMPLETED: [PlanStatus.CLOSED],
            PlanStatus.CLOSED: []
        }
        self.sla_config = RESPONSE_SLA

    def _is_valid_status_transition(self, current_status: PlanStatus,
                                    new_status: PlanStatus) -> bool:
        if new_status == PlanStatus.CLOSED:
            return current_status != PlanStatus.CLOSED
        return new_status in self.plan_status_flow.get(current_status, [])

    def _parse_measures(self, measures_str: Optional[str]) -> List[Dict[str, Any]]:
        if not measures_str:
            return []
        try:
            return json.loads(measures_str)
        except:
            return []

    def _serialize_measures(self, measures: List[Dict[str, Any]]) -> str:
        return json.dumps(measures, ensure_ascii=False)

    @with_session
    def update_plan_status(self, plan_id: int, new_status: PlanStatus,
                           operator: str, remark: Optional[str] = None,
                           session: Session = None) -> Optional[ResponsePlan]:
        try:
            plan = session.query(ResponsePlan).filter_by(id=plan_id).first()
            if not plan:
                logger.error(f"Response plan {plan_id} not found")
                return None

            old_status = plan.status

            if not self._is_valid_status_transition(old_status, new_status):
                error_msg = (
                    f"Invalid status transition for plan {plan_id}: "
                    f"{old_status.value} -> {new_status.value}"
                )
                logger.error(error_msg)
                raise ValueError(error_msg)

            now = datetime.now(timezone.utc)

            if new_status == PlanStatus.CONFIRMED:
                plan.confirmed_at = now
                plan.confirmed_by = operator
                if not plan.sla_confirmed_at:
                    plan.sla_confirmed_at = now

            if new_status == PlanStatus.EXECUTING:
                pass

            if new_status == PlanStatus.COMPLETED:
                plan.completed_at = now

            if new_status == PlanStatus.CLOSED:
                plan.closed_at = now
                if not remark:
                    raise ValueError("Closing a response plan requires a remark")

            plan.status = new_status
            if remark:
                plan.remarks = (plan.remarks or "") + f"\n[{now.strftime('%Y-%m-%d %H:%M:%S')}] {operator}: {remark}"
            plan.updated_at = now

            status_display = {
                PlanStatus.CREATED: "已生成",
                PlanStatus.CONFIRMED: "已确认",
                PlanStatus.EXECUTING: "执行中",
                PlanStatus.COMPLETED: "已完成",
                PlanStatus.CLOSED: "已关闭"
            }

            detail = f"预案状态变更: {status_display.get(old_status, old_status.value)} -> {status_display.get(new_status, new_status.value)}"
            if remark:
                detail += f", 备注: {remark}"

            log_audit(
                action="response_plan_status_update",
                resource_type="response_plan",
                resource_id=str(plan_id),
                detail=detail,
                user=operator
            )

            logger.info(
                f"Response plan {plan_id} status updated: "
                f"{old_status.value} -> {new_status.value} by {operator}"
            )

            return plan

        except ValueError:
            raise
        except Exception as e:
            logger.exception(f"Failed to update plan status for plan {plan_id}: {e}")
            raise

    @with_session
    def update_measure_status(self, plan_id: int, measure_type: str,
                              measure_index: int, is_completed: bool,
                              operator: str, remark: Optional[str] = None,
                              session: Session = None) -> Optional[ResponsePlan]:
        try:
            plan = session.query(ResponsePlan).filter_by(id=plan_id).first()
            if not plan:
                logger.error(f"Response plan {plan_id} not found")
                return None

            if measure_type == "isolation":
                measures = self._parse_measures(plan.isolation_status)
            elif measure_type == "mitigation":
                measures = self._parse_measures(plan.mitigation_status)
            else:
                raise ValueError(f"Invalid measure type: {measure_type}")

            if measure_index < 0 or measure_index >= len(measures):
                raise ValueError(f"Invalid measure index: {measure_index}")

            now = datetime.now(timezone.utc)
            measures[measure_index]["status"] = MeasureStatus.COMPLETED.value if is_completed else MeasureStatus.PENDING.value
            measures[measure_index]["completed_at"] = now.strftime('%Y-%m-%d %H:%M:%S') if is_completed else None
            measures[measure_index]["operator"] = operator
            if remark:
                measures[measure_index]["remark"] = remark

            if measure_type == "isolation":
                plan.isolation_status = self._serialize_measures(measures)
                if is_completed and not plan.sla_isolation_at:
                    all_completed = all(m["status"] == MeasureStatus.COMPLETED.value for m in measures)
                    if all_completed:
                        plan.sla_isolation_at = now
            else:
                plan.mitigation_status = self._serialize_measures(measures)
                if is_completed and not plan.sla_mitigation_at:
                    all_completed = all(m["status"] == MeasureStatus.COMPLETED.value for m in measures)
                    if all_completed:
                        plan.sla_mitigation_at = now

            plan.updated_at = now

            status = "完成" if is_completed else "重置为待处理"
            detail = f"更新{measure_type}措施状态: 第{measure_index + 1}条 {status}"
            if remark:
                detail += f", 备注: {remark}"

            log_audit(
                action="response_measure_status_update",
                resource_type="response_plan",
                resource_id=str(plan_id),
                detail=detail,
                user=operator
            )

            logger.info(
                f"Plan {plan_id} {measure_type} measure {measure_index} "
                f"updated to {'completed' if is_completed else 'pending'} by {operator}"
            )

            return plan

        except ValueError:
            raise
        except Exception as e:
            logger.exception(f"Failed to update measure status for plan {plan_id}: {e}")
            raise

    @with_read_session
    def check_response_sla(self, session: Session = None) -> List[Dict[str, Any]]:
        try:
            now = datetime.now(timezone.utc)
            sla_violations = []

            active_plans = session.query(ResponsePlan).filter(
                ResponsePlan.status.in_([
                    PlanStatus.CREATED,
                    PlanStatus.CONFIRMED,
                    PlanStatus.EXECUTING
                ])
            ).all()

            for plan in active_plans:
                violations = []
                created_at = plan.created_at

                if not plan.sla_confirmed_at:
                    deadline = created_at + timedelta(minutes=self.sla_config["confirmation_minutes"])
                    if now > deadline:
                        delay_minutes = (now - deadline).total_seconds() / 60
                        violations.append({
                            "type": "confirmation",
                            "sla_minutes": self.sla_config["confirmation_minutes"],
                            "delay_minutes": delay_minutes,
                            "message": f"预案确认超时 {delay_minutes:.0f} 分钟"
                        })

                if not plan.sla_mitigation_at:
                    deadline = created_at + timedelta(hours=self.sla_config["mitigation_hours"])
                    if now > deadline:
                        delay_hours = (now - deadline).total_seconds() / 3600
                        violations.append({
                            "type": "mitigation",
                            "sla_hours": self.sla_config["mitigation_hours"],
                            "delay_hours": delay_hours,
                            "message": f"临时缓解措施执行超时 {delay_hours:.1f} 小时"
                        })

                if not plan.sla_isolation_at:
                    deadline = created_at + timedelta(hours=self.sla_config["isolation_hours"])
                    if now > deadline:
                        delay_hours = (now - deadline).total_seconds() / 3600
                        violations.append({
                            "type": "isolation",
                            "sla_hours": self.sla_config["isolation_hours"],
                            "delay_hours": delay_hours,
                            "message": f"完全隔离措施执行超时 {delay_hours:.1f} 小时"
                        })

                if violations:
                    sla_violations.append({
                        "plan_id": plan.id,
                        "vuln_instance_id": plan.vuln_instance_id,
                        "trigger_reason": plan.trigger_reason,
                        "status": plan.status.value,
                        "created_at": created_at.strftime('%Y-%m-%d %H:%M:%S'),
                        "violations": violations
                    })

            if sla_violations:
                logger.warning(f"Found {len(sla_violations)} response plans with SLA violations")
                for violation in sla_violations:
                    for v in violation["violations"]:
                        logger.warning(
                            f"Plan {violation['plan_id']} SLA violation: {v['message']}"
                        )

            return sla_violations

        except Exception as e:
            logger.exception(f"Failed to check response SLA: {e}")
            return []

    @with_read_session
    def get_plan_detail(self, plan_id: int, session: Session = None) -> Optional[Dict[str, Any]]:
        try:
            plan = session.query(ResponsePlan).filter_by(id=plan_id).first()
            if not plan:
                return None

            vuln_instance = session.query(VulnerabilityInstance).filter_by(
                id=plan.vuln_instance_id
            ).first()

            detail = {
                "id": plan.id,
                "vuln_instance_id": plan.vuln_instance_id,
                "vuln_id": plan.vuln_id,
                "incident_id": plan.incident_id,
                "status": plan.status.value,
                "vuln_type": plan.vuln_type.value,
                "trigger_reason": plan.trigger_reason,
                "trigger_condition": plan.trigger_condition,
                "affected_assets": self._parse_measures(plan.affected_assets),
                "isolation_measures": self._parse_measures(plan.isolation_measures),
                "mitigation_measures": self._parse_measures(plan.mitigation_measures),
                "root_fix_plan": self._parse_measures(plan.root_fix_plan),
                "contacts": self._parse_measures(plan.contacts),
                "knowledge_references": self._parse_measures(plan.knowledge_references),
                "isolation_status": self._parse_measures(plan.isolation_status),
                "mitigation_status": self._parse_measures(plan.mitigation_status),
                "confirmed_at": plan.confirmed_at.strftime('%Y-%m-%d %H:%M:%S') if plan.confirmed_at else None,
                "confirmed_by": plan.confirmed_by,
                "legal_notified": plan.legal_notified,
                "legal_notify_reason": plan.legal_notify_reason,
                "legal_notified_at": plan.legal_notified_at.strftime('%Y-%m-%d %H:%M:%S') if plan.legal_notified_at else None,
                "executed_by": plan.executed_by,
                "execution_time": plan.execution_time.strftime('%Y-%m-%d %H:%M:%S'),
                "completed_at": plan.completed_at.strftime('%Y-%m-%d %H:%M:%S') if plan.completed_at else None,
                "closed_at": plan.closed_at.strftime('%Y-%m-%d %H:%M:%S') if plan.closed_at else None,
                "created_at": plan.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                "updated_at": plan.updated_at.strftime('%Y-%m-%d %H:%M:%S')
            }

            if vuln_instance:
                detail["vulnerability"] = {
                    "id": vuln_instance.vulnerability.id,
                    "cve_id": vuln_instance.vulnerability.cve_id,
                    "title": vuln_instance.vulnerability.title,
                    "severity": vuln_instance.vulnerability.severity.value,
                    "cvss_score": float(vuln_instance.vulnerability.cvss_score) if vuln_instance.vulnerability.cvss_score else None
                }
                detail["asset"] = {
                    "id": vuln_instance.asset.id,
                    "name": vuln_instance.asset.name,
                    "ip": vuln_instance.asset.ip,
                    "type": vuln_instance.asset.type,
                    "importance": vuln_instance.asset.importance,
                    "department": vuln_instance.asset.department,
                    "owner": vuln_instance.asset.owner
                }
                detail["risk_score"] = float(vuln_instance.risk_score)

            return detail

        except Exception as e:
            logger.exception(f"Failed to get plan detail for plan {plan_id}: {e}")
            return None

    @with_read_session
    def list_active_plans(self, page: int = 1, page_size: int = 20,
                          session: Session = None) -> Dict[str, Any]:
        try:
            query = session.query(ResponsePlan).filter(
                ResponsePlan.status.in_([
                    PlanStatus.CREATED,
                    PlanStatus.CONFIRMED,
                    PlanStatus.EXECUTING
                ])
            )

            total = query.count()
            offset = (page - 1) * page_size
            plans = query.order_by(ResponsePlan.created_at.desc()).offset(offset).limit(page_size).all()

            plan_list = []
            for plan in plans:
                plan_list.append({
                    "id": plan.id,
                    "vuln_type": plan.vuln_type.value,
                    "status": plan.status.value,
                    "trigger_condition": plan.trigger_condition,
                    "trigger_reason": plan.trigger_reason[:100],
                    "executed_by": plan.executed_by,
                    "created_at": plan.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    "updated_at": plan.updated_at.strftime('%Y-%m-%d %H:%M:%S')
                })

            return {
                "total": total,
                "page": page,
                "page_size": page_size,
                "plans": plan_list
            }

        except Exception as e:
            logger.exception(f"Failed to list active plans: {e}")
            return {"total": 0, "page": page, "page_size": page_size, "plans": []}


response_plan_manager = ResponsePlanManager()
