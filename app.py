import os
import uuid
import json
from datetime import datetime, timedelta, timezone
from functools import wraps
from decimal import Decimal
import enum

from flask import Flask, Blueprint, request, jsonify, render_template, send_from_directory, redirect, url_for
from flask_cors import CORS
from sqlalchemy import func, and_, or_, case
from sqlalchemy.orm import Session, joinedload

from config import config
from database import db_manager
from logger import logger, log_audit, set_log_context
from models import (
    Asset, Vulnerability, VulnerabilityInstance, WorkOrder, Incident,
    ResponsePlan, ReviewTask, Notification, VerificationRecord,
    IncidentTimeline, Report, EscalationRecord,
    SeverityEnum, WorkOrderStatusEnum, FixStatusEnum,
    IncidentStatusEnum, IncidentTypeEnum, PlanStatus,
    VulnStatusEnum, NotificationTypeEnum, NotificationStatusEnum,
    IncidentEventTypeEnum, ReportTypeEnum, MeasureStatus,
    VulnType, ReviewTaskStatusEnum, ReviewTaskReasonEnum
)
from work_order import StatusManager, WorkOrderCreator, NotificationService
from verify import verification_scanner, verification_processor, review_task_manager
from response import plan_generator, response_trigger, notification_manager
from reports import StatsEngine, TrendAnalyzer, ChartGenerator, PdfReporter, ExcelReporter


app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = config.security.SECRET_KEY
app.config["JSON_AS_ASCII"] = False

CORS(app, resources={r"/api/*": {"origins": config.WEB_CORS_ORIGINS}})

status_manager = StatusManager()
work_order_creator = WorkOrderCreator()
notification_service = NotificationService()
stats_engine = StatsEngine()
trend_analyzer = TrendAnalyzer()


def success(data=None, message="success", code=0):
    return jsonify({
        "code": code,
        "message": message,
        "data": data,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })


def error(message="error", code=-1, status_code=400):
    resp = jsonify({
        "code": code,
        "message": message,
        "data": None,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    resp.status_code = status_code
    return resp


def paginate_result(items, total, page, page_size):
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size if page_size > 0 else 0
    }


def model_to_dict(obj, exclude=None, include=None):
    if obj is None:
        return None
    exclude = exclude or []
    result = {}
    for column in obj.__table__.columns:
        if column.name in exclude:
            continue
        if include and column.name not in include:
            continue
        value = getattr(obj, column.name)
        result[column.name] = _serialize_value(value)
    return result


def _serialize_value(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float, str)):
        return value
    if isinstance(value, (list, dict)):
        return value
    try:
        return str(value)
    except Exception:
        return None


def asset_to_dict(asset):
    if not asset:
        return None
    d = model_to_dict(asset)
    return d


def vulnerability_to_dict(vuln):
    if not vuln:
        return None
    d = model_to_dict(vuln)
    return d


def vuln_instance_to_dict(vi, include_relations=True):
    if not vi:
        return None
    d = model_to_dict(vi)
    if include_relations:
        if vi.vulnerability:
            d["vulnerability"] = vulnerability_to_dict(vi.vulnerability)
        if vi.asset:
            d["asset"] = asset_to_dict(vi.asset)
    return d


def work_order_to_dict(wo, include_relations=True):
    if not wo:
        return None
    d = model_to_dict(wo)
    if include_relations:
        if wo.vuln_instance:
            d["vuln_instance"] = vuln_instance_to_dict(wo.vuln_instance, include_relations=True)
        if wo.notifications:
            d["notifications"] = [model_to_dict(n) for n in wo.notifications]
        if wo.escalation_records:
            d["escalation_records"] = [model_to_dict(er) for er in wo.escalation_records]
        try:
            d["title"] = work_order_creator.get_title(wo)
        except Exception:
            d["title"] = f"工单 #{wo.id}"
    return d


def incident_to_dict(incident, include_relations=True):
    if not incident:
        return None
    d = model_to_dict(incident)
    if include_relations and incident.timelines:
        d["timelines"] = [model_to_dict(t) for t in incident.timelines]
    return d


def response_plan_to_dict(plan, include_relations=True):
    if not plan:
        return None
    d = model_to_dict(plan)
    if include_relations:
        if plan.vuln_instance:
            d["vuln_instance"] = vuln_instance_to_dict(plan.vuln_instance)
        if plan.vulnerability:
            d["vulnerability"] = vulnerability_to_dict(plan.vulnerability)
        if plan.affected_assets:
            try:
                d["affected_assets"] = json.loads(plan.affected_assets)
            except Exception:
                pass
        if plan.isolation_measures:
            try:
                d["isolation_measures"] = json.loads(plan.isolation_measures)
            except Exception:
                pass
        if plan.mitigation_measures:
            try:
                d["mitigation_measures"] = json.loads(plan.mitigation_measures)
            except Exception:
                pass
        if plan.root_fix_plan:
            try:
                d["root_fix_plan"] = json.loads(plan.root_fix_plan)
            except Exception:
                pass
        if plan.contacts:
            try:
                d["contacts"] = json.loads(plan.contacts)
            except Exception:
                pass
        if plan.knowledge_references:
            try:
                d["knowledge_references"] = json.loads(plan.knowledge_references)
            except Exception:
                pass
        if plan.isolation_status:
            try:
                d["isolation_status"] = json.loads(plan.isolation_status)
            except Exception:
                pass
        if plan.mitigation_status:
            try:
                d["mitigation_status"] = json.loads(plan.mitigation_status)
            except Exception:
                pass
    return d


def review_task_to_dict(task, include_relations=True):
    if not task:
        return None
    d = model_to_dict(task)
    if include_relations:
        if task.vuln_instance:
            d["vuln_instance"] = vuln_instance_to_dict(task.vuln_instance)
        if task.work_order:
            d["work_order"] = work_order_to_dict(task.work_order, include_relations=False)
    return d


def report_to_dict(report):
    if not report:
        return None
    d = model_to_dict(report)
    return d


def get_page_args():
    page = request.args.get("page", 1, type=int)
    page_size = request.args.get("page_size", 20, type=int)
    if page < 1:
        page = 1
    if page_size < 1 or page_size > 200:
        page_size = 20
    return page, page_size


def get_current_user():
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        if "admin" in token:
            return "admin"
    return None


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return error("Unauthorized", code=401, status_code=401)
        set_log_context(user=user, ip=request.remote_addr)
        return f(*args, **kwargs)
    return decorated


@app.before_request
def before_request():
    request_id = str(uuid.uuid4())[:8]
    user = get_current_user() or "anonymous"
    set_log_context(
        request_id=request_id,
        user=user,
        ip=request.remote_addr,
        operation_type=request.method,
        resource_type=request.path
    )
    request.start_time = datetime.now(timezone.utc)
    logger.info(
        f"Request started: {request.method} {request.path} "
        f"from {request.remote_addr}, user={user}, request_id={request_id}"
    )


@app.after_request
def after_request(response):
    duration = (datetime.now(timezone.utc) - request.start_time).total_seconds()
    logger.info(
        f"Request completed: {request.method} {request.path} "
        f"status={response.status_code}, duration={duration:.3f}s"
    )
    response.headers["X-Request-ID"] = getattr(request, "request_id", "")
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response


@app.errorhandler(404)
def not_found(e):
    return error("Resource not found", code=404, status_code=404)


@app.errorhandler(500)
def internal_error(e):
    logger.exception(f"Internal server error: {e}")
    return error("Internal server error", code=500, status_code=500)


@app.errorhandler(400)
def bad_request(e):
    return error(str(e) or "Bad request", code=400, status_code=400)


@app.errorhandler(401)
def unauthorized(e):
    return error("Unauthorized", code=401, status_code=401)


@app.errorhandler(403)
def forbidden(e):
    return error("Forbidden", code=403, status_code=403)


@app.route("/")
def index():
    return redirect("/static/index.html")


auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


@auth_bp.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json() or {}
        username = data.get("username", "")
        password = data.get("password", "")
        if username == "admin" and password == "admin":
            token = f"admin_token_{uuid.uuid4().hex}"
            log_audit(
                action="login",
                resource_type="auth",
                resource_id="-",
                detail=f"用户 {username} 登录成功",
                user=username,
                ip=request.remote_addr
            )
            return success({
                "token": token,
                "username": username,
                "expires_in": config.security.TOKEN_EXPIRE_HOURS * 3600
            }, "登录成功")
        return error("用户名或密码错误", code=401, status_code=401)
    except Exception as e:
        logger.exception(f"Login error: {e}")
        return error("登录失败", code=500, status_code=500)


app.register_blueprint(auth_bp)


vuln_bp = Blueprint("vulnerabilities", __name__, url_prefix="/api/vulnerabilities")


@vuln_bp.route("", methods=["GET"])
@login_required
def list_vulnerabilities():
    try:
        page, page_size = get_page_args()
        cve_id = request.args.get("cve_id")
        severity = request.args.get("severity")
        status = request.args.get("status")
        asset_id = request.args.get("asset_id", type=int)
        keyword = request.args.get("keyword")
        start_date = request.args.get("start_date")
        end_date = request.args.get("end_date")
        risk_score_min = request.args.get("risk_score_min", type=float)
        risk_score_max = request.args.get("risk_score_max", type=float)
        sort_by = request.args.get("sort_by", "created_at")
        sort_order = request.args.get("sort_order", "desc")

        with db_manager.get_session() as session:
            query = session.query(VulnerabilityInstance).join(
                Vulnerability, VulnerabilityInstance.vuln_id == Vulnerability.id
            ).join(
                Asset, VulnerabilityInstance.asset_id == Asset.id
            )

            conditions = []
            if cve_id:
                conditions.append(Vulnerability.cve_id.like(f"%{cve_id}%"))
            if severity:
                try:
                    conditions.append(Vulnerability.severity == SeverityEnum(severity))
                except ValueError:
                    pass
            if status:
                try:
                    conditions.append(VulnerabilityInstance.fix_status == FixStatusEnum(status))
                except ValueError:
                    pass
            if asset_id:
                conditions.append(VulnerabilityInstance.asset_id == asset_id)
            if keyword:
                conditions.append(or_(
                    Vulnerability.title.like(f"%{keyword}%"),
                    Vulnerability.description.like(f"%{keyword}%"),
                    Asset.name.like(f"%{keyword}%"),
                    Asset.ip.like(f"%{keyword}%")
                ))
            if start_date:
                try:
                    start_dt = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
                    conditions.append(VulnerabilityInstance.discovery_time >= start_dt)
                except ValueError:
                    pass
            if end_date:
                try:
                    end_dt = datetime.fromisoformat(end_date.replace("Z", "+00:00"))
                    conditions.append(VulnerabilityInstance.discovery_time <= end_dt)
                except ValueError:
                    pass
            if risk_score_min is not None:
                conditions.append(VulnerabilityInstance.risk_score >= risk_score_min)
            if risk_score_max is not None:
                conditions.append(VulnerabilityInstance.risk_score <= risk_score_max)

            if conditions:
                query = query.filter(and_(*conditions))

            total = query.count()

            sort_column = None
            if sort_by == "risk_score":
                sort_column = VulnerabilityInstance.risk_score
            elif sort_by == "severity":
                sort_column = Vulnerability.severity
            elif sort_by == "discovery_time":
                sort_column = VulnerabilityInstance.discovery_time
            elif sort_by == "fix_deadline":
                sort_column = VulnerabilityInstance.fix_deadline
            else:
                sort_column = VulnerabilityInstance.created_at

            if sort_order == "asc":
                query = query.order_by(sort_column.asc())
            else:
                query = query.order_by(sort_column.desc())

            offset = (page - 1) * page_size
            instances = query.offset(offset).limit(page_size).all()

            items = [vuln_instance_to_dict(vi) for vi in instances]
            return success(paginate_result(items, total, page, page_size))
    except Exception as e:
        logger.exception(f"List vulnerabilities error: {e}")
        return error(f"查询失败: {str(e)}", code=500, status_code=500)


@vuln_bp.route("/<int:vi_id>", methods=["GET"])
@login_required
def get_vulnerability(vi_id):
    try:
        with db_manager.get_session() as session:
            vi = session.query(VulnerabilityInstance).filter_by(id=vi_id).first()
            if not vi:
                return error("漏洞实例不存在", code=404, status_code=404)

            result = vuln_instance_to_dict(vi)

            work_orders = session.query(WorkOrder).filter_by(vuln_instance_id=vi_id).all()
            result["work_orders"] = [work_order_to_dict(wo, include_relations=False) for wo in work_orders]

            verifications = session.query(VerificationRecord).filter_by(vuln_instance_id=vi_id).order_by(
                VerificationRecord.verification_time.desc()
            ).all()
            result["verification_records"] = [model_to_dict(v) for v in verifications]

            escalations = session.query(EscalationRecord).join(WorkOrder).filter(
                WorkOrder.vuln_instance_id == vi_id
            ).all()
            result["escalation_records"] = [model_to_dict(er) for er in escalations]

            return success(result)
    except Exception as e:
        logger.exception(f"Get vulnerability {vi_id} error: {e}")
        return error(f"查询失败: {str(e)}", code=500, status_code=500)


@vuln_bp.route("", methods=["POST"])
@login_required
def create_vulnerability():
    try:
        data = request.get_json() or {}
        user = get_current_user()

        with db_manager.get_session() as session:
            vuln_data = data.get("vulnerability", {})
            vi_data = data.get("instance", {})

            vuln = Vulnerability(
                cve_id=vuln_data.get("cve_id"),
                title=vuln_data.get("title", "手动添加漏洞"),
                description=vuln_data.get("description"),
                severity=SeverityEnum(vuln_data.get("severity", "medium")),
                cvss_score=vuln_data.get("cvss_score"),
                cwe_id=vuln_data.get("cwe_id"),
                reference=vuln_data.get("reference"),
                source=vuln_data.get("source", "manual"),
                extra_data=vuln_data.get("extra_data")
            )
            session.add(vuln)
            session.flush()

            fix_deadline_hours = config.work_order.DEADLINE_HOURS.get(vuln.severity.value, 72)
            vi = VulnerabilityInstance(
                vuln_id=vuln.id,
                asset_id=vi_data.get("asset_id"),
                risk_score=Decimal(str(vi_data.get("risk_score", 50))),
                fix_deadline=datetime.now(timezone.utc) + timedelta(hours=fix_deadline_hours),
                fix_status=FixStatusEnum(vi_data.get("fix_status", "pending")),
                is_high_priority=vi_data.get("is_high_priority", False),
                high_risk_reasons=vi_data.get("high_risk_reasons"),
                port=vi_data.get("port"),
                protocol=vi_data.get("protocol"),
                location=vi_data.get("location"),
                evidence=vi_data.get("evidence")
            )
            session.add(vi)
            session.flush()

            log_audit(
                action="vulnerability_create",
                resource_type="vulnerability_instance",
                resource_id=str(vi.id),
                detail=f"手动创建漏洞实例，漏洞: {vuln.title}, 资产ID: {vi.asset_id}",
                user=user,
                ip=request.remote_addr
            )

            return success(vuln_instance_to_dict(vi), "创建成功")
    except Exception as e:
        logger.exception(f"Create vulnerability error: {e}")
        return error(f"创建失败: {str(e)}", code=500, status_code=500)


@vuln_bp.route("/<int:vi_id>", methods=["PUT"])
@login_required
def update_vulnerability(vi_id):
    try:
        data = request.get_json() or {}
        user = get_current_user()

        with db_manager.get_session() as session:
            vi = session.query(VulnerabilityInstance).filter_by(id=vi_id).first()
            if not vi:
                return error("漏洞实例不存在", code=404, status_code=404)

            updatable_fields = [
                "fix_status", "risk_score", "fix_deadline", "is_high_priority",
                "high_risk_reasons", "port", "protocol", "location", "evidence"
            ]
            changes = []
            for field in updatable_fields:
                if field in data:
                    old_value = getattr(vi, field)
                    if field == "fix_status":
                        try:
                            new_value = FixStatusEnum(data[field])
                        except ValueError:
                            continue
                    elif field == "risk_score":
                        new_value = Decimal(str(data[field]))
                    elif field == "fix_deadline":
                        try:
                            new_value = datetime.fromisoformat(data[field].replace("Z", "+00:00"))
                        except ValueError:
                            continue
                    else:
                        new_value = data[field]
                    setattr(vi, field, new_value)
                    changes.append(f"{field}: {old_value} -> {new_value}")

            vi.updated_at = datetime.now(timezone.utc)

            log_audit(
                action="vulnerability_update",
                resource_type="vulnerability_instance",
                resource_id=str(vi_id),
                detail=f"更新漏洞实例，变更: {'; '.join(changes) if changes else '无变更'}",
                user=user,
                ip=request.remote_addr
            )

            return success(vuln_instance_to_dict(vi), "更新成功")
    except Exception as e:
        logger.exception(f"Update vulnerability {vi_id} error: {e}")
        return error(f"更新失败: {str(e)}", code=500, status_code=500)


@vuln_bp.route("/<int:vi_id>", methods=["DELETE"])
@login_required
def delete_vulnerability(vi_id):
    try:
        user = get_current_user()
        with db_manager.get_session() as session:
            vi = session.query(VulnerabilityInstance).filter_by(id=vi_id).first()
            if not vi:
                return error("漏洞实例不存在", code=404, status_code=404)

            session.delete(vi)

            log_audit(
                action="vulnerability_delete",
                resource_type="vulnerability_instance",
                resource_id=str(vi_id),
                detail=f"删除漏洞实例",
                user=user,
                ip=request.remote_addr
            )

            return success(None, "删除成功")
    except Exception as e:
        logger.exception(f"Delete vulnerability {vi_id} error: {e}")
        return error(f"删除失败: {str(e)}", code=500, status_code=500)


@vuln_bp.route("/<int:vi_id>/trigger-scan", methods=["POST"])
@login_required
def trigger_scan(vi_id):
    try:
        user = get_current_user()
        data = request.get_json() or {}

        with db_manager.get_session() as session:
            vi = session.query(VulnerabilityInstance).filter_by(id=vi_id).first()
            if not vi:
                return error("漏洞实例不存在", code=404, status_code=404)

            vi.updated_at = datetime.now(timezone.utc)

            log_audit(
                action="vulnerability_trigger_scan",
                resource_type="vulnerability_instance",
                resource_id=str(vi_id),
                detail=f"触发重新扫描/评估",
                user=user,
                ip=request.remote_addr
            )

            return success({"status": "scanning_triggered", "vuln_instance_id": vi_id}, "扫描已触发")
    except Exception as e:
        logger.exception(f"Trigger scan for {vi_id} error: {e}")
        return error(f"触发扫描失败: {str(e)}", code=500, status_code=500)


@vuln_bp.route("/batch-import", methods=["POST"])
@login_required
def batch_import():
    try:
        user = get_current_user()
        data = request.get_json() or {}
        items = data.get("items", [])

        with db_manager.get_session() as session:
            imported_count = 0
            for item in items:
                try:
                    vuln_data = item.get("vulnerability", {})
                    vi_data = item.get("instance", {})

                    vuln = Vulnerability(
                        cve_id=vuln_data.get("cve_id"),
                        title=vuln_data.get("title", "导入漏洞"),
                        description=vuln_data.get("description"),
                        severity=SeverityEnum(vuln_data.get("severity", "medium")),
                        cvss_score=vuln_data.get("cvss_score"),
                        cwe_id=vuln_data.get("cwe_id"),
                        reference=vuln_data.get("reference"),
                        source=vuln_data.get("source", "batch_import"),
                        extra_data=vuln_data.get("extra_data")
                    )
                    session.add(vuln)
                    session.flush()

                    fix_deadline_hours = config.work_order.DEADLINE_HOURS.get(vuln.severity.value, 72)
                    vi = VulnerabilityInstance(
                        vuln_id=vuln.id,
                        asset_id=vi_data.get("asset_id"),
                        risk_score=Decimal(str(vi_data.get("risk_score", 50))),
                        fix_deadline=datetime.now(timezone.utc) + timedelta(hours=fix_deadline_hours),
                        fix_status=FixStatusEnum(vi_data.get("fix_status", "pending")),
                        is_high_priority=vi_data.get("is_high_priority", False),
                        high_risk_reasons=vi_data.get("high_risk_reasons"),
                        port=vi_data.get("port"),
                        protocol=vi_data.get("protocol"),
                        location=vi_data.get("location"),
                        evidence=vi_data.get("evidence")
                    )
                    session.add(vi)
                    imported_count += 1
                except Exception as item_err:
                    logger.warning(f"Batch import item failed: {item_err}")
                    continue

            log_audit(
                action="vulnerability_batch_import",
                resource_type="vulnerability_instance",
                resource_id="-",
                detail=f"批量导入漏洞，成功 {imported_count}/{len(items)} 条",
                user=user,
                ip=request.remote_addr
            )

            return success({"imported": imported_count, "total": len(items)}, "批量导入完成")
    except Exception as e:
        logger.exception(f"Batch import error: {e}")
        return error(f"批量导入失败: {str(e)}", code=500, status_code=500)


@vuln_bp.route("/stats", methods=["GET"])
@login_required
def vuln_stats():
    try:
        with db_manager.get_session() as session:
            by_severity = session.query(
                Vulnerability.severity, func.count(VulnerabilityInstance.id)
            ).join(
                VulnerabilityInstance, Vulnerability.id == VulnerabilityInstance.vuln_id
            ).group_by(Vulnerability.severity).all()

            severity_stats = {}
            for sev, count in by_severity:
                severity_stats[sev.value] = count

            by_asset_type = session.query(
                Asset.type, func.count(VulnerabilityInstance.id)
            ).join(
                VulnerabilityInstance, Asset.id == VulnerabilityInstance.asset_id
            ).group_by(Asset.type).all()

            asset_type_stats = {}
            for atype, count in by_asset_type:
                asset_type_stats[atype] = count

            by_status = session.query(
                VulnerabilityInstance.fix_status, func.count(VulnerabilityInstance.id)
            ).group_by(VulnerabilityInstance.fix_status).all()

            status_stats = {}
            for st, count in by_status:
                status_stats[st.value] = count

            total = session.query(func.count(VulnerabilityInstance.id)).scalar() or 0

            return success({
                "total": total,
                "by_severity": severity_stats,
                "by_asset_type": asset_type_stats,
                "by_fix_status": status_stats
            })
    except Exception as e:
        logger.exception(f"Vuln stats error: {e}")
        return error(f"统计失败: {str(e)}", code=500, status_code=500)


app.register_blueprint(vuln_bp)


wo_bp = Blueprint("work_orders", __name__, url_prefix="/api/work-orders")


@wo_bp.route("", methods=["GET"])
@login_required
def list_work_orders():
    try:
        page, page_size = get_page_args()
        status = request.args.get("status")
        assignee = request.args.get("assignee")
        department = request.args.get("department")
        severity = request.args.get("severity")
        escalation_level = request.args.get("escalation_level", type=int)
        overdue = request.args.get("overdue", type=lambda x: x.lower() == "true")
        start_date = request.args.get("start_date")
        end_date = request.args.get("end_date")
        sort_by = request.args.get("sort_by", "created_at")
        sort_order = request.args.get("sort_order", "desc")

        with db_manager.get_session() as session:
            query = session.query(WorkOrder).join(
                VulnerabilityInstance, WorkOrder.vuln_instance_id == VulnerabilityInstance.id
            ).join(
                Vulnerability, VulnerabilityInstance.vuln_id == Vulnerability.id
            ).join(
                Asset, VulnerabilityInstance.asset_id == Asset.id
            )

            conditions = []
            if status:
                try:
                    conditions.append(WorkOrder.status == WorkOrderStatusEnum(status))
                except ValueError:
                    pass
            if assignee:
                conditions.append(WorkOrder.assignee == assignee)
            if department:
                conditions.append(Asset.department == department)
            if severity:
                try:
                    conditions.append(Vulnerability.severity == SeverityEnum(severity))
                except ValueError:
                    pass
            if escalation_level is not None:
                conditions.append(WorkOrder.escalation_level >= escalation_level)
            if overdue:
                conditions.append(WorkOrder.deadline < datetime.now(timezone.utc))
            if start_date:
                try:
                    start_dt = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
                    conditions.append(WorkOrder.created_at >= start_dt)
                except ValueError:
                    pass
            if end_date:
                try:
                    end_dt = datetime.fromisoformat(end_date.replace("Z", "+00:00"))
                    conditions.append(WorkOrder.created_at <= end_dt)
                except ValueError:
                    pass

            if conditions:
                query = query.filter(and_(*conditions))

            total = query.count()

            sort_column = None
            if sort_by == "deadline":
                sort_column = WorkOrder.deadline
            elif sort_by == "escalation_level":
                sort_column = WorkOrder.escalation_level
            elif sort_by == "status":
                sort_column = WorkOrder.status
            else:
                sort_column = WorkOrder.created_at

            if sort_order == "asc":
                query = query.order_by(sort_column.asc())
            else:
                query = query.order_by(sort_column.desc())

            offset = (page - 1) * page_size
            orders = query.offset(offset).limit(page_size).all()

            items = [work_order_to_dict(wo) for wo in orders]
            return success(paginate_result(items, total, page, page_size))
    except Exception as e:
        logger.exception(f"List work orders error: {e}")
        return error(f"查询失败: {str(e)}", code=500, status_code=500)


@wo_bp.route("/<int:wo_id>", methods=["GET"])
@login_required
def get_work_order(wo_id):
    try:
        with db_manager.get_session() as session:
            wo = session.query(WorkOrder).filter_by(id=wo_id).first()
            if not wo:
                return error("工单不存在", code=404, status_code=404)

            result = work_order_to_dict(wo)

            timeline = []
            if wo.created_at:
                timeline.append({
                    "time": wo.created_at.isoformat(),
                    "event": "工单创建",
                    "operator": "system",
                    "detail": f"工单创建，截止日期: {wo.deadline.isoformat()}"
                })
            if wo.started_at:
                timeline.append({
                    "time": wo.started_at.isoformat(),
                    "event": "开始修复",
                    "operator": wo.assignee,
                    "detail": "修复工作开始"
                })
            if wo.fixed_at:
                timeline.append({
                    "time": wo.fixed_at.isoformat(),
                    "event": "修复完成",
                    "operator": wo.assignee,
                    "detail": "漏洞已修复，等待验证"
                })
            if wo.verified_at:
                timeline.append({
                    "time": wo.verified_at.isoformat(),
                    "event": "验证完成",
                    "operator": "system",
                    "detail": "验证扫描完成"
                })
            if wo.closed_at:
                timeline.append({
                    "time": wo.closed_at.isoformat(),
                    "event": "工单关闭",
                    "operator": "system",
                    "detail": "工单已关闭"
                })

            for er in result.get("escalation_records", []):
                timeline.append({
                    "time": er.get("created_at"),
                    "event": "工单升级",
                    "operator": er.get("escalated_by"),
                    "detail": f"升级至等级 {er.get('new_level')}, 原因: {er.get('reason')}"
                })

            timeline.sort(key=lambda x: x.get("time", ""))
            result["timeline"] = timeline

            return success(result)
    except Exception as e:
        logger.exception(f"Get work order {wo_id} error: {e}")
        return error(f"查询失败: {str(e)}", code=500, status_code=500)


@wo_bp.route("", methods=["POST"])
@login_required
def create_work_order():
    try:
        data = request.get_json() or {}
        user = get_current_user()
        vuln_instance_id = data.get("vuln_instance_id")

        if not vuln_instance_id:
            return error("缺少 vuln_instance_id 参数", code=400, status_code=400)

        new_wo = work_order_creator.create(vuln_instance_id, operator=user)
        if not new_wo:
            return error("创建工单失败", code=500, status_code=500)

        with db_manager.get_session() as session:
            wo = (
                session.query(WorkOrder)
                .options(
                    joinedload(WorkOrder.vuln_instance)
                    .joinedload(VulnerabilityInstance.vulnerability),
                    joinedload(WorkOrder.vuln_instance)
                    .joinedload(VulnerabilityInstance.asset),
                    joinedload(WorkOrder.notifications),
                    joinedload(WorkOrder.escalation_records),
                )
                .filter_by(id=new_wo.id)
                .first()
            )
            if wo and data.get("assignee"):
                wo.assignee = data["assignee"]
                wo.updated_at = datetime.now(timezone.utc)
                session.flush()
            wo_dict = work_order_to_dict(wo, include_relations=True) if wo else None

        return success(wo_dict, "创建成功")
    except Exception as e:
        logger.exception(f"Create work order error: {e}")
        return error(f"创建失败: {str(e)}", code=500, status_code=500)


@wo_bp.route("/<int:wo_id>", methods=["PUT"])
@login_required
def update_work_order(wo_id):
    try:
        data = request.get_json() or {}
        user = get_current_user()

        with db_manager.get_session() as session:
            wo = session.query(WorkOrder).filter_by(id=wo_id).first()
            if not wo:
                return error("工单不存在", code=404, status_code=404)

            changes = []
            if "assignee" in data:
                old = wo.assignee
                wo.assignee = data["assignee"]
                changes.append(f"assignee: {old} -> {data['assignee']}")
            if "deadline" in data:
                try:
                    old = wo.deadline
                    new_deadline = datetime.fromisoformat(data["deadline"].replace("Z", "+00:00"))
                    wo.deadline = new_deadline
                    changes.append(f"deadline: {old} -> {new_deadline}")
                except ValueError:
                    pass
            if "remarks" in data:
                wo.remarks = data["remarks"]
                changes.append("remarks updated")
            if "priority" in data:
                wo.priority = data["priority"]
                changes.append(f"priority: {wo.priority} -> {data['priority']}")

            wo.updated_at = datetime.now(timezone.utc)

            log_audit(
                action="work_order_update",
                resource_type="work_order",
                resource_id=str(wo_id),
                detail=f"更新工单: {'; '.join(changes) if changes else '无变更'}",
                user=user,
                ip=request.remote_addr
            )

            return success(work_order_to_dict(wo), "更新成功")
    except Exception as e:
        logger.exception(f"Update work order {wo_id} error: {e}")
        return error(f"更新失败: {str(e)}", code=500, status_code=500)


@wo_bp.route("/<int:wo_id>", methods=["DELETE"])
@login_required
def delete_work_order(wo_id):
    try:
        user = get_current_user()
        with db_manager.get_session() as session:
            wo = session.query(WorkOrder).filter_by(id=wo_id).first()
            if not wo:
                return error("工单不存在", code=404, status_code=404)

            session.delete(wo)

            log_audit(
                action="work_order_delete",
                resource_type="work_order",
                resource_id=str(wo_id),
                detail=f"删除工单",
                user=user,
                ip=request.remote_addr
            )

            return success(None, "删除成功")
    except Exception as e:
        logger.exception(f"Delete work order {wo_id} error: {e}")
        return error(f"删除失败: {str(e)}", code=500, status_code=500)


@wo_bp.route("/<int:wo_id>/status", methods=["POST"])
@login_required
def update_wo_status(wo_id):
    try:
        data = request.get_json() or {}
        user = get_current_user() or "system"
        new_status_str = data.get("new_status")
        reason = data.get("reason", "")

        if not new_status_str:
            return error("缺少 new_status 参数", code=400, status_code=400)

        try:
            new_status = WorkOrderStatusEnum(new_status_str)
        except ValueError:
            return error(f"无效的状态值: {new_status_str}", code=400, status_code=400)

        wo = status_manager.update_status(wo_id, new_status, user, reason)
        if not wo:
            return error("更新状态失败，工单不存在或状态流转无效", code=500, status_code=500)

        return success(work_order_to_dict(wo), "状态更新成功")
    except ValueError as e:
        return error(str(e), code=400, status_code=400)
    except Exception as e:
        logger.exception(f"Update work order {wo_id} status error: {e}")
        return error(f"状态更新失败: {str(e)}", code=500, status_code=500)


@wo_bp.route("/<int:wo_id>/assign", methods=["POST"])
@login_required
def assign_work_order(wo_id):
    try:
        data = request.get_json() or {}
        user = get_current_user() or "system"
        assignee = data.get("assignee")
        reason = data.get("reason", "")

        if not assignee:
            return error("缺少 assignee 参数", code=400, status_code=400)

        with db_manager.get_session() as session:
            wo = session.query(WorkOrder).filter_by(id=wo_id).first()
            if not wo:
                return error("工单不存在", code=404, status_code=404)

            old_assignee = wo.assignee
            wo.assignee = assignee
            wo.updated_at = datetime.now(timezone.utc)

            log_audit(
                action="work_order_assign",
                resource_type="work_order",
                resource_id=str(wo_id),
                detail=f"重新分配工单: {old_assignee} -> {assignee}, 原因: {reason}",
                user=user,
                ip=request.remote_addr
            )

            return success(work_order_to_dict(wo), "分配成功")
    except Exception as e:
        logger.exception(f"Assign work order {wo_id} error: {e}")
        return error(f"分配失败: {str(e)}", code=500, status_code=500)


@wo_bp.route("/<int:wo_id>/escalate", methods=["POST"])
@login_required
def escalate_work_order(wo_id):
    try:
        data = request.get_json() or {}
        user = get_current_user() or "system"
        level_raw = data.get("level")
        reason = data.get("reason", "")

        if level_raw is None:
            return error("缺少 level 参数", code=400, status_code=400)
        try:
            level = int(level_raw)
        except (ValueError, TypeError):
            return error("level 必须是整数", code=400, status_code=400)

        with db_manager.get_session() as session:
            wo = session.query(WorkOrder).filter_by(id=wo_id).first()
            if not wo:
                return error("工单不存在", code=404, status_code=404)

            old_level = wo.escalation_level
            wo.escalation_level = max(level, old_level)
            wo.updated_at = datetime.now(timezone.utc)

            er = EscalationRecord(
                work_order_id=wo_id,
                old_level=old_level,
                new_level=wo.escalation_level,
                reason=reason or "手动升级",
                escalated_by=user
            )
            session.add(er)

            log_audit(
                action="work_order_escalate",
                resource_type="work_order",
                resource_id=str(wo_id),
                detail=f"手动升级工单: {old_level} -> {wo.escalation_level}, 原因: {reason}",
                user=user,
                ip=request.remote_addr
            )

            return success(work_order_to_dict(wo), "升级成功")
    except Exception as e:
        logger.exception(f"Escalate work order {wo_id} error: {e}")
        return error(f"升级失败: {str(e)}", code=500, status_code=500)


@wo_bp.route("/<int:wo_id>/verify", methods=["POST"])
@login_required
def verify_work_order(wo_id):
    try:
        data = request.get_json() or {}
        user = get_current_user() or "system"
        scan_type = data.get("scan_type", "quick")

        result = verification_scanner.trigger_verification(
            wo_id, operator=user, scan_type=scan_type
        )

        if not result:
            return error("触发验证失败", code=500, status_code=500)

        if config.TEST_MODE:
            mock_result = verification_scanner.mock_scan_result(result.vuln_instance_id)
            processed_wo = verification_processor.process_verification_result(
                mock_result.vuln_instance_id,
                mock_result.is_fixed,
                mock_result.details,
                user,
                mock_result.scan_type,
                mock_result.scan_id,
                mock_result.evidence
            )
            if processed_wo:
                return success(work_order_to_dict(processed_wo), f"验证完成，结果: {'通过' if mock_result.is_fixed else '未通过'}")

        return success(result.to_dict(), "验证已触发")
    except Exception as e:
        logger.exception(f"Verify work order {wo_id} error: {e}")
        return error(f"验证失败: {str(e)}", code=500, status_code=500)


@wo_bp.route("/stats", methods=["GET"])
@login_required
def work_order_stats():
    try:
        with db_manager.get_session() as session:
            by_status = session.query(
                WorkOrder.status, func.count(WorkOrder.id)
            ).group_by(WorkOrder.status).all()

            status_stats = {}
            for st, count in by_status:
                status_stats[st.value] = count

            now = datetime.now(timezone.utc)
            overdue_count = session.query(func.count(WorkOrder.id)).filter(
                WorkOrder.status != WorkOrderStatusEnum.CLOSED,
                WorkOrder.deadline < now
            ).scalar() or 0

            closed_orders = session.query(WorkOrder).filter(
                WorkOrder.status == WorkOrderStatusEnum.CLOSED,
                WorkOrder.closed_at.isnot(None),
                WorkOrder.created_at.isnot(None)
            ).limit(100).all()

            avg_duration = 0.0
            if closed_orders:
                durations = []
                for wo in closed_orders:
                    if wo.closed_at and wo.created_at:
                        durations.append((wo.closed_at - wo.created_at).total_seconds() / 3600)
                if durations:
                    avg_duration = sum(durations) / len(durations)

            total = session.query(func.count(WorkOrder.id)).scalar() or 0
            pending = status_stats.get("pending", 0)
            fixing = status_stats.get("fixing", 0)
            fixed = status_stats.get("fixed", 0)
            verifying = status_stats.get("verifying", 0)
            closed = status_stats.get("closed", 0)

            return success({
                "total": total,
                "by_status": status_stats,
                "pending": pending,
                "fixing": fixing,
                "fixed": fixed,
                "verifying": verifying,
                "closed": closed,
                "overdue_count": overdue_count,
                "overdue_rate": (overdue_count / total * 100) if total > 0 else 0,
                "avg_fix_duration_hours": round(avg_duration, 2),
                "fix_rate": (closed / total * 100) if total > 0 else 0
            })
    except Exception as e:
        logger.exception(f"Work order stats error: {e}")
        return error(f"统计失败: {str(e)}", code=500, status_code=500)


@wo_bp.route("/valid-statuses/<current>", methods=["GET"])
@login_required
def get_valid_statuses(current):
    try:
        try:
            current_status = WorkOrderStatusEnum(current)
        except ValueError:
            return error(f"无效的状态值: {current}", code=400, status_code=400)

        valid = status_manager.get_valid_next_statuses(current_status)
        return success([s.value for s in valid])
    except Exception as e:
        logger.exception(f"Get valid statuses error: {e}")
        return error(f"查询失败: {str(e)}", code=500, status_code=500)


app.register_blueprint(wo_bp)


asset_bp = Blueprint("assets", __name__, url_prefix="/api/assets")


@asset_bp.route("", methods=["GET"])
@login_required
def list_assets():
    try:
        page, page_size = get_page_args()
        keyword = request.args.get("keyword")
        asset_type = request.args.get("type")
        importance = request.args.get("importance", type=int)
        department = request.args.get("department")
        owner = request.args.get("owner")
        sort_by = request.args.get("sort_by", "created_at")
        sort_order = request.args.get("sort_order", "desc")

        with db_manager.get_session() as session:
            query = session.query(Asset)
            conditions = []

            if keyword:
                conditions.append(or_(
                    Asset.name.like(f"%{keyword}%"),
                    Asset.ip.like(f"%{keyword}%"),
                    Asset.description.like(f"%{keyword}%")
                ))
            if asset_type:
                conditions.append(Asset.type == asset_type)
            if importance is not None:
                conditions.append(Asset.importance == importance)
            if department:
                conditions.append(Asset.department == department)
            if owner:
                conditions.append(Asset.owner == owner)

            if conditions:
                query = query.filter(and_(*conditions))

            total = query.count()

            sort_column = None
            if sort_by == "name":
                sort_column = Asset.name
            elif sort_by == "importance":
                sort_column = Asset.importance
            elif sort_by == "department":
                sort_column = Asset.department
            elif sort_by == "type":
                sort_column = Asset.type
            else:
                sort_column = Asset.created_at

            if sort_order == "asc":
                query = query.order_by(sort_column.asc())
            else:
                query = query.order_by(sort_column.desc())

            offset = (page - 1) * page_size
            assets = query.offset(offset).limit(page_size).all()

            items = [asset_to_dict(a) for a in assets]
            for item, asset in zip(items, assets):
                vuln_count = session.query(func.count(VulnerabilityInstance.id)).filter_by(
                    asset_id=asset.id
                ).scalar() or 0
                item["vuln_count"] = vuln_count
                active_vuln_count = session.query(func.count(VulnerabilityInstance.id)).filter(
                    VulnerabilityInstance.asset_id == asset.id,
                    VulnerabilityInstance.fix_status != FixStatusEnum.VERIFIED
                ).scalar() or 0
                item["active_vuln_count"] = active_vuln_count

            return success(paginate_result(items, total, page, page_size))
    except Exception as e:
        logger.exception(f"List assets error: {e}")
        return error(f"查询失败: {str(e)}", code=500, status_code=500)


@asset_bp.route("/<int:asset_id>", methods=["GET"])
@login_required
def get_asset(asset_id):
    try:
        with db_manager.get_session() as session:
            asset = session.query(Asset).filter_by(id=asset_id).first()
            if not asset:
                return error("资产不存在", code=404, status_code=404)

            result = asset_to_dict(asset)

            vuln_instances = session.query(VulnerabilityInstance).filter_by(asset_id=asset_id).all()
            result["vuln_instances"] = [vuln_instance_to_dict(vi, include_relations=False) for vi in vuln_instances]

            by_severity = session.query(
                Vulnerability.severity, func.count(VulnerabilityInstance.id)
            ).join(
                Vulnerability, VulnerabilityInstance.vuln_id == Vulnerability.id
            ).filter(
                VulnerabilityInstance.asset_id == asset_id
            ).group_by(Vulnerability.severity).all()

            vuln_stats = {}
            for sev, count in by_severity:
                vuln_stats[sev.value] = count
            result["vuln_stats"] = vuln_stats
            result["total_vulns"] = sum(vuln_stats.values())

            by_status = session.query(
                VulnerabilityInstance.fix_status, func.count(VulnerabilityInstance.id)
            ).filter_by(asset_id=asset_id).group_by(VulnerabilityInstance.fix_status).all()

            status_stats = {}
            for st, count in by_status:
                status_stats[st.value] = count
            result["fix_status_stats"] = status_stats

            return success(result)
    except Exception as e:
        logger.exception(f"Get asset {asset_id} error: {e}")
        return error(f"查询失败: {str(e)}", code=500, status_code=500)


@asset_bp.route("", methods=["POST"])
@login_required
def create_asset():
    try:
        data = request.get_json() or {}
        user = get_current_user()

        required_fields = ["name", "ip", "type", "importance", "owner", "department"]
        for f in required_fields:
            if not data.get(f):
                return error(f"缺少必填字段: {f}", code=400, status_code=400)

        with db_manager.get_session() as session:
            asset = Asset(
                name=data["name"],
                ip=data["ip"],
                type=data["type"],
                importance=int(data["importance"]),
                owner=data["owner"],
                department=data["department"],
                description=data.get("description")
            )
            session.add(asset)
            session.flush()

            log_audit(
                action="asset_create",
                resource_type="asset",
                resource_id=str(asset.id),
                detail=f"创建资产: {asset.name} ({asset.ip})",
                user=user,
                ip=request.remote_addr
            )

            return success(asset_to_dict(asset), "创建成功")
    except Exception as e:
        logger.exception(f"Create asset error: {e}")
        return error(f"创建失败: {str(e)}", code=500, status_code=500)


@asset_bp.route("/<int:asset_id>", methods=["PUT"])
@login_required
def update_asset(asset_id):
    try:
        data = request.get_json() or {}
        user = get_current_user()

        with db_manager.get_session() as session:
            asset = session.query(Asset).filter_by(id=asset_id).first()
            if not asset:
                return error("资产不存在", code=404, status_code=404)

            updatable = ["name", "ip", "type", "importance", "owner", "department", "description"]
            changes = []
            for field in updatable:
                if field in data:
                    old = getattr(asset, field)
                    new_val = int(data[field]) if field == "importance" else data[field]
                    setattr(asset, field, new_val)
                    changes.append(f"{field}: {old} -> {new_val}")

            asset.updated_at = datetime.now(timezone.utc)

            log_audit(
                action="asset_update",
                resource_type="asset",
                resource_id=str(asset_id),
                detail=f"更新资产: {'; '.join(changes) if changes else '无变更'}",
                user=user,
                ip=request.remote_addr
            )

            return success(asset_to_dict(asset), "更新成功")
    except Exception as e:
        logger.exception(f"Update asset {asset_id} error: {e}")
        return error(f"更新失败: {str(e)}", code=500, status_code=500)


@asset_bp.route("/<int:asset_id>", methods=["DELETE"])
@login_required
def delete_asset(asset_id):
    try:
        user = get_current_user()
        with db_manager.get_session() as session:
            asset = session.query(Asset).filter_by(id=asset_id).first()
            if not asset:
                return error("资产不存在", code=404, status_code=404)

            session.delete(asset)

            log_audit(
                action="asset_delete",
                resource_type="asset",
                resource_id=str(asset_id),
                detail=f"删除资产: {asset.name}",
                user=user,
                ip=request.remote_addr
            )

            return success(None, "删除成功")
    except Exception as e:
        logger.exception(f"Delete asset {asset_id} error: {e}")
        return error(f"删除失败: {str(e)}", code=500, status_code=500)


@asset_bp.route("/stats", methods=["GET"])
@login_required
def asset_stats():
    try:
        with db_manager.get_session() as session:
            by_importance = session.query(
                Asset.importance, func.count(Asset.id)
            ).group_by(Asset.importance).all()
            importance_stats = {str(i): c for i, c in by_importance}

            by_type = session.query(
                Asset.type, func.count(Asset.id)
            ).group_by(Asset.type).all()
            type_stats = {t: c for t, c in by_type}

            by_department = session.query(
                Asset.department, func.count(Asset.id)
            ).group_by(Asset.department).all()
            dept_stats = {d: c for d, c in by_department}

            total = session.query(func.count(Asset.id)).scalar() or 0

            return success({
                "total": total,
                "by_importance": importance_stats,
                "by_type": type_stats,
                "by_department": dept_stats
            })
    except Exception as e:
        logger.exception(f"Asset stats error: {e}")
        return error(f"统计失败: {str(e)}", code=500, status_code=500)


app.register_blueprint(asset_bp)


incident_bp = Blueprint("incidents", __name__, url_prefix="/api/incidents")


@incident_bp.route("", methods=["GET"])
@login_required
def list_incidents():
    try:
        page, page_size = get_page_args()
        status = request.args.get("status")
        incident_type = request.args.get("type")
        severity = request.args.get("severity")
        created_by = request.args.get("created_by")
        assigned_to = request.args.get("assigned_to")
        keyword = request.args.get("keyword")
        start_date = request.args.get("start_date")
        end_date = request.args.get("end_date")

        with db_manager.get_session() as session:
            query = session.query(Incident)
            conditions = []

            if status:
                try:
                    conditions.append(Incident.status == IncidentStatusEnum(status))
                except ValueError:
                    pass
            if incident_type:
                try:
                    conditions.append(Incident.type == IncidentTypeEnum(incident_type))
                except ValueError:
                    pass
            if severity:
                try:
                    conditions.append(Incident.severity == SeverityEnum(severity))
                except ValueError:
                    pass
            if created_by:
                conditions.append(Incident.created_by == created_by)
            if assigned_to:
                conditions.append(Incident.assigned_to == assigned_to)
            if keyword:
                conditions.append(or_(
                    Incident.title.like(f"%{keyword}%"),
                    Incident.description.like(f"%{keyword}%")
                ))
            if start_date:
                try:
                    start_dt = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
                    conditions.append(Incident.created_at >= start_dt)
                except ValueError:
                    pass
            if end_date:
                try:
                    end_dt = datetime.fromisoformat(end_date.replace("Z", "+00:00"))
                    conditions.append(Incident.created_at <= end_dt)
                except ValueError:
                    pass

            if conditions:
                query = query.filter(and_(*conditions))

            total = query.count()
            query = query.order_by(Incident.created_at.desc())

            offset = (page - 1) * page_size
            incidents = query.offset(offset).limit(page_size).all()

            items = [incident_to_dict(inc) for inc in incidents]
            return success(paginate_result(items, total, page, page_size))
    except Exception as e:
        logger.exception(f"List incidents error: {e}")
        return error(f"查询失败: {str(e)}", code=500, status_code=500)


@incident_bp.route("/<int:incident_id>", methods=["GET"])
@login_required
def get_incident(incident_id):
    try:
        with db_manager.get_session() as session:
            incident = session.query(Incident).filter_by(id=incident_id).first()
            if not incident:
                return error("安全事件不存在", code=404, status_code=404)

            result = incident_to_dict(incident)
            return success(result)
    except Exception as e:
        logger.exception(f"Get incident {incident_id} error: {e}")
        return error(f"查询失败: {str(e)}", code=500, status_code=500)


@incident_bp.route("", methods=["POST"])
@login_required
def create_incident():
    try:
        data = request.get_json() or {}
        user = get_current_user() or "system"

        required = ["title", "description", "type", "severity"]
        for f in required:
            if not data.get(f):
                return error(f"缺少必填字段: {f}", code=400, status_code=400)

        with db_manager.get_session() as session:
            incident = Incident(
                title=data["title"],
                description=data["description"],
                type=IncidentTypeEnum(data["type"]),
                severity=SeverityEnum(data["severity"]),
                status=IncidentStatusEnum(data.get("status", "open")),
                assets_affected=data.get("assets_affected"),
                created_by=user,
                assigned_to=data.get("assigned_to")
            )
            session.add(incident)
            session.flush()

            timeline = IncidentTimeline(
                incident_id=incident.id,
                event_type=IncidentEventTypeEnum.DETECTED,
                description=f"安全事件创建，类型: {data['type']}, 严重级别: {data['severity']}",
                operator=user
            )
            session.add(timeline)

            log_audit(
                action="incident_create",
                resource_type="incident",
                resource_id=str(incident.id),
                detail=f"创建安全事件: {incident.title}",
                user=user,
                ip=request.remote_addr
            )

            return success(incident_to_dict(incident), "创建成功")
    except Exception as e:
        logger.exception(f"Create incident error: {e}")
        return error(f"创建失败: {str(e)}", code=500, status_code=500)


@incident_bp.route("/<int:incident_id>", methods=["PUT"])
@login_required
def update_incident(incident_id):
    try:
        data = request.get_json() or {}
        user = get_current_user()

        with db_manager.get_session() as session:
            incident = session.query(Incident).filter_by(id=incident_id).first()
            if not incident:
                return error("安全事件不存在", code=404, status_code=404)

            updatable = ["title", "description", "type", "severity", "assets_affected", "assigned_to"]
            for field in updatable:
                if field in data:
                    if field == "type":
                        try:
                            incident.type = IncidentTypeEnum(data[field])
                        except ValueError:
                            pass
                    elif field == "severity":
                        try:
                            incident.severity = SeverityEnum(data[field])
                        except ValueError:
                            pass
                    else:
                        setattr(incident, field, data[field])

            incident.updated_at = datetime.now(timezone.utc)

            log_audit(
                action="incident_update",
                resource_type="incident",
                resource_id=str(incident_id),
                detail=f"更新安全事件",
                user=user,
                ip=request.remote_addr
            )

            return success(incident_to_dict(incident), "更新成功")
    except Exception as e:
        logger.exception(f"Update incident {incident_id} error: {e}")
        return error(f"更新失败: {str(e)}", code=500, status_code=500)


@incident_bp.route("/<int:incident_id>", methods=["DELETE"])
@login_required
def delete_incident(incident_id):
    try:
        user = get_current_user()
        with db_manager.get_session() as session:
            incident = session.query(Incident).filter_by(id=incident_id).first()
            if not incident:
                return error("安全事件不存在", code=404, status_code=404)

            session.delete(incident)

            log_audit(
                action="incident_delete",
                resource_type="incident",
                resource_id=str(incident_id),
                detail=f"删除安全事件",
                user=user,
                ip=request.remote_addr
            )

            return success(None, "删除成功")
    except Exception as e:
        logger.exception(f"Delete incident {incident_id} error: {e}")
        return error(f"删除失败: {str(e)}", code=500, status_code=500)


@incident_bp.route("/<int:incident_id>/status", methods=["POST"])
@login_required
def update_incident_status(incident_id):
    try:
        data = request.get_json() or {}
        user = get_current_user() or "system"
        new_status_str = data.get("new_status")
        reason = data.get("reason", "")

        if not new_status_str:
            return error("缺少 new_status 参数", code=400, status_code=400)

        try:
            new_status = IncidentStatusEnum(new_status_str)
        except ValueError:
            return error(f"无效的状态值: {new_status_str}", code=400, status_code=400)

        with db_manager.get_session() as session:
            incident = session.query(Incident).filter_by(id=incident_id).first()
            if not incident:
                return error("安全事件不存在", code=404, status_code=404)

            old_status = incident.status
            incident.status = new_status
            now = datetime.now(timezone.utc)
            incident.updated_at = now

            if new_status == IncidentStatusEnum.RECOVERED:
                incident.resolved_at = now
            if new_status == IncidentStatusEnum.CLOSED:
                incident.closed_at = now

            timeline = IncidentTimeline(
                incident_id=incident_id,
                event_type=IncidentEventTypeEnum.TRIAGED,
                description=f"状态变更: {old_status.value} -> {new_status.value}, 原因: {reason}",
                operator=user
            )
            session.add(timeline)

            log_audit(
                action="incident_status_update",
                resource_type="incident",
                resource_id=str(incident_id),
                detail=f"状态变更: {old_status.value} -> {new_status.value}",
                user=user,
                ip=request.remote_addr
            )

            return success(incident_to_dict(incident), "状态更新成功")
    except Exception as e:
        logger.exception(f"Update incident {incident_id} status error: {e}")
        return error(f"状态更新失败: {str(e)}", code=500, status_code=500)


@incident_bp.route("/<int:incident_id>/timeline", methods=["POST"])
@login_required
def add_incident_timeline(incident_id):
    try:
        data = request.get_json() or {}
        user = get_current_user() or "system"
        event_type_str = data.get("event_type", "comment")
        description = data.get("description", "")

        if not description:
            return error("缺少 description 参数", code=400, status_code=400)

        try:
            event_type = IncidentEventTypeEnum(event_type_str)
        except ValueError:
            event_type = IncidentEventTypeEnum.COMMENT

        with db_manager.get_session() as session:
            incident = session.query(Incident).filter_by(id=incident_id).first()
            if not incident:
                return error("安全事件不存在", code=404, status_code=404)

            timeline = IncidentTimeline(
                incident_id=incident_id,
                event_type=event_type,
                description=description,
                operator=user
            )
            session.add(timeline)
            incident.updated_at = datetime.now(timezone.utc)

            log_audit(
                action="incident_timeline_add",
                resource_type="incident",
                resource_id=str(incident_id),
                detail=f"添加时间线事件: {event_type.value} - {description[:100]}",
                user=user,
                ip=request.remote_addr
            )

            return success(model_to_dict(timeline), "添加成功")
    except Exception as e:
        logger.exception(f"Add incident timeline error: {e}")
        return error(f"添加失败: {str(e)}", code=500, status_code=500)


@incident_bp.route("/<int:incident_id>/analyze", methods=["GET"])
@login_required
def analyze_incident(incident_id):
    try:
        user = get_current_user()
        with db_manager.get_session() as session:
            incident = session.query(Incident).filter_by(id=incident_id).first()
            if not incident:
                return error("安全事件不存在", code=404, status_code=404)

            timelines = session.query(IncidentTimeline).filter_by(
                incident_id=incident_id
            ).order_by(IncidentTimeline.created_at.asc()).all()

            analysis_report = {
                "incident_id": incident.id,
                "title": incident.title,
                "type": incident.type.value,
                "severity": incident.severity.value,
                "status": incident.status.value,
                "duration_hours": 0,
                "timeline_count": len(timelines),
                "analysis": {
                    "summary": f"安全事件分析：{incident.title}",
                    "key_findings": [
                        f"事件类型: {incident.type.value}",
                        f"严重级别: {incident.severity.value}",
                        f"当前状态: {incident.status.value}",
                        f"时间线事件数: {len(timelines)}"
                    ],
                    "recommendations": [
                        "建议核查相关漏洞修复情况",
                        "建议检查同类资产是否存在类似问题",
                        "建议完善相关安全防护措施"
                    ]
                },
                "timeline": [model_to_dict(t) for t in timelines]
            }

            if incident.created_at:
                now = datetime.now(timezone.utc)
                analysis_report["duration_hours"] = round(
                    (now - incident.created_at).total_seconds() / 3600, 2
                )

            log_audit(
                action="incident_analyze",
                resource_type="incident",
                resource_id=str(incident_id),
                detail="触发事件分析",
                user=user,
                ip=request.remote_addr
            )

            return success(analysis_report, "分析完成")
    except Exception as e:
        logger.exception(f"Analyze incident {incident_id} error: {e}")
        return error(f"分析失败: {str(e)}", code=500, status_code=500)


app.register_blueprint(incident_bp)


dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api/dashboard")


@dashboard_bp.route("/summary", methods=["GET"])
@login_required
def dashboard_summary():
    try:
        with db_manager.get_session() as session:
            today = datetime.now(timezone.utc)
            today_start = datetime(today.year, today.month, today.day, tzinfo=timezone.utc)

            total_vulns = session.query(func.count(VulnerabilityInstance.id)).scalar() or 0
            pending_fix = session.query(func.count(VulnerabilityInstance.id)).filter(
                VulnerabilityInstance.fix_status.in_([
                    FixStatusEnum.PENDING, FixStatusEnum.IN_PROGRESS
                ])
            ).scalar() or 0
            fixed_vulns = session.query(func.count(VulnerabilityInstance.id)).filter(
                VulnerabilityInstance.fix_status == FixStatusEnum.VERIFIED
            ).scalar() or 0

            fix_rate = (fixed_vulns / total_vulns * 100) if total_vulns > 0 else 0

            active_work_orders = session.query(func.count(WorkOrder.id)).filter(
                WorkOrder.status != WorkOrderStatusEnum.CLOSED
            ).scalar() or 0
            overdue_work_orders = session.query(func.count(WorkOrder.id)).filter(
                WorkOrder.status != WorkOrderStatusEnum.CLOSED,
                WorkOrder.deadline < today
            ).scalar() or 0
            overdue_rate = (overdue_work_orders / active_work_orders * 100) if active_work_orders > 0 else 0

            today_new = session.query(func.count(VulnerabilityInstance.id)).filter(
                VulnerabilityInstance.discovery_time >= today_start
            ).scalar() or 0

            closed_orders = session.query(WorkOrder).filter(
                WorkOrder.status == WorkOrderStatusEnum.CLOSED,
                WorkOrder.closed_at.isnot(None),
                WorkOrder.created_at.isnot(None)
            ).limit(100).all()
            avg_fix_hours = 0.0
            if closed_orders:
                durations = []
                for wo in closed_orders:
                    if wo.closed_at and wo.created_at:
                        durations.append((wo.closed_at - wo.created_at).total_seconds() / 3600)
                if durations:
                    avg_fix_hours = round(sum(durations) / len(durations), 2)

            return success({
                "total_vulns": total_vulns,
                "pending_fix": pending_fix,
                "fixed_vulns": fixed_vulns,
                "fix_rate": round(fix_rate, 2),
                "active_work_orders": active_work_orders,
                "overdue_work_orders": overdue_work_orders,
                "overdue_rate": round(overdue_rate, 2),
                "today_new_vulns": today_new,
                "avg_fix_duration_hours": avg_fix_hours
            })
    except Exception as e:
        logger.exception(f"Dashboard summary error: {e}")
        return error(f"统计失败: {str(e)}", code=500, status_code=500)


@dashboard_bp.route("/severity-distribution", methods=["GET"])
@login_required
def severity_distribution():
    try:
        with db_manager.get_session() as session:
            results = session.query(
                Vulnerability.severity, func.count(VulnerabilityInstance.id)
            ).join(
                VulnerabilityInstance, Vulnerability.id == VulnerabilityInstance.vuln_id
            ).group_by(Vulnerability.severity).all()

            data = {}
            for sev, count in results:
                data[sev.value] = count

            labels_map = {
                "critical": "严重",
                "high": "高危",
                "medium": "中危",
                "low": "低危"
            }
            chart_data = []
            for key in ["critical", "high", "medium", "low"]:
                chart_data.append({
                    "name": labels_map.get(key, key),
                    "value": data.get(key, 0),
                    "key": key
                })

            return success({
                "raw": data,
                "chart": chart_data
            })
    except Exception as e:
        logger.exception(f"Severity distribution error: {e}")
        return error(f"统计失败: {str(e)}", code=500, status_code=500)


@dashboard_bp.route("/asset-type-distribution", methods=["GET"])
@login_required
def asset_type_distribution():
    try:
        with db_manager.get_session() as session:
            by_asset = session.query(
                Asset.type, func.count(VulnerabilityInstance.id)
            ).join(
                VulnerabilityInstance, Asset.id == VulnerabilityInstance.asset_id
            ).group_by(Asset.type).all()

            asset_data = {}
            for atype, count in by_asset:
                asset_data[atype] = count

            chart_data = [
                {"name": k, "value": v} for k, v in asset_data.items()
            ]

            return success({
                "raw": asset_data,
                "chart": chart_data
            })
    except Exception as e:
        logger.exception(f"Asset type distribution error: {e}")
        return error(f"统计失败: {str(e)}", code=500, status_code=500)


@dashboard_bp.route("/trend", methods=["GET"])
@login_required
def trend_data():
    try:
        with db_manager.get_session() as session:
            days = 30
            now = datetime.now(timezone.utc)
            start_date = now - timedelta(days=days)

            new_vulns = []
            fixed_vulns = []
            dates = []

            for i in range(days):
                day_start = datetime(
                    start_date.year, start_date.month, start_date.day,
                    tzinfo=timezone.utc
                ) + timedelta(days=i)
                day_end = day_start + timedelta(days=1)
                date_str = day_start.strftime("%Y-%m-%d")
                dates.append(date_str)

                nv = session.query(func.count(VulnerabilityInstance.id)).filter(
                    and_(
                        VulnerabilityInstance.discovery_time >= day_start,
                        VulnerabilityInstance.discovery_time < day_end
                    )
                ).scalar() or 0
                new_vulns.append(nv)

                fv = session.query(func.count(WorkOrder.id)).filter(
                    and_(
                        WorkOrder.status == WorkOrderStatusEnum.CLOSED,
                        WorkOrder.closed_at >= day_start,
                        WorkOrder.closed_at < day_end
                    )
                ).scalar() or 0
                fixed_vulns.append(fv)

            return success({
                "dates": dates,
                "new_vulns": new_vulns,
                "fixed_vulns": fixed_vulns
            })
    except Exception as e:
        logger.exception(f"Trend data error: {e}")
        return error(f"统计失败: {str(e)}", code=500, status_code=500)


@dashboard_bp.route("/department-stats", methods=["GET"])
@login_required
def department_stats():
    try:
        with db_manager.get_session() as session:
            results = session.query(
                Asset.department,
                func.count(VulnerabilityInstance.id).label("total"),
                func.sum(case(
                    (VulnerabilityInstance.fix_status == FixStatusEnum.VERIFIED, 1),
                    else_=0
                )).label("fixed")
            ).join(
                VulnerabilityInstance, Asset.id == VulnerabilityInstance.asset_id
            ).group_by(Asset.department).all()

            dept_data = []
            for dept, total, fixed in results:
                fixed_val = fixed or 0
                total_val = total or 0
                rate = (fixed_val / total_val * 100) if total_val > 0 else 0
                dept_data.append({
                    "department": dept,
                    "total": total_val,
                    "fixed": fixed_val,
                    "fix_rate": round(rate, 2)
                })

            dept_data.sort(key=lambda x: x["total"], reverse=True)
            return success(dept_data)
    except Exception as e:
        logger.exception(f"Department stats error: {e}")
        return error(f"统计失败: {str(e)}", code=500, status_code=500)


@dashboard_bp.route("/workorder-stage", methods=["GET"])
@login_required
def workorder_stage():
    try:
        with db_manager.get_session() as session:
            results = session.query(
                WorkOrder.status, func.count(WorkOrder.id)
            ).group_by(WorkOrder.status).all()

            labels_map = {
                "pending": "待处理",
                "fixing": "修复中",
                "fixed": "已修复",
                "verifying": "验证中",
                "closed": "已关闭"
            }

            stage_data = []
            for st, count in results:
                stage_data.append({
                    "key": st.value,
                    "name": labels_map.get(st.value, st.value),
                    "value": count
                })

            return success(stage_data)
    except Exception as e:
        logger.exception(f"Workorder stage error: {e}")
        return error(f"统计失败: {str(e)}", code=500, status_code=500)


app.register_blueprint(dashboard_bp)


report_bp = Blueprint("reports", __name__, url_prefix="/api/reports")


@report_bp.route("/summary", methods=["GET"])
@login_required
def reports_summary():
    try:
        with db_manager.get_session() as session:
            now = datetime.now(timezone.utc)
            today_start = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
            week_ago = today_start - timedelta(days=7)

            total_vulns = session.query(func.count(VulnerabilityInstance.id)).scalar() or 0
            pending_vulns = (
                session.query(func.count(VulnerabilityInstance.id))
                .filter(VulnerabilityInstance.fix_status == FixStatusEnum.PENDING)
                .scalar() or 0
            )
            fixed_vulns = (
                session.query(func.count(VulnerabilityInstance.id))
                .filter(VulnerabilityInstance.fix_status == FixStatusEnum.VERIFIED)
                .scalar() or 0
            )
            fix_rate = round((fixed_vulns / total_vulns * 100), 2) if total_vulns > 0 else 0.0

            total_work_orders = session.query(func.count(WorkOrder.id)).scalar() or 0
            active_work_orders = (
                session.query(func.count(WorkOrder.id))
                .filter(WorkOrder.status.notin_([WorkOrderStatusEnum.CLOSED]))
                .scalar() or 0
            )
            overdue_work_orders = (
                session.query(func.count(WorkOrder.id))
                .filter(WorkOrder.status.notin_([WorkOrderStatusEnum.CLOSED]))
                .filter(WorkOrder.deadline < now)
                .scalar() or 0
            )
            overdue_rate = round((overdue_work_orders / active_work_orders * 100), 2) if active_work_orders > 0 else 0.0

            severity_results = (
                session.query(Vulnerability.severity, func.count(VulnerabilityInstance.id))
                .join(VulnerabilityInstance, VulnerabilityInstance.vuln_id == Vulnerability.id)
                .group_by(Vulnerability.severity)
                .all()
            )
            severity_labels = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}
            severity_distribution = []
            for sev, cnt in severity_results:
                severity_distribution.append({
                    "key": sev,
                    "name": severity_labels.get(sev, sev),
                    "value": cnt
                })

            stage_results = (
                session.query(WorkOrder.status, func.count(WorkOrder.id))
                .group_by(WorkOrder.status)
                .all()
            )
            stage_labels = {
                "pending": "待修复",
                "in_progress": "修复中",
                "fixed": "已修复",
                "verifying": "验证中",
                "closed": "已关闭"
            }
            workorder_stage = []
            for st, cnt in stage_results:
                workorder_stage.append({
                    "key": st.value,
                    "name": stage_labels.get(st.value, st.value),
                    "value": cnt
                })

            asset_type_results = (
                session.query(Asset.type, func.count(VulnerabilityInstance.id))
                .join(VulnerabilityInstance, VulnerabilityInstance.asset_id == Asset.id)
                .group_by(Asset.type)
                .all()
            )
            asset_type_labels = {
                "web_server": "Web服务器",
                "database": "数据库",
                "application": "应用系统",
                "network": "网络设备",
                "file_server": "文件服务器",
                "other": "其他"
            }
            asset_type_distribution = []
            for at, cnt in asset_type_results:
                asset_type_distribution.append({
                    "key": at,
                    "name": asset_type_labels.get(at, at),
                    "value": cnt
                })

            trend_days = []
            for i in range(6, -1, -1):
                day_start = today_start - timedelta(days=i)
                day_end = day_start + timedelta(days=1)
                day_new = (
                    session.query(func.count(VulnerabilityInstance.id))
                    .filter(VulnerabilityInstance.discovery_time >= day_start)
                    .filter(VulnerabilityInstance.discovery_time < day_end)
                    .scalar() or 0
                )
                day_fixed = (
                    session.query(func.count(WorkOrder.id))
                    .filter(WorkOrder.fixed_at >= day_start)
                    .filter(WorkOrder.fixed_at < day_end)
                    .scalar() or 0
                )
                trend_days.append({
                    "date": day_start.strftime("%m-%d"),
                    "new": day_new,
                    "fixed": day_fixed
                })

            dept_results = (
                session.query(Asset.department,
                              func.count(VulnerabilityInstance.id),
                              func.sum(case((VulnerabilityInstance.fix_status == FixStatusEnum.VERIFIED, 1), else_=0)))
                .join(VulnerabilityInstance, VulnerabilityInstance.asset_id == Asset.id)
                .group_by(Asset.department)
                .all()
            )
            department_stats = []
            for dept, total_d, fixed_d in dept_results:
                total_d = total_d or 0
                fixed_d = fixed_d or 0
                department_stats.append({
                    "department": dept or "未分配",
                    "total": total_d,
                    "fixed": fixed_d,
                    "fix_rate": round((fixed_d / total_d * 100), 2) if total_d > 0 else 0.0
                })

            top_high_risk = (
                session.query(VulnerabilityInstance)
                .order_by(VulnerabilityInstance.risk_score.desc())
                .limit(10)
                .all()
            )
            top_high_risk_list = []
            for vi in top_high_risk:
                vuln = session.query(Vulnerability).filter_by(id=vi.vuln_id).first()
                asset = session.query(Asset).filter_by(id=vi.asset_id).first()
                top_high_risk_list.append({
                    "id": vi.id,
                    "title": vuln.title if vuln else f"漏洞#{vi.vuln_id}",
                    "severity": vuln.severity.value if vuln and vuln.severity else None,
                    "risk_score": vi.risk_score,
                    "asset_name": asset.name if asset else f"资产#{vi.asset_id}",
                    "asset_ip": asset.ip if asset else None,
                    "fix_status": vi.fix_status.value,
                    "discovery_time": vi.discovery_time.isoformat() if vi.discovery_time else None
                })

            recent_reports = (
                session.query(Report)
                .order_by(Report.created_at.desc())
                .limit(5)
                .all()
            )
            recent_reports_list = [report_to_dict(r) for r in recent_reports]

        return success({
            "overview": {
                "total_vulns": total_vulns,
                "pending_vulns": pending_vulns,
                "fixed_vulns": fixed_vulns,
                "fix_rate": fix_rate,
                "total_work_orders": total_work_orders,
                "active_work_orders": active_work_orders,
                "overdue_work_orders": overdue_work_orders,
                "overdue_rate": overdue_rate,
                "generated_at": now.isoformat()
            },
            "severity_distribution": severity_distribution,
            "workorder_stage": workorder_stage,
            "asset_type_distribution": asset_type_distribution,
            "trend_days": trend_days,
            "department_stats": department_stats,
            "top_high_risk": top_high_risk_list,
            "recent_reports": recent_reports_list
        })
    except Exception as e:
        logger.exception(f"Reports summary error: {e}")
        return error(f"查询失败: {str(e)}", code=500, status_code=500)


@report_bp.route("/generate", methods=["GET"])
@login_required
def generate_report():
    try:
        user = get_current_user() or "system"
        report_type = request.args.get("type", "daily")

        try:
            report_type_enum = ReportTypeEnum(report_type.lower())
        except ValueError:
            report_type_enum = ReportTypeEnum.DAILY

        with db_manager.get_session() as session:
            now = datetime.now(timezone.utc)
            if report_type_enum == ReportTypeEnum.DAILY:
                period_start = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
                period_end = period_start + timedelta(days=1)
            elif report_type_enum == ReportTypeEnum.WEEKLY:
                period_start = now - timedelta(days=now.weekday())
                period_start = datetime(
                    period_start.year, period_start.month, period_start.day,
                    tzinfo=timezone.utc
                )
                period_end = period_start + timedelta(days=7)
            else:
                period_start = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
                if now.month == 12:
                    period_end = datetime(now.year + 1, 1, 1, tzinfo=timezone.utc)
                else:
                    period_end = datetime(now.year, now.month + 1, 1, tzinfo=timezone.utc)

            stats = stats_engine.calculate_daily_stats(now, session=session)

            report = Report(
                type=report_type_enum,
                period_start=period_start,
                period_end=period_end,
                generated_by=user,
                summary_stats=stats.to_dict() if stats else None
            )
            session.add(report)
            session.flush()

            try:
                pdf_reporter = PdfReporter()
                pdf_path = pdf_reporter.generate_pdf_report(
                    report_type_enum.value, period_start, period_end,
                    stats_data=stats, session=session
                )
                report.file_path_pdf = pdf_path
            except Exception as pdf_err:
                logger.warning(f"PDF generation failed: {pdf_err}")

            log_audit(
                action="report_generate",
                resource_type="report",
                resource_id=str(report.id),
                detail=f"生成{report_type_enum.value}报表",
                user=user,
                ip=request.remote_addr
            )

            return success(report_to_dict(report), "报表生成成功")
    except Exception as e:
        logger.exception(f"Generate report error: {e}")
        return error(f"生成失败: {str(e)}", code=500, status_code=500)


@report_bp.route("", methods=["GET"])
@login_required
def list_reports():
    try:
        page, page_size = get_page_args()
        report_type = request.args.get("type")

        with db_manager.get_session() as session:
            query = session.query(Report)
            if report_type:
                try:
                    query = query.filter(Report.type == ReportTypeEnum(report_type))
                except ValueError:
                    pass

            total = query.count()
            query = query.order_by(Report.created_at.desc())
            offset = (page - 1) * page_size
            reports = query.offset(offset).limit(page_size).all()

            items = [report_to_dict(r) for r in reports]
            return success(paginate_result(items, total, page, page_size))
    except Exception as e:
        logger.exception(f"List reports error: {e}")
        return error(f"查询失败: {str(e)}", code=500, status_code=500)


@report_bp.route("/<int:report_id>/download", methods=["GET"])
@login_required
def download_report(report_id):
    try:
        user = get_current_user()
        with db_manager.get_session() as session:
            report = session.query(Report).filter_by(id=report_id).first()
            if not report:
                return error("报表不存在", code=404, status_code=404)

            file_path = report.file_path_pdf or report.file_path_excel
            if not file_path or not os.path.exists(file_path):
                return error("报表文件不存在", code=404, status_code=404)

            directory = os.path.dirname(file_path)
            filename = os.path.basename(file_path)

            log_audit(
                action="report_download",
                resource_type="report",
                resource_id=str(report_id),
                detail=f"下载报表: {filename}",
                user=user,
                ip=request.remote_addr
            )

            return send_from_directory(directory, filename, as_attachment=True)
    except Exception as e:
        logger.exception(f"Download report error: {e}")
        return error(f"下载失败: {str(e)}", code=500, status_code=500)


app.register_blueprint(report_bp)


response_bp = Blueprint("response_plans", __name__, url_prefix="/api/response-plans")


@response_bp.route("", methods=["GET"])
@login_required
def list_response_plans():
    try:
        page, page_size = get_page_args()
        status = request.args.get("status")
        vuln_type = request.args.get("vuln_type")

        with db_manager.get_session() as session:
            query = session.query(ResponsePlan)
            conditions = []

            if status:
                try:
                    conditions.append(ResponsePlan.status == PlanStatus(status))
                except ValueError:
                    pass
            if vuln_type:
                try:
                    conditions.append(ResponsePlan.vuln_type == VulnType(vuln_type))
                except ValueError:
                    pass

            if conditions:
                query = query.filter(and_(*conditions))

            total = query.count()
            query = query.order_by(ResponsePlan.created_at.desc())
            offset = (page - 1) * page_size
            plans = query.offset(offset).limit(page_size).all()

            items = [response_plan_to_dict(p) for p in plans]
            return success(paginate_result(items, total, page, page_size))
    except Exception as e:
        logger.exception(f"List response plans error: {e}")
        return error(f"查询失败: {str(e)}", code=500, status_code=500)


@response_bp.route("/<int:plan_id>", methods=["GET"])
@login_required
def get_response_plan(plan_id):
    try:
        with db_manager.get_session() as session:
            plan = session.query(ResponsePlan).filter_by(id=plan_id).first()
            if not plan:
                return error("应急预案不存在", code=404, status_code=404)
            return success(response_plan_to_dict(plan))
    except Exception as e:
        logger.exception(f"Get response plan {plan_id} error: {e}")
        return error(f"查询失败: {str(e)}", code=500, status_code=500)


@response_bp.route("", methods=["POST"])
@login_required
def trigger_response_plan():
    try:
        data = request.get_json() or {}
        user = get_current_user() or "system"
        vuln_instance_id = data.get("vuln_instance_id")
        reason = data.get("reason", "手动触发应急响应")

        if not vuln_instance_id:
            return error("缺少 vuln_instance_id 参数", code=400, status_code=400)

        with db_manager.get_session() as session:
            vi = session.query(VulnerabilityInstance).filter_by(id=vuln_instance_id).first()
            if not vi:
                return error("漏洞实例不存在", code=404, status_code=404)

            plan = plan_generator.generate_response_plan(
                vuln_instance_id, reason, "manual_trigger", user, session=session
            )
            if not plan:
                return error("生成应急预案失败", code=500, status_code=500)

            notification_manager.notify_response_team(plan.id, user, session=session)

            log_audit(
                action="response_plan_trigger",
                resource_type="response_plan",
                resource_id=str(plan.id),
                detail=f"手动触发应急响应，漏洞实例: {vuln_instance_id}, 原因: {reason}",
                user=user,
                ip=request.remote_addr
            )

            return success(response_plan_to_dict(plan), "应急预案已触发")
    except Exception as e:
        logger.exception(f"Trigger response plan error: {e}")
        return error(f"触发失败: {str(e)}", code=500, status_code=500)


@response_bp.route("/<int:plan_id>/status", methods=["POST"])
@login_required
def update_plan_status(plan_id):
    try:
        data = request.get_json() or {}
        user = get_current_user() or "system"
        new_status_str = data.get("new_status")
        remark = data.get("remark", "")

        if not new_status_str:
            return error("缺少 new_status 参数", code=400, status_code=400)

        try:
            new_status = PlanStatus(new_status_str)
        except ValueError:
            return error(f"无效的状态值: {new_status_str}", code=400, status_code=400)

        with db_manager.get_session() as session:
            plan = session.query(ResponsePlan).filter_by(id=plan_id).first()
            if not plan:
                return error("应急预案不存在", code=404, status_code=404)

            old_status = plan.status
            plan.status = new_status
            now = datetime.now(timezone.utc)
            plan.updated_at = now

            if new_status == PlanStatus.CONFIRMED and not plan.confirmed_at:
                plan.confirmed_at = now
                plan.confirmed_by = user
            if new_status == PlanStatus.COMPLETED and not plan.completed_at:
                plan.completed_at = now
            if new_status == PlanStatus.CLOSED and not plan.closed_at:
                plan.closed_at = now

            if remark:
                plan.remarks = (plan.remarks or "") + f"\n[{now.isoformat()}] {remark}"

            log_audit(
                action="response_plan_status_update",
                resource_type="response_plan",
                resource_id=str(plan_id),
                detail=f"状态变更: {old_status.value} -> {new_status.value}, 备注: {remark}",
                user=user,
                ip=request.remote_addr
            )

            return success(response_plan_to_dict(plan), "状态更新成功")
    except Exception as e:
        logger.exception(f"Update plan {plan_id} status error: {e}")
        return error(f"更新失败: {str(e)}", code=500, status_code=500)


@response_bp.route("/<int:plan_id>/measures", methods=["POST"])
@login_required
def update_plan_measures(plan_id):
    try:
        data = request.get_json() or {}
        user = get_current_user() or "system"
        measure_type = data.get("measure_type", "isolation")
        new_status_str = data.get("status", "in_progress")
        remark = data.get("remark", "")

        if "measure_id" not in data or data["measure_id"] is None:
            return error("缺少 measure_id 参数", code=400, status_code=400)
        try:
            measure_id = int(data["measure_id"])
        except (ValueError, TypeError):
            return error("measure_id 必须是整数", code=400, status_code=400)

        try:
            new_status = MeasureStatus(new_status_str)
        except ValueError:
            new_status = MeasureStatus.IN_PROGRESS

        with db_manager.get_session() as session:
            plan = session.query(ResponsePlan).filter_by(id=plan_id).first()
            if not plan:
                return error("应急预案不存在", code=404, status_code=404)

            status_field = "isolation_status" if measure_type == "isolation" else "mitigation_status"
            status_str = getattr(plan, status_field)
            measures = []
            if status_str:
                try:
                    measures = json.loads(status_str)
                except Exception:
                    measures = []

            for m in measures:
                if m.get("id") == measure_id:
                    m["status"] = new_status.value
                    m["operator"] = user
                    m["remark"] = remark
                    m["completed_at"] = datetime.now(timezone.utc).isoformat() if new_status == MeasureStatus.COMPLETED else None
                    break

            setattr(plan, status_field, json.dumps(measures, ensure_ascii=False))
            plan.updated_at = datetime.now(timezone.utc)

            log_audit(
                action="response_plan_measures_update",
                resource_type="response_plan",
                resource_id=str(plan_id),
                detail=f"更新措施状态: {measure_type}#{measure_id} -> {new_status.value}",
                user=user,
                ip=request.remote_addr
            )

            return success(response_plan_to_dict(plan), "措施状态更新成功")
    except Exception as e:
        logger.exception(f"Update plan measures error: {e}")
        return error(f"更新失败: {str(e)}", code=500, status_code=500)


@response_bp.route("/<int:plan_id>/notify-team", methods=["POST"])
@login_required
def notify_response_team(plan_id):
    try:
        user = get_current_user() or "system"
        with db_manager.get_session() as session:
            plan = session.query(ResponsePlan).filter_by(id=plan_id).first()
            if not plan:
                return error("应急预案不存在", code=404, status_code=404)

            success_count = notification_manager.notify_response_team(plan_id, user, session=session)

            log_audit(
                action="response_team_notify",
                resource_type="response_plan",
                resource_id=str(plan_id),
                detail="重新通知应急小组",
                user=user,
                ip=request.remote_addr
            )

            return success({"notified": success_count}, "通知已发送")
    except Exception as e:
        logger.exception(f"Notify response team error: {e}")
        return error(f"通知失败: {str(e)}", code=500, status_code=500)


@response_bp.route("/<int:plan_id>/notify-legal", methods=["POST"])
@login_required
def notify_legal(plan_id):
    try:
        data = request.get_json() or {}
        user = get_current_user() or "system"
        reason = data.get("reason", "涉及数据安全或合规风险")

        with db_manager.get_session() as session:
            plan = session.query(ResponsePlan).filter_by(id=plan_id).first()
            if not plan:
                return error("应急预案不存在", code=404, status_code=404)

            success_count = notification_manager.notify_legal_department(
                plan_id, reason, user, session=session
            )

            log_audit(
                action="legal_department_notify",
                resource_type="response_plan",
                resource_id=str(plan_id),
                detail=f"通知法务部门，原因: {reason}",
                user=user,
                ip=request.remote_addr
            )

            return success({"notified": success_count}, "法务部门已通知")
    except Exception as e:
        logger.exception(f"Notify legal error: {e}")
        return error(f"通知失败: {str(e)}", code=500, status_code=500)


app.register_blueprint(response_bp)


review_bp = Blueprint("review_tasks", __name__, url_prefix="/api/review-tasks")


@review_bp.route("", methods=["GET"])
@login_required
def list_review_tasks():
    try:
        page, page_size = get_page_args()
        status = request.args.get("status")
        reason = request.args.get("reason")

        with db_manager.get_session() as session:
            query = session.query(ReviewTask)
            conditions = []

            if status:
                try:
                    conditions.append(ReviewTask.status == ReviewTaskStatusEnum(status))
                except ValueError:
                    pass
            if reason:
                try:
                    conditions.append(ReviewTask.reason == ReviewTaskReasonEnum(reason))
                except ValueError:
                    pass

            if conditions:
                query = query.filter(and_(*conditions))

            total = query.count()
            query = query.order_by(ReviewTask.created_at.desc())
            offset = (page - 1) * page_size
            tasks = query.offset(offset).limit(page_size).all()

            items = [review_task_to_dict(t) for t in tasks]
            return success(paginate_result(items, total, page, page_size))
    except Exception as e:
        logger.exception(f"List review tasks error: {e}")
        return error(f"查询失败: {str(e)}", code=500, status_code=500)


@review_bp.route("/<int:task_id>", methods=["GET"])
@login_required
def get_review_task(task_id):
    try:
        with db_manager.get_session() as session:
            task = session.query(ReviewTask).filter_by(id=task_id).first()
            if not task:
                return error("复盘任务不存在", code=404, status_code=404)
            return success(review_task_to_dict(task))
    except Exception as e:
        logger.exception(f"Get review task {task_id} error: {e}")
        return error(f"查询失败: {str(e)}", code=500, status_code=500)


@review_bp.route("/<int:task_id>", methods=["PUT"])
@login_required
def update_review_task(task_id):
    try:
        data = request.get_json() or {}
        user = get_current_user()

        with db_manager.get_session() as session:
            task = session.query(ReviewTask).filter_by(id=task_id).first()
            if not task:
                return error("复盘任务不存在", code=404, status_code=404)

            if "root_cause" in data:
                task.root_cause = data["root_cause"]
            if "root_cause_category" in data:
                task.root_cause_category = data["root_cause_category"]
            if "improvement_measures" in data:
                task.improvement_measures = data["improvement_measures"]
            if "analysis_result" in data:
                task.analysis_result = data["analysis_result"]
            if "assignees" in data:
                if isinstance(data["assignees"], list):
                    task.assignees = ",".join(data["assignees"])
                else:
                    task.assignees = data["assignees"]
            if "deadline" in data:
                try:
                    task.deadline = datetime.fromisoformat(data["deadline"].replace("Z", "+00:00"))
                except ValueError:
                    pass

            task.updated_at = datetime.now(timezone.utc)

            log_audit(
                action="review_task_update",
                resource_type="review_task",
                resource_id=str(task_id),
                detail="更新复盘任务内容",
                user=user,
                ip=request.remote_addr
            )

            return success(review_task_to_dict(task), "更新成功")
    except Exception as e:
        logger.exception(f"Update review task {task_id} error: {e}")
        return error(f"更新失败: {str(e)}", code=500, status_code=500)


@review_bp.route("/<int:task_id>/status", methods=["POST"])
@login_required
def update_review_task_status(task_id):
    try:
        data = request.get_json() or {}
        user = get_current_user() or "system"
        new_status_str = data.get("new_status")
        analysis = data.get("analysis")

        if not new_status_str:
            return error("缺少 new_status 参数", code=400, status_code=400)

        try:
            new_status = ReviewTaskStatusEnum(new_status_str)
        except ValueError:
            return error(f"无效的状态值: {new_status_str}", code=400, status_code=400)

        task = review_task_manager.update_review_task_status(
            task_id, new_status, analysis, user
        )
        if not task:
            return error("更新状态失败，任务不存在或状态流转无效", code=500, status_code=500)

        return success(review_task_to_dict(task), "状态更新成功")
    except ValueError as e:
        return error(str(e), code=400, status_code=400)
    except Exception as e:
        logger.exception(f"Update review task {task_id} status error: {e}")
        return error(f"更新失败: {str(e)}", code=500, status_code=500)


app.register_blueprint(review_bp)


def run_web_server():
    db_manager.init_db()
    host = config.WEB_HOST
    port = config.WEB_PORT
    logger.info(f"Starting web server on {host}:{port}")
    app.run(host=host, port=port, debug=config.DEBUG, threaded=True)


if __name__ == "__main__":
    run_web_server()
