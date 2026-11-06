import os
import sys
import psycopg2
import requests
from psycopg2.extras import RealDictCursor, Json
from psycopg2.pool import SimpleConnectionPool
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from functools import wraps
import logging
from opentelemetry import metrics, trace
from opentelemetry.trace import Status, StatusCode

from telemetry import init_telemetry

# Configura o logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# Carrega .env para desenvolvimento local
load_dotenv()

app = Flask(__name__)
init_telemetry(app, default_service_name="targeting-service")

tracer = trace.get_tracer("togglemaster/targeting-service")
meter = metrics.get_meter("togglemaster/targeting-service")
operation_counter = meter.create_counter(
    "togglemaster.targeting.operations",
    unit="1",
    description="Operações realizadas sobre regras de segmentação",
)
auth_counter = meter.create_counter(
    "togglemaster.targeting.auth_checks",
    unit="1",
    description="Validações de autenticação solicitadas pelo targeting-service",
)

# --- Configuração ---
DATABASE_URL = os.getenv("DATABASE_URL")
AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL")

if not DATABASE_URL or not AUTH_SERVICE_URL:
    log.critical("Erro: DATABASE_URL e AUTH_SERVICE_URL devem ser definidos.")
    sys.exit(1)

# --- Pool de Conexão com o Banco ---
try:
    pool = SimpleConnectionPool(1, 5, dsn=DATABASE_URL)
    log.info("Pool de conexões com o PostgreSQL (targeting) inicializado.")
except psycopg2.OperationalError as e:
    log.critical(f"Erro fatal ao conectar ao PostgreSQL: {e}")
    sys.exit(1)


# --- Middleware de Autenticação (Idêntico ao flag-service) ---
def require_auth(f):
    """Middleware para validar a chave de API contra o auth-service"""

    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            auth_counter.add(1, {"auth.result": "missing_credentials"})
            return jsonify({"error": "Authorization header obrigatório"}), 401

        try:
            validate_url = f"{AUTH_SERVICE_URL}/validate"
            response = requests.get(validate_url, headers={"Authorization": auth_header}, timeout=3)

            if response.status_code != 200:
                auth_counter.add(1, {"auth.result": "invalid"})
                log.warning(f"Falha na validação da chave (status: {response.status_code})")
                return jsonify({"error": "Chave de API inválida"}), 401

            auth_counter.add(1, {"auth.result": "valid"})

        except requests.exceptions.Timeout:
            auth_counter.add(1, {"auth.result": "timeout"})
            log.error("Timeout ao conectar com o auth-service")
            return jsonify(
                {"error": "Serviço de autenticação indisponível (timeout)"}
            ), 504  # Gateway Timeout
        except requests.exceptions.RequestException as e:
            auth_counter.add(1, {"auth.result": "unavailable"})
            log.error(f"Erro ao conectar com o auth-service: {e}")
            return jsonify(
                {"error": "Serviço de autenticação indisponível"}
            ), 503  # Service Unavailable

        return f(*args, **kwargs)

    return decorated


def observe_targeting_operation(operation):
    """Cria spans de negócio sem incluir o JSON das regras ou dados do usuário."""

    def decorator(f):
        @wraps(f)
        def observed(*args, **kwargs):
            with tracer.start_as_current_span(f"targeting_rule.{operation}") as span:
                if "flag_name" in kwargs:
                    span.set_attribute("feature_flag.name", kwargs["flag_name"])
                try:
                    response = f(*args, **kwargs)
                    status_code = (
                        response[1]
                        if isinstance(response, tuple) and len(response) > 1
                        else getattr(response, "status_code", 200)
                    )
                    span.set_attribute("targeting.operation", operation)
                    span.set_attribute("http.response.status_code", status_code)
                    operation_counter.add(
                        1,
                        {
                            "targeting.operation": operation,
                            "http.response.status_code": status_code,
                        },
                    )
                    if status_code >= 500:
                        span.set_status(Status(StatusCode.ERROR, "operation failed"))
                    return response
                except Exception as error:
                    span.record_exception(error)
                    span.set_status(Status(StatusCode.ERROR, "unhandled operation error"))
                    raise

        return observed

    return decorator


# --- Endpoints da API ---


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/rules", methods=["POST"])
@require_auth
@observe_targeting_operation("create")
def create_rule():
    """Cria uma nova regra de segmentação para uma flag"""
    data = request.get_json()
    if not data or "flag_name" not in data or "rules" not in data:
        return jsonify({"error": "'flag_name' e 'rules' (JSON) são obrigatórios"}), 400

    flag_name = data["flag_name"]
    rules_obj = data["rules"]  # O objeto JSON
    is_enabled = data.get("is_enabled", True)

    conn = None
    cur = None
    try:
        conn = pool.getconn()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            "INSERT INTO targeting_rules (flag_name, is_enabled, rules, created_at, updated_at) "
            "VALUES (%s, %s, %s, NOW(), NOW()) RETURNING *",
            (flag_name, is_enabled, Json(rules_obj)),  # Usa Json() para serializar
        )
        new_rule = cur.fetchone()
        conn.commit()
        log.info(f"Regra para '{flag_name}' criada com sucesso.")
        return jsonify(new_rule), 201
    except psycopg2.IntegrityError:
        if conn:
            conn.rollback()
        log.warning(f"Tentativa de criar regra duplicada: '{flag_name}'")
        return jsonify({"error": f"Regra para a flag '{flag_name}' já existe"}), 409
    except Exception as e:
        if conn:
            conn.rollback()
        log.error(f"Erro ao criar regra: {e}")
        return jsonify({"error": "Erro interno do servidor", "details": str(e)}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            pool.putconn(conn)


@app.route("/rules/<string:flag_name>", methods=["GET"])
@require_auth
@observe_targeting_operation("get")
def get_rule(flag_name):
    """Busca uma regra de segmentação pelo nome da flag"""
    conn = None
    cur = None
    try:
        conn = pool.getconn()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM targeting_rules WHERE flag_name = %s", (flag_name,))
        rule = cur.fetchone()
        if not rule:
            return jsonify({"error": "Regra não encontrada"}), 404
        return jsonify(rule)
    except Exception as e:
        log.error(f"Erro ao buscar regra '{flag_name}': {e}")
        return jsonify({"error": "Erro interno do servidor", "details": str(e)}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            pool.putconn(conn)


@app.route("/rules/<string:flag_name>", methods=["PUT"])
@require_auth
@observe_targeting_operation("update")
def update_rule(flag_name):
    """Atualiza a regra de segmentação de uma flag"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Corpo da requisição obrigatório"}), 400

    fields = []
    values = []

    if "rules" in data:
        fields.append("rules = %s")
        values.append(Json(data["rules"]))  # Serializa o JSON
    if "is_enabled" in data:
        fields.append("is_enabled = %s")
        values.append(data["is_enabled"])

    if not fields:
        return jsonify({"error": "Pelo menos um campo ('rules', 'is_enabled') é obrigatório"}), 400

    values.append(flag_name)  # Adiciona o 'flag_name' para a cláusula WHERE

    query = f"UPDATE targeting_rules SET {', '.join(fields)} WHERE flag_name = %s RETURNING *"

    conn = None
    cur = None
    try:
        conn = pool.getconn()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(query, tuple(values))

        if cur.rowcount == 0:
            return jsonify({"error": "Regra não encontrada"}), 404

        updated_rule = cur.fetchone()
        conn.commit()
        log.info(f"Regra para '{flag_name}' atualizada com sucesso.")
        return jsonify(updated_rule), 200
    except Exception as e:
        if conn:
            conn.rollback()
        log.error(f"Erro ao atualizar regra '{flag_name}': {e}")
        return jsonify({"error": "Erro interno do servidor", "details": str(e)}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            pool.putconn(conn)


@app.route("/rules/<string:flag_name>", methods=["DELETE"])
@require_auth
@observe_targeting_operation("delete")
def delete_rule(flag_name):
    """Deleta a regra de segmentação de uma flag"""
    conn = None
    cur = None
    try:
        conn = pool.getconn()
        cur = conn.cursor()
        cur.execute("DELETE FROM targeting_rules WHERE flag_name = %s", (flag_name,))

        if cur.rowcount == 0:
            return jsonify({"error": "Regra não encontrada"}), 404

        conn.commit()
        log.info(f"Regra para '{flag_name}' deletada com sucesso.")
        return "", 204  # 204 No Content
    except Exception as e:
        if conn:
            conn.rollback()
        log.error(f"Erro ao deletar regra '{flag_name}': {e}")
        return jsonify({"error": "Erro interno do servidor", "details": str(e)}), 500
    finally:
        if cur:
            cur.close()
        if conn:
            pool.putconn(conn)


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8003))
    app.run(host="0.0.0.0", port=port, debug=False)
