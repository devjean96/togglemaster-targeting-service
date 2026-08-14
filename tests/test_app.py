import psycopg2
import requests


def test_health_check(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_requires_authorization_header(client):
    response = client.get("/rules/checkout")

    assert response.status_code == 401
    assert response.get_json() == {"error": "Authorization header obrigatório"}


def test_rejects_invalid_api_key(client, app_module, auth_headers):
    app_module.requests.get.return_value.status_code = 401

    response = client.get("/rules/checkout", headers=auth_headers)

    assert response.status_code == 401
    assert response.get_json() == {"error": "Chave de API inválida"}
    app_module.requests.get.assert_called_once_with(
        "http://auth-service/validate",
        headers={"Authorization": "Bearer valid-key"},
        timeout=3,
    )


def test_returns_gateway_timeout_when_auth_service_times_out(client, app_module, auth_headers):
    app_module.requests.get.side_effect = requests.exceptions.Timeout

    response = client.get("/rules/checkout", headers=auth_headers)

    assert response.status_code == 504
    assert response.get_json() == {"error": "Serviço de autenticação indisponível (timeout)"}


def test_returns_service_unavailable_when_auth_service_fails(client, app_module, auth_headers):
    app_module.requests.get.side_effect = requests.exceptions.ConnectionError("offline")

    response = client.get("/rules/checkout", headers=auth_headers)

    assert response.status_code == 503
    assert response.get_json() == {"error": "Serviço de autenticação indisponível"}


def test_create_rule_requires_flag_name_and_rules(client, auth_headers):
    response = client.post("/rules", json={"flag_name": "checkout"}, headers=auth_headers)

    assert response.status_code == 400
    assert response.get_json() == {"error": "'flag_name' e 'rules' (JSON) são obrigatórios"}


def test_create_rule(client, database, pool, auth_headers):
    connection, cursor = database
    rules = {"type": "PERCENTAGE", "value": 50}
    created = {"flag_name": "checkout", "rules": rules, "is_enabled": True}
    cursor.fetchone.return_value = created

    response = client.post(
        "/rules", json={"flag_name": "checkout", "rules": rules}, headers=auth_headers
    )

    assert response.status_code == 201
    assert response.get_json() == created
    values = cursor.execute.call_args.args[1]
    assert values[:2] == ("checkout", True)
    assert values[2].adapted == rules
    connection.commit.assert_called_once_with()
    cursor.close.assert_called_once_with()
    pool.putconn.assert_called_once_with(connection)


def test_create_duplicate_rule_rolls_back(client, database, auth_headers):
    connection, cursor = database
    cursor.execute.side_effect = psycopg2.IntegrityError

    response = client.post(
        "/rules", json={"flag_name": "checkout", "rules": {}}, headers=auth_headers
    )

    assert response.status_code == 409
    assert response.get_json() == {"error": "Regra para a flag 'checkout' já existe"}
    connection.rollback.assert_called_once_with()


def test_create_rule_returns_internal_error(client, database, auth_headers):
    connection, cursor = database
    cursor.execute.side_effect = RuntimeError("write failed")

    response = client.post(
        "/rules", json={"flag_name": "checkout", "rules": {}}, headers=auth_headers
    )

    assert response.status_code == 500
    assert response.get_json()["details"] == "write failed"
    connection.rollback.assert_called_once_with()


def test_get_rule(client, database, auth_headers):
    _, cursor = database
    cursor.fetchone.return_value = {"flag_name": "checkout", "rules": {}}

    response = client.get("/rules/checkout", headers=auth_headers)

    assert response.status_code == 200
    assert response.get_json()["flag_name"] == "checkout"
    cursor.execute.assert_called_once_with(
        "SELECT * FROM targeting_rules WHERE flag_name = %s", ("checkout",)
    )


def test_get_missing_rule(client, database, auth_headers):
    _, cursor = database
    cursor.fetchone.return_value = None

    response = client.get("/rules/unknown", headers=auth_headers)

    assert response.status_code == 404
    assert response.get_json() == {"error": "Regra não encontrada"}


def test_get_rule_returns_internal_error(client, database, auth_headers):
    _, cursor = database
    cursor.execute.side_effect = RuntimeError("read failed")

    response = client.get("/rules/checkout", headers=auth_headers)

    assert response.status_code == 500
    assert response.get_json()["details"] == "read failed"


def test_update_rule_requires_body(client, auth_headers):
    response = client.put("/rules/checkout", json={}, headers=auth_headers)

    assert response.status_code == 400
    assert response.get_json() == {"error": "Corpo da requisição obrigatório"}


def test_update_rule_requires_supported_field(client, auth_headers):
    response = client.put("/rules/checkout", json={"flag_name": "other"}, headers=auth_headers)

    assert response.status_code == 400
    assert "Pelo menos um campo" in response.get_json()["error"]


def test_update_rule(client, database, auth_headers):
    connection, cursor = database
    rules = {"type": "PERCENTAGE", "value": 75}
    cursor.rowcount = 1
    cursor.fetchone.return_value = {
        "flag_name": "checkout",
        "rules": rules,
        "is_enabled": False,
    }

    response = client.put(
        "/rules/checkout",
        json={"rules": rules, "is_enabled": False},
        headers=auth_headers,
    )

    assert response.status_code == 200
    query, values = cursor.execute.call_args.args
    assert query == (
        "UPDATE targeting_rules SET rules = %s, is_enabled = %s WHERE flag_name = %s RETURNING *"
    )
    assert values[0].adapted == rules
    assert values[1:] == (False, "checkout")
    connection.commit.assert_called_once_with()


def test_update_missing_rule(client, database, auth_headers):
    connection, cursor = database
    cursor.rowcount = 0

    response = client.put("/rules/unknown", json={"is_enabled": True}, headers=auth_headers)

    assert response.status_code == 404
    assert response.get_json() == {"error": "Regra não encontrada"}
    connection.commit.assert_not_called()


def test_update_rule_returns_internal_error(client, database, auth_headers):
    connection, cursor = database
    cursor.execute.side_effect = RuntimeError("update failed")

    response = client.put("/rules/checkout", json={"is_enabled": True}, headers=auth_headers)

    assert response.status_code == 500
    assert response.get_json()["details"] == "update failed"
    connection.rollback.assert_called_once_with()


def test_delete_rule(client, database, auth_headers):
    connection, cursor = database
    cursor.rowcount = 1

    response = client.delete("/rules/checkout", headers=auth_headers)

    assert response.status_code == 204
    cursor.execute.assert_called_once_with(
        "DELETE FROM targeting_rules WHERE flag_name = %s", ("checkout",)
    )
    connection.commit.assert_called_once_with()


def test_delete_missing_rule(client, database, auth_headers):
    connection, cursor = database
    cursor.rowcount = 0

    response = client.delete("/rules/unknown", headers=auth_headers)

    assert response.status_code == 404
    assert response.get_json() == {"error": "Regra não encontrada"}
    connection.commit.assert_not_called()


def test_delete_rule_error_rolls_back_and_releases_connection(client, database, pool, auth_headers):
    connection, cursor = database
    cursor.execute.side_effect = RuntimeError("delete failed")

    response = client.delete("/rules/checkout", headers=auth_headers)

    assert response.status_code == 500
    assert response.get_json()["details"] == "delete failed"
    connection.rollback.assert_called_once_with()
    cursor.close.assert_called_once_with()
    pool.putconn.assert_called_once_with(connection)
