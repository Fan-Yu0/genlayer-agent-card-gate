import json


AGENT_ID = "triage-agent"
CARD_URL = "https://agents.example.com/triage/agent-card.json"
POLICY_URL = "https://registry.example.com/policy"

STREAMING = 1
PUSH_NOTIFICATIONS = 2
STATE_TRANSITION_HISTORY = 4
AUTHENTICATION = 8
ALL = 15


def _mock_evidence(vm, payload):
    vm.mock_web(
        r".*agents\.example\.com/triage/agent-card\.json.*",
        {"status": 200, "body": '{"name":"triage-agent","endpoint":"https://agents.example.com/a2a"}'},
    )
    vm.mock_web(
        r".*registry\.example\.com/policy.*",
        {"status": 200, "body": "Agents must use HTTPS and declare authentication."},
    )
    vm.mock_llm(r".*AGENT CARD CONFORMANCE SCREEN.*", json.dumps(payload))


def _evidence(
    capabilities=None,
    auth_scheme="oauth2",
    secure=True,
    consistency="consistent",
    summary="Evidence matches.",
):
    return {
        "capabilities": capabilities
        if capabilities is not None
        else {
            "streaming": True,
            "push_notifications": False,
            "state_transition_history": True,
            "authentication": True,
        },
        "auth_scheme": auth_scheme,
        "transport_secure": secure,
        "source_consistency": consistency,
        "summary": summary,
    }


def _register(contract, vm, publisher, mask=5, require_auth=True):
    vm.sender = publisher
    contract.register_agent(AGENT_ID, CARD_URL, POLICY_URL, mask, require_auth)


def test_complete_card_is_approved(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/agent_card_gate.py")
    _register(contract, direct_vm, direct_alice, mask=5)
    _mock_evidence(direct_vm, _evidence())

    contract.assess(AGENT_ID)

    result = contract.get_assessment(AGENT_ID)
    assert result["state"] == 1
    assert result["decision"] == 1
    assert result["capability_mask"] == 13
    assert result["missing_capabilities"] == 0
    assert result["auth_scheme"] == "oauth2"
    assert result["transport_secure"] is True
    assert result["round"] == 1
    assert contract.is_conformant(AGENT_ID) is True


def test_missing_capability_is_conditional(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/agent_card_gate.py")
    _register(contract, direct_vm, direct_alice, mask=15)
    _mock_evidence(direct_vm, _evidence())

    contract.assess(AGENT_ID)

    result = contract.get_assessment(AGENT_ID)
    assert result["decision"] == 2
    assert result["missing_capabilities"] == PUSH_NOTIFICATIONS
    assert contract.is_conformant(AGENT_ID) is False


def test_insecure_transport_is_blocked(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/agent_card_gate.py")
    _register(contract, direct_vm, direct_alice)
    _mock_evidence(direct_vm, _evidence(secure=False))

    contract.assess(AGENT_ID)

    result = contract.get_assessment(AGENT_ID)
    assert result["decision"] == 3
    assert result["transport_secure"] is False


def test_missing_auth_is_blocked(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/agent_card_gate.py")
    _register(contract, direct_vm, direct_alice, mask=1, require_auth=True)
    _mock_evidence(
        direct_vm,
        _evidence(
            capabilities={
                "streaming": True,
                "push_notifications": False,
                "state_transition_history": False,
                "authentication": False,
            },
            auth_scheme="none",
        ),
    )

    contract.assess(AGENT_ID)

    assert contract.get_assessment(AGENT_ID)["decision"] == 3


def test_auth_not_required_allows_anonymous_card(
    direct_vm, direct_deploy, direct_alice
):
    contract = direct_deploy("contracts/agent_card_gate.py")
    _register(contract, direct_vm, direct_alice, mask=1, require_auth=False)
    _mock_evidence(
        direct_vm,
        _evidence(
            capabilities={
                "streaming": True,
                "push_notifications": False,
                "state_transition_history": False,
                "authentication": False,
            },
            auth_scheme="none",
        ),
    )

    contract.assess(AGENT_ID)

    assert contract.get_assessment(AGENT_ID)["decision"] == 1


def test_conflicting_sources_require_review(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/agent_card_gate.py")
    _register(contract, direct_vm, direct_alice)
    _mock_evidence(direct_vm, _evidence(consistency="conflicting"))

    contract.assess(AGENT_ID)

    assert contract.get_assessment(AGENT_ID)["decision"] == 4


def test_insufficient_sources_require_review(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/agent_card_gate.py")
    _register(contract, direct_vm, direct_alice)
    _mock_evidence(direct_vm, _evidence(consistency="insufficient"))

    contract.assess(AGENT_ID)

    assert contract.get_assessment(AGENT_ID)["decision"] == 4


def test_duplicate_registration_is_rejected(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/agent_card_gate.py")
    _register(contract, direct_vm, direct_alice)

    with direct_vm.expect_revert("already registered"):
        contract.register_agent(AGENT_ID, CARD_URL, POLICY_URL, 1, True)


def test_requires_https_urls(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/agent_card_gate.py")
    direct_vm.sender = direct_alice

    with direct_vm.expect_revert("agent_card_url must be an https URL"):
        contract.register_agent(
            AGENT_ID, "http://agents.example.com/card", POLICY_URL, 1, True
        )


def test_evidence_urls_must_differ(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/agent_card_gate.py")
    direct_vm.sender = direct_alice

    with direct_vm.expect_revert("evidence URLs must differ"):
        contract.register_agent(AGENT_ID, CARD_URL, CARD_URL, 1, True)


def test_required_capabilities_must_be_valid(direct_vm, direct_deploy, direct_alice):
    contract = direct_deploy("contracts/agent_card_gate.py")
    direct_vm.sender = direct_alice

    with direct_vm.expect_revert("required_capabilities"):
        contract.register_agent(AGENT_ID, CARD_URL, POLICY_URL, 0, True)


def test_only_publisher_can_withdraw(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    contract = direct_deploy("contracts/agent_card_gate.py")
    _register(contract, direct_vm, direct_alice)

    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("only the publisher can withdraw"):
        contract.withdraw(AGENT_ID)

    direct_vm.sender = direct_alice
    contract.withdraw(AGENT_ID)
    assert contract.get_assessment(AGENT_ID)["state"] == 2
    assert contract.is_conformant(AGENT_ID) is False


def test_unknown_agent_is_not_conformant(direct_deploy):
    contract = direct_deploy("contracts/agent_card_gate.py")

    assert contract.is_conformant("unknown") is False
    assert contract.get_assessment("unknown") == {}


def test_validator_accepts_matching_evidence(
    direct_vm, direct_deploy, direct_alice
):
    contract = direct_deploy("contracts/agent_card_gate.py")
    _register(contract, direct_vm, direct_alice)
    _mock_evidence(direct_vm, _evidence())

    contract.assess(AGENT_ID)

    assert direct_vm.run_validator() is True


def test_validator_rejects_changed_capabilities(
    direct_vm, direct_deploy, direct_alice
):
    contract = direct_deploy("contracts/agent_card_gate.py")
    _register(contract, direct_vm, direct_alice)
    _mock_evidence(direct_vm, _evidence())
    contract.assess(AGENT_ID)

    direct_vm.clear_mocks()
    _mock_evidence(
        direct_vm,
        _evidence(
            capabilities={
                "streaming": True,
                "push_notifications": True,
                "state_transition_history": True,
                "authentication": True,
            }
        ),
    )

    assert direct_vm.run_validator() is False


def test_validator_rejects_changed_auth_scheme(
    direct_vm, direct_deploy, direct_alice
):
    contract = direct_deploy("contracts/agent_card_gate.py")
    _register(contract, direct_vm, direct_alice)
    _mock_evidence(direct_vm, _evidence(auth_scheme="oauth2"))
    contract.assess(AGENT_ID)

    direct_vm.clear_mocks()
    _mock_evidence(direct_vm, _evidence(auth_scheme="api_key"))

    assert direct_vm.run_validator() is False


def test_validator_rejects_changed_transport_security(
    direct_vm, direct_deploy, direct_alice
):
    contract = direct_deploy("contracts/agent_card_gate.py")
    _register(contract, direct_vm, direct_alice)
    _mock_evidence(direct_vm, _evidence(secure=True))
    contract.assess(AGENT_ID)

    direct_vm.clear_mocks()
    _mock_evidence(direct_vm, _evidence(secure=False))

    assert direct_vm.run_validator() is False


def test_validator_ignores_summary_wording(
    direct_vm, direct_deploy, direct_alice
):
    contract = direct_deploy("contracts/agent_card_gate.py")
    _register(contract, direct_vm, direct_alice)
    _mock_evidence(direct_vm, _evidence(summary="Leader wording."))
    contract.assess(AGENT_ID)

    direct_vm.clear_mocks()
    _mock_evidence(direct_vm, _evidence(summary="Different validator wording."))

    assert direct_vm.run_validator() is True


def test_capability_bits_expose_policy(direct_deploy):
    contract = direct_deploy("contracts/agent_card_gate.py")

    bits = contract.capability_bits()
    assert bits["streaming"] == 1
    assert bits["push_notifications"] == 2
    assert bits["state_transition_history"] == 4
    assert bits["authentication"] == 8
    assert bits["all"] == 15
    assert bits["approved"] == 1
    assert bits["review_required"] == 4
    assert bits["policy_version"] == "a2a-agent-card-v1"
