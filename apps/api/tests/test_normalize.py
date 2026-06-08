from trustgraph_security.schema import (
    ThreatModel, IngestService, IngestThreat, IngestEndpoint,
)
from trustgraph_security.normalize import threat_model_to_triples


def test_threat_model_emits_typed_nodes_and_edges():
    tm = ThreatModel(
        system="acme",
        services=[
            IngestService(id="svc-a", name="a", criticality="high",
                          exposure="internet",
                          endpoints=[
                              IngestEndpoint(id="ep-1", path="/x",
                                             method="GET", exposure="internet"),
                          ]),
        ],
        threats=[
            IngestThreat(id="thr-1", title="t", target_service="svc-a",
                         stride="Spoofing", risk="high"),
        ],
    )
    triples = threat_model_to_triples(tm)
    iris = {(t["s"]["v"], t["p"]["v"], t["o"]["v"]) for t in triples}

    # System -> contains -> Service edge present
    assert any("contains" in p for _, p, _ in iris)
    # Threat -> targets -> Service edge present
    assert any("targets" in p for _, p, _ in iris)
    # Service typed
    assert any(o.endswith("#Service") for _, _, o in iris)
    # Endpoint typed
    assert any(o.endswith("#Endpoint") for _, _, o in iris)
