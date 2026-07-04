from siglum.sealing.dsse import statement_bytes, dsse_pae, DsseEnvelope, DSSE_PAYLOAD_TYPE
from siglum.canonical import canonical_json
from siglum.predicate import build_predicate
from siglum.derive import assess
from tests.test_derive import _b, _v
from siglum.verdict import ValidatorStatus


def test_statement_bytes_equals_canonical_predicate():
    a = assess(_b([_v(ValidatorStatus.PASSED)]))
    assert statement_bytes(a) == canonical_json(build_predicate(a))


def test_dsse_pae_matches_spec_vector():
    # "application/vnd.in-toto+json" is 28 bytes; PAE = DSSEv1 <len(type)> <type> <len(body)> <body>
    assert dsse_pae("application/vnd.in-toto+json", b"x") == b"DSSEv1 28 application/vnd.in-toto+json 1 x"


def test_envelope_roundtrips():
    e = DsseEnvelope(payload_type=DSSE_PAYLOAD_TYPE, payload_b64="eA==",
                     signatures=({"sig": "AAAA"},))
    assert DsseEnvelope.from_dict(e.to_dict()) == e
