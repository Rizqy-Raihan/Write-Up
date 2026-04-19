from stix2.v21 import Indicator, Malware, Relationship
from datetime import datetime

indicator = Indicator(
    name="Malicious IP C2",
    description="IP used to communicate with attacker (C2)",
    indicator_types=["malicious-activity"],
    pattern_type="stix",
    pattern="[ipv4-addr:value = '149.154.166.110']",
    valid_from=datetime.utcnow()
)

malware = Malware(
    name="Slashing Trojan",
    description="Trojan malware that uses IP for C2 communication",
    malware_types=["trojan"],
    is_family=False
)

relationship = Relationship(
    relationship_type="indicates",
    source_ref=indicator.id,
    target_ref=malware.id
)

print(indicator.serialize(pretty=True))
print(malware.serialize(pretty=True))
print(relationship.serialize(pretty=True))
