import yaml
from app.policy.loader import parse_yaml_policy
from app.pipeline.runner import run_pipeline
from app.config import init_settings

init_settings()

with open('policy_xml.yaml', 'r') as f:
    policy_dict = yaml.safe_load(f)
    # The models are Pydantic; loader.py imports models.MaskingPolicy.
    from app.policy.models import MaskingPolicy
    policy = MaskingPolicy(**policy_dict)

with open('data/sample.xml', 'rb') as f:
    raw_bytes = f.read()

res = run_pipeline(raw_bytes=raw_bytes, fmt='xml', policy=policy, role='analyst')

print('OUTPUT:\n', res.output_bytes.decode('utf-8'))
