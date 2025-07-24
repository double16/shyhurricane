import os


def configure():
    os.environ['PYTORCH_ENABLE_MPS_FALLBACK'] = '1'
    os.environ['ANONYMIZED_TELEMETRY'] = "False"
    os.environ['HAYSTACK_TELEMETRY_ENABLED'] = "False"
    os.environ['HAYSTACK_TELEMETRY_DISABLED'] = "1"
