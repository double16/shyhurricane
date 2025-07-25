from typing import Optional

from shyhurricane.generator_config import GeneratorConfig

_generator_config: Optional[GeneratorConfig] = GeneratorConfig.from_env()


def set_generator_config(config: GeneratorConfig):
    global _generator_config
    _generator_config = config


def get_generator_config() -> GeneratorConfig:
    global _generator_config
    return _generator_config
