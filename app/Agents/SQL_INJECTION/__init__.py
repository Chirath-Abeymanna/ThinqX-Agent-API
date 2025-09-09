"""
SQL Injection Assessment Agent Package
A comprehensive AI agent for detecting SQL injection vulnerabilities using LangGraph
"""

__version__ = "1.0.0"
__author__ = "AI Security Agent"
__description__ = "SQL Injection Assessment Agent using LangGraph"

from .sqli import (
    InjectionType,
    PayloadCategory,
    InjectionResult,
    TargetInfo,
    AgentState
)

from .payloads import SQLInjectionPayloads
from .injection_engine import SQLInjectionEngine
from .agent import SQLInjectionAgent

__all__ = [
    'InjectionType',
    'PayloadCategory', 
    'InjectionResult',
    'TargetInfo',
    'AgentState',
    'SQLInjectionPayloads',
    'SQLInjectionEngine',
    'SQLInjectionAgent'
] 