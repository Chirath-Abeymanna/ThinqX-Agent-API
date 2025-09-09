#!/usr/bin/env python3
"""
SQL Injection Assessment Agent using LangGraph
A comprehensive AI agent for detecting SQL injection vulnerabilities
"""

import asyncio
import json
import re
import time
import urllib.parse
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import logging

import aiohttp
import requests
from bs4 import BeautifulSoup
from langchain_core.messages import HumanMessage, AIMessage
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from pydantic import BaseModel, Field
import colorama
from colorama import Fore, Style

# Initialize colorama for colored output
colorama.init()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class InjectionType(Enum):
    """Types of SQL injection techniques"""
    BOOLEAN_BASED = "boolean_based"
    TIME_BASED = "time_based"
    ERROR_BASED = "error_based"
    UNION_BASED = "union_based"
    STACKED_QUERIES = "stacked_queries"
    OUT_OF_BAND = "out_of_band"

class PayloadCategory(Enum):
    """Categories of SQL injection payloads"""
    AUTHENTICATION_BYPASS = "auth_bypass"
    DATA_EXTRACTION = "data_extraction"
    DATABASE_ENUMERATION = "db_enumeration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    FILE_OPERATIONS = "file_operations"

@dataclass
class InjectionResult:
    """Result of a SQL injection test"""
    payload: str
    injection_type: InjectionType
    success: bool
    response_time: float
    response_size: int
    error_message: Optional[str] = None
    extracted_data: Optional[str] = None
    confidence: float = 0.0

@dataclass
class TargetInfo:
    """Information about the target"""
    url: str
    method: str
    parameters: Dict[str, str]
    headers: Dict[str, str]
    cookies: Dict[str, str]

class AgentState(BaseModel):
    """State for the LangGraph agent"""
    target_url: str = Field(description="Target URL to test")
    target_info: Optional[TargetInfo] = Field(default=None, description="Target information")
    discovered_parameters: List[str] = Field(default_factory=list, description="Discovered parameters")
    injection_results: List[InjectionResult] = Field(default_factory=list, description="Injection test results")
    vulnerable_parameters: List[str] = Field(default_factory=list, description="Vulnerable parameters found")
    current_phase: str = Field(default="reconnaissance", description="Current assessment phase")
    messages: List[Any] = Field(default_factory=list, description="Agent messages")
    confidence_score: float = Field(default=0.0, description="Overall confidence score")
    recommendations: List[str] = Field(default_factory=list, description="Security recommendations")
    
    class Config:
        arbitrary_types_allowed = True
