from app.Agents.SQL_INJECTION.main import run_sql_injection_agent
from app.models.sql_inject_model import SQLInjectionReport

def get_sql_injection_report(target_url: str) -> dict:
	report: SQLInjectionReport = run_sql_injection_agent(target_url)
	return report.dict()
