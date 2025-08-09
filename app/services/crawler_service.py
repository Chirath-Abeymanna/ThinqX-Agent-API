"""
FastAPI-compatible web crawler service wrapper
"""
import threading
import time
import uuid
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

from app.Agents.web_crawler_agent import IntelligentWebCrawler
from app.models.crawl_model import CrawlResponse, CrawlSummary, DiscoveryStatistics, SecurityAnalysis, CategoryFindings, CrawlResultItem, DetailedResult


class CrawlTask:
    """Represents a crawling task with status tracking"""
    
    def __init__(self, task_id: str, domain: str, max_threads: int, max_depth: int):
        self.task_id = task_id
        self.domain = domain
        self.max_threads = max_threads
        self.max_depth = max_depth
        self.status = "pending"  # pending, running, completed, failed
        self.progress = "Initializing..."
        self.start_time = None
        self.end_time = None
        self.result = None
        self.error = None
        self.crawler = None
        self.thread = None


class WebCrawlerService:
    """Service class to manage web crawling tasks"""
    
    def __init__(self):
        self.active_tasks: Dict[str, CrawlTask] = {}
        self.completed_tasks: Dict[str, CrawlTask] = {}
        self.executor = ThreadPoolExecutor(max_workers=5)  # Limit concurrent crawls
    
    def generate_task_id(self) -> str:
        """Generate a unique task ID"""
        return str(uuid.uuid4())
    
    def create_crawl_task(self, domain: str, max_threads: int = 10, max_depth: int = 3) -> str:
        """Create a new crawl task"""
        task_id = self.generate_task_id()
        task = CrawlTask(task_id, domain, max_threads, max_depth)
        self.active_tasks[task_id] = task
        return task_id
    
    def get_task_status(self, task_id: str) -> Optional[CrawlTask]:
        """Get the status of a crawl task"""
        if task_id in self.active_tasks:
            return self.active_tasks[task_id]
        elif task_id in self.completed_tasks:
            return self.completed_tasks[task_id]
        return None
    
    def _run_crawler(self, task: CrawlTask):
        """Run the crawler in a separate thread"""
        try:
            task.status = "running"
            task.start_time = datetime.now()
            task.progress = "Starting crawler..."
            
            # Create crawler instance
            task.crawler = IntelligentWebCrawler(
                target_domain=task.domain,
                max_threads=task.max_threads,
                max_depth=task.max_depth
            )
            
            # Override print_status to track progress
            original_print_status = task.crawler.print_status
            
            def track_progress(message: str, level: str = "info"):
                task.progress = message
                original_print_status(message, level)
            
            task.crawler.print_status = track_progress
            
            # Start crawling
            task.progress = "Crawling in progress..."
            task.crawler.start_crawling()
            
            # Generate report
            task.progress = "Generating report..."
            report_data = task.crawler.generate_report()
            
            # Save report to file (like CLI version)
            task.progress = "Saving report file..."
            report_file = task.crawler.save_report()
            
            # Convert to response format
            task.result = self._convert_to_response_format(report_data, task.domain, report_file)
            
            task.status = "completed"
            task.end_time = datetime.now()
            task.progress = "Completed successfully"
            
        except Exception as e:
            task.status = "failed"
            task.end_time = datetime.now()
            task.error = str(e)
            task.progress = f"Failed: {str(e)}"
        
        finally:
            # Move to completed tasks
            if task.task_id in self.active_tasks:
                self.completed_tasks[task.task_id] = self.active_tasks.pop(task.task_id)
    
    def start_crawl_async(self, domain: str, max_threads: int = 10, max_depth: int = 3) -> str:
        """Start a crawl asynchronously and return task ID"""
        task_id = self.create_crawl_task(domain, max_threads, max_depth)
        task = self.active_tasks[task_id]
        
        # Start the crawl in a separate thread
        task.thread = threading.Thread(target=self._run_crawler, args=(task,))
        task.thread.daemon = True
        task.thread.start()
        
        return task_id
    
    def wait_for_completion(self, task_id: str) -> Optional[CrawlResponse]:
        """Wait for a task to complete without timeout - let it run as long as needed"""
        while True:
            task = self.get_task_status(task_id)
            
            if not task:
                return None
            
            if task.status == "completed":
                return task.result
            elif task.status == "failed":
                raise Exception(task.error or "Crawl failed")
            
            time.sleep(2)  # Check every 2 seconds
    
    def _convert_to_response_format(self, report_data: Dict[str, Any], domain: str, report_file: str = None) -> CrawlResponse:
        """Convert crawler report to FastAPI response format"""
        try:
            # Convert crawl summary
            crawl_summary = None
            if 'crawl_summary' in report_data:
                cs = report_data['crawl_summary']
                crawl_summary = CrawlSummary(
                    target_domain=cs.get('target_domain', domain),
                    crawl_duration=cs.get('crawl_duration', 0),
                    urls_discovered=cs.get('urls_discovered', 0),
                    urls_successfully_crawled=cs.get('urls_successfully_crawled', 0),
                    errors_encountered=cs.get('errors_encountered', 0),
                    start_time=cs.get('start_time'),
                    end_time=cs.get('end_time')
                )
            
            # Convert discovery statistics
            discovery_stats = None
            if 'discovery_statistics' in report_data:
                ds = report_data['discovery_statistics']
                discovery_stats = DiscoveryStatistics(
                    total_files_found=ds.get('total_files_found', 0),
                    total_forms_found=ds.get('total_forms_found', 0),
                    sensitive_files_found=ds.get('sensitive_files_found', 0),
                    hidden_files_discovered=ds.get('hidden_files_discovered', 0)
                )
            
            # Convert security analysis
            security_analysis = None
            if 'security_analysis' in report_data:
                sa = report_data['security_analysis']
                security_analysis = SecurityAnalysis(
                    security_headers_coverage=sa.get('security_headers_coverage', {}),
                    forms_discovered=sa.get('forms_discovered', 0),
                    cookies_found=sa.get('cookies_found', 0)
                )
            
            # Convert categorized findings
            categorized_findings = {}
            if 'categorized_findings' in report_data:
                for category, data in report_data['categorized_findings'].items():
                    urls = []
                    for url_data in data.get('urls', []):
                        urls.append(CrawlResultItem(
                            url=url_data.get('url', ''),
                            status_code=url_data.get('status_code', 0),
                            content_type=url_data.get('content_type', ''),
                            content_length=url_data.get('content_length', 0),
                            response_time=url_data.get('response_time', 0),
                            title=url_data.get('title', ''),
                            forms_count=url_data.get('forms_count', 0),
                            technologies=url_data.get('technologies', []),
                            file_category=category,
                            sensitivity_level=url_data.get('sensitivity_level', 'low')
                        ))
                    
                    categorized_findings[category] = CategoryFindings(
                        count=data.get('count', 0),
                        sensitivity_breakdown=data.get('sensitivity_breakdown', {}),
                        urls=urls
                    )
            
            # Convert detailed results
            detailed_results = []
            if 'detailed_results' in report_data:
                for result in report_data['detailed_results']:
                    # Ensure redirect_chain contains only strings
                    redirect_chain = result.get('redirect_chain', [])
                    if redirect_chain:
                        redirect_chain = [str(url) for url in redirect_chain]
                    
                    detailed_results.append(DetailedResult(
                        url=result.get('url', ''),
                        category=result.get('category', ''),
                        sensitivity_level=result.get('sensitivity_level', 'low'),
                        status_code=result.get('status_code', 0),
                        content_type=result.get('content_type', ''),
                        content_length=result.get('content_length', 0),
                        response_time=result.get('response_time', 0),
                        title=result.get('title', ''),
                        forms=result.get('forms', []),
                        technologies=result.get('technologies', []),
                        security_headers=result.get('security_headers', {}),
                        cookies=result.get('cookies', []),
                        comments_count=result.get('comments_count', 0),
                        scripts_count=result.get('scripts_count', 0),
                        redirect_chain=redirect_chain
                    ))
            
            return CrawlResponse(
                success=True,
                message="Crawl completed successfully",
                crawl_summary=crawl_summary,
                discovery_statistics=discovery_stats,
                categorized_findings=categorized_findings,
                sensitivity_analysis=report_data.get('sensitivity_analysis', {}),
                technology_fingerprints=report_data.get('technology_fingerprints', {}),
                security_analysis=security_analysis,
                detailed_results=detailed_results,
                report_file=report_file
            )
            
        except Exception as e:
            # Print detailed error information for debugging
            print(f"Error converting crawl results: {str(e)}")
            print(f"Error type: {type(e)}")
            import traceback
            traceback.print_exc()
            
            return CrawlResponse(
                success=False,
                message=f"Error converting crawl results: {str(e)}"
            )
    
    def cleanup_old_tasks(self, max_age_hours: int = 24):
        """Clean up old completed tasks"""
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        
        # Clean completed tasks
        to_remove = []
        for task_id, task in self.completed_tasks.items():
            if task.end_time and task.end_time < cutoff_time:
                to_remove.append(task_id)
        
        for task_id in to_remove:
            del self.completed_tasks[task_id]


# Global service instance
crawler_service = WebCrawlerService()
