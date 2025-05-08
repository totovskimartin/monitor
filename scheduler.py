"""
Scheduler module for background tasks
"""

import logging
import atexit
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger
import database as db
from app import check_ping

# Configure logging
logger = logging.getLogger('scheduler')

# Global scheduler instance
scheduler = None

def run_ping_checks():
    """Run ping checks for all domains"""
    logger.info("Running ping checks for all domains")
    try:
        # Get all domains
        with db.get_db() as db_session:
            domains = db_session.query(db.Domain).all()
            
            for domain in domains:
                try:
                    # Check if ping monitoring is enabled for this domain
                    ping_monitored = db.get_organization_setting(
                        domain.organization_id, 
                        f"domain_{domain.id}_ping_monitored", 
                        False
                    )
                    
                    if not ping_monitored:
                        continue
                        
                    # Run ping check
                    logger.debug(f"Running ping check for {domain.name}")
                    ping_result = check_ping(domain.name)
                    
                    # Log the result
                    logger.debug(f"Ping check for {domain.name}: {ping_result}")
                    
                except Exception as e:
                    logger.error(f"Error running ping check for {domain.name}: {e}")
    except Exception as e:
        logger.error(f"Error in run_ping_checks: {e}")

def init_scheduler(app=None):
    """Initialize the scheduler"""
    global scheduler
    
    if scheduler:
        logger.warning("Scheduler already initialized")
        return scheduler
        
    logger.info("Initializing scheduler")
    
    # Create scheduler
    scheduler = BackgroundScheduler()
    
    # Add ping check job (every 5 minutes)
    scheduler.add_job(
        func=run_ping_checks,
        trigger=IntervalTrigger(minutes=5),
        id='ping_check_job',
        name='Check ping status for all domains',
        replace_existing=True
    )
    
    # Add hourly statistics aggregation job (every hour at minute 5)
    scheduler.add_job(
        func=db.aggregate_hourly_statistics,
        trigger=CronTrigger(minute=5),
        id='hourly_stats_job',
        name='Aggregate hourly uptime statistics',
        replace_existing=True
    )
    
    # Add daily statistics aggregation job (every day at 00:10)
    scheduler.add_job(
        func=db.aggregate_daily_statistics,
        trigger=CronTrigger(hour=0, minute=10),
        id='daily_stats_job',
        name='Aggregate daily uptime statistics',
        replace_existing=True
    )
    
    # Add weekly statistics aggregation job (every Monday at 00:15)
    scheduler.add_job(
        func=db.aggregate_weekly_statistics,
        trigger=CronTrigger(day_of_week=0, hour=0, minute=15),
        id='weekly_stats_job',
        name='Aggregate weekly uptime statistics',
        replace_existing=True
    )
    
    # Add monthly statistics aggregation job (1st day of month at 00:20)
    scheduler.add_job(
        func=db.aggregate_monthly_statistics,
        trigger=CronTrigger(day=1, hour=0, minute=20),
        id='monthly_stats_job',
        name='Aggregate monthly uptime statistics',
        replace_existing=True
    )
    
    # Start the scheduler
    scheduler.start()
    
    # Register shutdown function
    atexit.register(lambda: scheduler.shutdown())
    
    logger.info("Scheduler initialized with jobs")
    
    return scheduler

def get_scheduler():
    """Get the scheduler instance"""
    global scheduler
    if not scheduler:
        scheduler = init_scheduler()
    return scheduler

def get_scheduler_jobs():
    """Get all scheduler jobs"""
    global scheduler
    if not scheduler:
        return []
    
    jobs = []
    for job in scheduler.get_jobs():
        jobs.append({
            'id': job.id,
            'name': job.name,
            'next_run_time': job.next_run_time.strftime('%Y-%m-%d %H:%M:%S') if job.next_run_time else None,
            'trigger': str(job.trigger)
        })
    
    return jobs

def pause_job(job_id):
    """Pause a job"""
    global scheduler
    if not scheduler:
        return False
    
    job = scheduler.get_job(job_id)
    if not job:
        return False
    
    job.pause()
    return True

def resume_job(job_id):
    """Resume a job"""
    global scheduler
    if not scheduler:
        return False
    
    job = scheduler.get_job(job_id)
    if not job:
        return False
    
    job.resume()
    return True

def run_job_now(job_id):
    """Run a job immediately"""
    global scheduler
    if not scheduler:
        return False
    
    job = scheduler.get_job(job_id)
    if not job:
        return False
    
    job.func()
    return True
