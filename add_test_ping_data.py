#!/usr/bin/env python3
import sys
import random
from datetime import datetime, timedelta
import database as db

def add_test_ping_data(domain_name, num_entries=50):
    """Add test ping data for a domain"""
    print(f"Adding {num_entries} test ping entries for {domain_name}...")
    
    # Get the domain
    domain = db.get_domain_by_name(domain_name)
    if not domain:
        print(f"Domain {domain_name} not found!")
        return False
    
    # Generate test data
    current_time = datetime.now()
    success_count = 0
    
    for i in range(num_entries):
        # Create a timestamp going back in time
        timestamp = current_time - timedelta(hours=i)
        
        # Generate a random response time between 10ms and 200ms
        response_time = random.randint(10, 200)
        
        # Most entries should be 'up', but add some 'down' entries randomly
        status = 'up' if random.random() > 0.1 else 'down'
        
        # Record the ping status
        success = db.record_ping_status(domain_name, status, response_time)
        if success:
            success_count += 1
    
    print(f"Successfully added {success_count} ping entries for {domain_name}")
    return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python add_test_ping_data.py <domain_name> [num_entries]")
        sys.exit(1)
    
    domain_name = sys.argv[1]
    num_entries = int(sys.argv[2]) if len(sys.argv) > 2 else 50
    
    add_test_ping_data(domain_name, num_entries)
