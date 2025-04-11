from collections import deque
from datetime import datetime
import threading
import time

# 최근 30분간의 통계를 저장 (10초 간격으로)
MAX_STATS_LENGTH = 180
stats_history = deque(maxlen=MAX_STATS_LENGTH)
active_users = set()
request_count = 0
start_time = datetime.now()

def get_system_stats():
    return {
        'timestamp': datetime.now(),
        'active_users': len(active_users),
        'requests_per_minute': calculate_requests_per_minute()
    }

def calculate_requests_per_minute():
    global request_count
    elapsed_minutes = (datetime.now() - start_time).total_seconds() / 60
    if elapsed_minutes == 0:
        return 0
    return round(request_count / elapsed_minutes, 2)

def collect_stats():
    while True:
        stats = get_system_stats()
        stats_history.append(stats)
        time.sleep(10)  # 10초마다 통계 수집

def init_stats():
    stats_thread = threading.Thread(target=collect_stats, daemon=True)
    stats_thread.start()

def record_request(user_id=None):
    global request_count
    request_count += 1
    if user_id:
        active_users.add(user_id)

def remove_user(user_id):
    if user_id in active_users:
        active_users.remove(user_id)

def get_current_stats():
    return {
        'current': get_system_stats(),
        'history': list(stats_history)
    }
