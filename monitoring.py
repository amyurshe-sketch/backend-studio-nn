# monitoring.py
import time
import logging
from datetime import datetime
from typing import Dict, List
import psutil
import os

logger = logging.getLogger("myapp.monitoring")

class PerformanceMonitor:
    def __init__(self):
        self.request_times: Dict[str, List[float]] = {}
        self.error_count = 0
        self.success_count = 0
        
    def log_request(self, method: str, path: str, duration: float, status_code: int):
        """Логирование метрик запроса"""
        key = f"{method}_{path}"
        
        if key not in self.request_times:
            self.request_times[key] = []
        
        self.request_times[key].append(duration)
        
        if status_code >= 400:
            self.error_count += 1
        else:
            self.success_count += 1
            
        # Сохраняем только последние 1000 записей для каждого эндпоинта
        if len(self.request_times[key]) > 1000:
            self.request_times[key] = self.request_times[key][-1000:]
    
    def get_performance_stats(self) -> Dict:
        """Получить статистику производительности"""
        stats = {
            "timestamp": datetime.utcnow().isoformat(),
            "total_requests": self.success_count + self.error_count,
            "success_count": self.success_count,
            "error_count": self.error_count,
            "error_rate": self.error_count / max(1, self.success_count + self.error_count),
            "endpoints": {},
            "system": self.get_system_stats()
        }
        
        for endpoint, times in self.request_times.items():
            if times:
                stats["endpoints"][endpoint] = {
                    "request_count": len(times),
                    "avg_time": sum(times) / len(times),
                    "max_time": max(times),
                    "min_time": min(times),
                    "p95_time": sorted(times)[int(len(times) * 0.95)] if len(times) > 1 else times[0]
                }
        
        return stats
    
    def get_system_stats(self) -> Dict:
        """Получить системные метрики"""
        process = psutil.Process(os.getpid())
        memory_info = process.memory_info()
        
        return {
            "memory_mb": memory_info.rss / 1024 / 1024,
            "memory_percent": process.memory_percent(),
            "cpu_percent": process.cpu_percent(),
            "system_memory_percent": psutil.virtual_memory().percent,
            "system_cpu_percent": psutil.cpu_percent(interval=None),
            "open_connections": len(process.connections()) if hasattr(process, 'connections') else 0
        }
    
    def log_performance_metrics(self):
        """Периодическое логирование метрик"""
        stats = self.get_performance_stats()
        logger.info(f"PERFORMANCE_METRICS - {stats}")

# Глобальный экземпляр монитора
performance_monitor = PerformanceMonitor()

def measure_performance(endpoint_name: str = None):
    """Декоратор для измерения производительности эндпоинтов"""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start_time
                
                # Логируем производительность
                if endpoint_name:
                    logger.info(f"PERFORMANCE - {endpoint_name} - {duration:.3f}s")
                
                return result
            except Exception as e:
                duration = time.time() - start_time
                logger.error(f"PERFORMANCE_ERROR - {endpoint_name} - {duration:.3f}s - Error: {str(e)}")
                raise
        return wrapper
    return decorator