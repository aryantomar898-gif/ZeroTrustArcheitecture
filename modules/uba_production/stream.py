"""
S8: Stream processing integration (Kafka / Polling).
"""

from __future__ import annotations

import asyncio
import json
import logging

from sentinelcommand.core.config import get_settings
from sentinelcommand.core.database import async_session_factory
from sentinelcommand.modules.uba_production.engine import ProductionUBAEngine

logger = logging.getLogger(__name__)
_settings = get_settings()


class KafkaStreamProcessor:
    """Consumes security events from Kafka and feeds them to the UBA Engine."""
    
    def __init__(self):
        self.is_running = False
        self._task = None
        
    async def start(self):
        if not _settings.KAFKA_BOOTSTRAP_SERVERS:
            logger.warning("Kafka not configured. Stream processor disabled.")
            return
            
        self.is_running = True
        self._task = asyncio.create_task(self._consume())
        logger.info(f"Started Kafka consumer on topic {_settings.KAFKA_TOPIC}")
        
    async def stop(self):
        self.is_running = False
        if self._task:
            self._task.cancel()
            
    async def _consume(self):
        try:
            from aiokafka import AIOKafkaConsumer
            
            consumer = AIOKafkaConsumer(
                _settings.KAFKA_TOPIC,
                bootstrap_servers=_settings.KAFKA_BOOTSTRAP_SERVERS,
                group_id=_settings.KAFKA_GROUP_ID,
                value_deserializer=lambda m: json.loads(m.decode('utf-8'))
            )
            
            await consumer.start()
            
            try:
                async for msg in consumer:
                    if not self.is_running:
                        break
                        
                    event = msg.value
                    async with async_session_factory() as db:
                        engine = ProductionUBAEngine(db)
                        # In production, we'd load custom rules once globally
                        await engine.process_event(event)
                        
            finally:
                await consumer.stop()
                
        except ImportError:
            logger.error("aiokafka not installed. Run: pip install aiokafka")
        except Exception as e:
            logger.error(f"Kafka consumer error: {e}")
