import asyncio
import datetime
from app.parser import parse_packet
from app.utils import get_logger

logger = get_logger(__name__)

class NetSentinelEngine:
    """
    Elite Async Processing Engine.
    Decouples packet capture from analysis and persistence for high-speed ops.
    """
    def __init__(self, db, analyzer, detection_engine):
        self.db = db
        self.analyzer = analyzer
        self.detection_engine = detection_engine
        self.queue = asyncio.Queue(maxsize=10000)
        self.is_running = False

    async def enqueue_packet(self, packet):
        """ Adds raw packet to the processing queue """
        if self.queue.full():
            logger.warning("Engine queue full, dropping packet.")
            return
        await self.queue.put(packet)

    async def process_loop(self):
        """ Main processing loop - runs asynchronously """
        self.is_running = True
        logger.info("Elite Async Engine started.")
        
        while self.is_running:
            try:
                packet = await self.queue.get()
                
                # 1. Parse
                timestamp = datetime.datetime.now()
                parsed = parse_packet(packet, timestamp.isoformat())
                
                # 2. Persist
                self.db.add_packet({
                    **parsed,
                    "timestamp": timestamp
                })
                
                # 3. Analyze & Detect
                self.analyzer.analyze_packet(parsed)
                src_ip = parsed.get("source_ip")
                stats = self.analyzer.get_traffic_stats(src_ip) if src_ip else {}
                self.detection_engine.run_detections(parsed, self.analyzer.connections, {src_ip: stats} if src_ip else {})
                
                self.queue.task_done()
                
            except Exception as e:
                logger.error(f"Engine Loop Error: {e}")
                await asyncio.sleep(0.1)

    def stop(self):
        self.is_running = False
        logger.info("Elite Async Engine stopping.")
