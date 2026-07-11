import numpy as np
from sklearn.ensemble import IsolationForest

from app.utils import get_logger

logger = get_logger(__name__)

class MLEngine:
    """Use Isolation Forest for local traffic-baseline anomaly detection."""

    def __init__(self):
        self.model = IsolationForest(contamination=0.05, random_state=42)
        self.is_trained = False
        self.feature_history = []

    def prepare_features(self, stats):
        """Extract numerical features from traffic statistics."""
        return [
            stats.get("total_packets", 0),
            stats.get("total_bytes", 0),
            len(stats.get("dest_ports", {})),
            stats.get("dns_queries", 0),
            stats.get("syn_packets", 0),
            stats.get("threat_score", 0)
        ]

    def train_model(self, all_stats):
        """Train the model when enough hosts are available for a baseline."""
        data = [self.prepare_features(s) for s in all_stats.values()]
        if len(data) < 10:
            return False
            
        X = np.array(data)
        self.model.fit(X)
        self.is_trained = True
        logger.info("ML Anomaly Detection model trained on baseline.")
        return True

    def predict_anomaly(self, stats):
        """Return whether the trained model marks the host statistics as anomalous."""
        if not self.is_trained:
            return False
            
        X = np.array([self.prepare_features(stats)])
        prediction = self.model.predict(X)
        is_anomaly = prediction[0] == -1
        if is_anomaly:
            logger.warning("ML anomaly detected for host behavior.")
        return is_anomaly
