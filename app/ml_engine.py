import numpy as np
from sklearn.ensemble import IsolationForest
import pandas as pd
from app.utils import get_logger

logger = get_logger(__name__)

class MLEngine:
    """
    Ultra-Expert ML Engine.
    Uses Isolation Forest for unsupervised anomaly detection on traffic patterns.
    """
    def __init__(self):
        self.model = IsolationForest(contamination=0.05, random_state=42)
        self.is_trained = False
        self.feature_history = []

    def prepare_features(self, stats):
        """ Extracts numerical features from traffic stats for ML """
        return [
            stats.get("total_packets", 0),
            stats.get("total_bytes", 0),
            len(stats.get("dest_ports", {})),
            stats.get("dns_queries", 0),
            stats.get("syn_packets", 0),
            stats.get("threat_score", 0)
        ]

    def train_model(self, all_stats):
        """ Trains the model on current traffic baseline """
        data = [self.prepare_features(s) for s in all_stats.values()]
        if len(data) < 10: # Minimum data to train
            return False
            
        X = np.array(data)
        self.model.fit(X)
        self.is_trained = True
        logger.info("ML Anomaly Detection model trained on baseline.")
        return True

    def predict_anomaly(self, stats):
        """ Predicts if a host's behavior is an anomaly """
        if not self.is_trained:
            return False
            
        X = np.array([self.prepare_features(stats)])
        prediction = self.model.predict(X)
        # -1 is anomaly, 1 is normal
        is_anomaly = prediction[0] == -1
        if is_anomaly:
            logger.warning(f"ML: Anomaly detected for host behavior.")
        return is_anomaly
