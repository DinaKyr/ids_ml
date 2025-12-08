import pandas as pd
import joblib

class PacketPred:
    def __init__(self, model_path, analyzer):

        self.analyzer = analyzer
        self.model_package = joblib.load(model_path)
        self.mlp = self.model_package["mlp_model"]
        self.scaler = self.model_package["scaler"]
        self.target_encoder = self.model_package["target_encoder"]
        self.selected_features = self.model_package["selected_features"]

    def predict(self, packet):
        features = self.analyzer.analyze_packet(packet)
        if not features:
            return None, None

        df = pd.DataFrame([features])

        # Target encode service (as DataFrame)
        df[['service']] = self.target_encoder.transform(df[['service']])

        # Scale numeric features
        df[self.selected_features] = self.scaler.transform(df[self.selected_features])

        pred_class = self.mlp.predict(df)[0]
        pred_prob = self.mlp.predict_proba(df).max()

        return pred_class, pred_prob
