"""
Inference Engine for Hybrid IDS
Loads trained models and provides prediction wrappers with SHAP/LIME support.
Models inspected and confirmed:
  - Network: MLP, input=(None,52), output=(None,7), StandardScaler
  - Log: CNN-LSTM, input=(None,100), output=(None,1), Keras Tokenizer
"""

import os
import joblib
import numpy as np
import shap
import tensorflow as tf


class DetectionEngine:
    def __init__(self):
        self.network_model = None
        self.network_scaler = None
        self.network_encoder = None
        self.log_model = None
        self.log_tokenizer = None
        self.shap_explainer = None
        self.shap_background = None
        self.network_feature_names = []
        self.load_models()

    def load_models(self):
        model_dir = os.path.join(os.path.dirname(__file__), 'models')
        try:
            # --- Network MLP ---
            net_path = os.path.join(model_dir, 'mlp_network_intrusion.h5')
            if os.path.exists(net_path):
                self.network_model = tf.keras.models.load_model(net_path)
                self.network_scaler = joblib.load(os.path.join(model_dir, 'network_scaler.pkl'))
                self.network_encoder = joblib.load(os.path.join(model_dir, 'network_label_encoder.pkl'))
                self.network_feature_names = list(self.network_scaler.feature_names_in_)

                # SHAP background (scaled random samples)
                bg_raw = np.random.randn(30, len(self.network_feature_names)).astype(np.float32)
                self.shap_background = self.network_scaler.transform(bg_raw)
                self.shap_explainer = shap.DeepExplainer(self.network_model, self.shap_background)
                print(f"[OK] Network MLP: input={self.network_model.input_shape}, classes={list(self.network_encoder.classes_)}")
            else:
                print("[SKIP] Network MLP not found")

            # --- Log CNN-LSTM ---
            log_path = os.path.join(model_dir, 'cnnlstm_log_anomaly.h5')
            if os.path.exists(log_path):
                self.log_model = tf.keras.models.load_model(log_path)
                self.log_tokenizer = joblib.load(os.path.join(model_dir, 'log_tokenizer.pkl'))
                print(f"[OK] Log CNN-LSTM: input={self.log_model.input_shape}")
            else:
                print("[SKIP] Log CNN-LSTM not found")
        except Exception as e:
            print(f"[ERROR] Model loading: {e}")

    def predict_network(self, features):
        """
        Predict network flow classification.
        Args: features - numpy array of 52 CICIDS2017 features (unscaled)
        Returns: (label:str, confidence:float, shap_dict:dict)
        """
        if self.network_model is None:
            return None, None, {}

        try:
            if isinstance(features, (list, tuple)):
                features = np.array(features, dtype=np.float32)
            if features.ndim == 1:
                features = features.reshape(1, -1)

            # Scale features using the SAME scaler from training
            features_scaled = self.network_scaler.transform(features)

            # Predict
            proba = self.network_model.predict(features_scaled, verbose=0)
            pred_class = int(np.argmax(proba, axis=-1).flatten()[0])
            confidence = float(np.max(proba))
            label = str(self.network_encoder.inverse_transform([pred_class])[0])

            # SHAP explanation (in try/except to not block prediction)
            shap_dict = self._compute_shap(features_scaled, pred_class)

            return label, confidence, shap_dict

        except Exception as e:
            print(f"[ERROR] Network prediction: {e}")
            return None, None, {}

    def _compute_shap(self, features_scaled, pred_class):
        """Compute SHAP values for a single sample."""
        try:
            shap_values = self.shap_explainer.shap_values(features_scaled)

            if isinstance(shap_values, list):
                vals = np.array(shap_values[pred_class]).flatten()
            else:
                vals = np.array(shap_values).flatten()

            if vals.ndim > 1:
                vals = vals[0]

            n = min(len(vals), len(self.network_feature_names))
            vals = vals[:n]
            top_idx = np.argsort(np.abs(vals))[::-1][:5]
            return {
                self.network_feature_names[i]: round(float(vals[i]), 4)
                for i in top_idx if i < n
            }
        except Exception as e:
            print(f"[WARN] SHAP failed: {e}")
            return {}

    def predict_log(self, log_text):
        """
        Predict system log anomaly.
        Args: log_text - raw log string
        Returns: (label:str, confidence:float, explanation:str)
        """
        if self.log_model is None:
            return None, None, None

        try:
            seq = self.log_tokenizer.texts_to_sequences([log_text])
            padded = tf.keras.preprocessing.sequence.pad_sequences(
                seq, maxlen=100, padding='post', truncating='post'
            )
            prob = float(self.log_model.predict(padded, verbose=0)[0][0])

            if prob > 0.5:
                return "Anomaly", prob, (
                    f"Log classified as ANOMALY (score: {prob:.2%}). "
                    f"Sequence pattern deviates from normal log behavior."
                )
            else:
                return "Normal", 1 - prob, (
                    f"Log classified as NORMAL (score: {1-prob:.2%}). "
                    f"Log follows expected patterns."
                )
        except Exception as e:
            print(f"[ERROR] Log prediction: {e}")
            return None, None, None

    def get_network_feature_names(self):
        """Return the 52 feature names expected by the model."""
        return self.network_feature_names


engine = DetectionEngine()
