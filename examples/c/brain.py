import sys
import pandas as pd
from sklearn.ensemble import IsolationForest

# Setup the AI model
# 'contamination' is the % of data you expect to be weird (e.g., 1%)
model = IsolationForest(contamination=0.01)
training_data = []
trained = False

print("🛡️ KernelTrace AI: Watching for anomalies...")

for line in sys.stdin:
    try:
        pid, comm, filename = line.strip().split(',', 2)
        
        # FEATURE ENGINEERING: Turn text into numbers the AI can 'see'
        features = [
            float(pid), 
            len(comm), 
            len(filename), 
            filename.count('/')  # Folder depth is a huge risk signal
        ]

        if not trained:
            training_data.append(features)
            if len(training_data) >= 100: # Learn from first 100 events
                model.fit(training_data)
                trained = True
                print("✅ Learning complete. Active protection engaged.")
        else:
            prediction = model.predict([features])[0]
            if prediction == -1: # -1 means 'Anomaly'
                print(f"🚨 ALERT: Suspicious activity from {comm} (PID {pid})")
                print(f"   Accessed: {filename}")
                
    except:
        continue
