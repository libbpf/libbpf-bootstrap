import sys
import re
from collections import deque
from sklearn.ensemble import IsolationForest

# --- TUNING PARAMETERS ---
WINDOW_SIZE = 2000    # The AI remembers the last 2000 system events
RETRAIN_EVERY = 300   # Refresh the model every 300 new events
CONTAMINATION = 0.001 # Sensitivity (0.1% of events flagged as weird)

# --- THE ENGINE ---
window = deque(maxlen=WINDOW_SIZE)
model = None
events_since_train = 0

def normalize_path(path):
    """
    Strips random hashes/hex from filenames (Spotify/Zen noise).
    Example: 'data_A53F00B8.bin' -> 'data_HASH.bin'
    """
    return re.sub(r'[a-fA-F0-9]{8,}', 'HASH', path)

def get_features(pid, comm, filename):
    """Turns raw kernel data into a numeric vector."""
    norm_path = normalize_path(filename)
    return [
        float(pid) / 100000,          # Normalized PID
        len(comm),                     # Process name length
        len(norm_path),                # Normalized path length
        norm_path.count('/'),          # Folder depth
        1 if ".cache" in filename else 0 # Cache flag
    ]

print(" KernelTrace AI: Adaptive Engine Starting...")

try:
    for line in sys.stdin:
        try:
            # Parse the CSV data from the C loader
            parts = line.strip().split(',', 2)
            if len(parts) < 3: continue
            pid, comm, filename = parts

            # 1. Feature Engineering
            features = get_features(pid, comm, filename)
            window.append(features)
            events_since_train += 1

            # 2. Initial Training
            if model is None and len(window) == WINDOW_SIZE:
                print(" Baseline captured. Protection Active.")
                model = IsolationForest(contamination=CONTAMINATION, n_jobs=-1)
                model.fit(list(window))

            # 3. Sliding Window Retrain
            if model and events_since_train >= RETRAIN_EVERY:
                model.fit(list(window))
                events_since_train = 0
                # print("AI Brain updated with recent system patterns.")

            # 4. Anomaly Detection
            if model:
                prediction = model.predict([features])[0]
                if prediction == -1:
                    score = model.decision_function([features])[0]
                    # Print formatted for the Bun server pipe
                    print(f" ALERT | Score: {score:.3f} | Proc: {comm} | Path: {filename}")
                    sys.stdout.flush() # Ensure the pipe sees this immediately

        except ValueError:
            continue

except KeyboardInterrupt:
    print("\n\n Brain shutting down safely. Great hunt!")
    sys.exit(0)
