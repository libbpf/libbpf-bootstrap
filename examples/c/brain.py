import sys

print("AI Brain is online. Waiting for kernel data...")

try:
    for line in sys.stdin:
        # 1. Parse the incoming data
        line = line.strip()
        if not line:
            continue

        try:
            pid, comm, filename = line.split(',', 2)

            # 2. This is where 'Find Out' learning happens!
            # For now, let's just flag if a specific file is touched
            if "test.txt" in filename.lower():
                print(f"⚠️  AI ALERT: Process {comm} (PID {pid}) accessed sensitive file: {filename}")

            # todo: Future step - feed (pid, comm, filename) into Isolation Forest

        except ValueError:
            continue # Skip malformed lines

except KeyboardInterrupt:
    print("\nBrain shutting down.")

