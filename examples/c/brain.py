from bcc import BPF
import ctypes as ct

# 1. Define the same struct as your C code
class Event(ct.Structure):
    _fields_ = [
        ("pid", ct.c_int),
        ("comm", ct.c_char * 16),
        ("filename", ct.c_char * 256),
    ]

# 2. This function runs every time an event pops out of the Ring Buffer
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Event)).contents
    print(f"ALARM! PID: {event.pid} | Process: {event.comm.decode()} | File: {event.filename.decode()}")

# 3. Load the compiled BPF object
# Note: You need to point this to your generated .o file
b = BPF(src_file="spy.bpf.c") 

# 4. Attach to the Ring Buffer
b["rb"].open_ring_buffer(print_event)

print("Brain is active. Listening for suspicious file opens...")

# 5. The "Listen" Loop
try:
    while True:
        b.ring_buffer_poll()
except KeyboardInterrupt:
    exit()
