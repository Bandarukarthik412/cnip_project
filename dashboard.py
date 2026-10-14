import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, IP, TCP, UDP, ICMP, AsyncSniffer
import threading
import queue
from datetime import datetime

# ---------------- DATA ----------------
packet_queue = queue.Queue()
stop_event = threading.Event()

total = 0
tcp_count = 0
udp_count = 0
icmp_count = 0
other_count = 0

monitor_thread = None
sniffer = None
monitoring = False


# ---------------- PACKET CAPTURE ----------------
def capture_packet(packet):
    if IP not in packet:
        return

    source = packet[IP].src
    destination = packet[IP].dst

    if TCP in packet:
        protocol = "TCP"
    elif UDP in packet:
        protocol = "UDP"
    elif ICMP in packet:
        protocol = "ICMP"
    else:
        protocol = "Other"

    packet_queue.put((source, destination, protocol))


def monitor_network():
    global sniffer, monitoring

    try:
        sniffer = AsyncSniffer(
            prn=capture_packet,
            store=False
        )
        sniffer.start()

        while not stop_event.wait(0.2):
            pass

        if sniffer and sniffer.running:
            sniffer.stop()

    except Exception as error:
        packet_queue.put(("ERROR", str(error), "ERROR"))

    finally:
        monitoring = False
        root.after(0, monitoring_stopped)


# ---------------- START / STOP ----------------
def start_monitoring():
    global monitor_thread, monitoring

    if monitoring:
        status_label.config(text="Monitoring is already running")
        return

    stop_event.clear()
    monitoring = True

    status_label.config(
        text="Monitoring active",
        fg="#55d6be"
    )

    monitor_thread = threading.Thread(
        target=monitor_network,
        daemon=True
    )
    monitor_thread.start()


def stop_monitoring():
    if not monitoring:
        status_label.config(text="Monitoring is not running")
        return

    stop_event.set()
    status_label.config(
        text="Stopping monitoring...",
        fg="#ffcc66"
    )


def monitoring_stopped():
    status_label.config(
        text="Monitoring stopped",
        fg="#ffcc66"
    )


# ---------------- DASHBOARD UPDATE ----------------
def update_dashboard():
    global total, tcp_count, udp_count, icmp_count, other_count

    while not packet_queue.empty():
        source, destination, protocol = packet_queue.get()

        if protocol == "ERROR":
            status_label.config(
                text="Capture error: " + destination,
                fg="#ff7777"
            )
            continue

        total += 1

        if protocol == "TCP":
            tcp_count += 1
        elif protocol == "UDP":
            udp_count += 1
        elif protocol == "ICMP":
            icmp_count += 1
        else:
            other_count += 1

        total_label.config(text=str(total))
        tcp_label.config(text=str(tcp_count))
        udp_label.config(text=str(udp_count))
        icmp_label.config(text=str(icmp_count))
        other_label.config(text=str(other_count))

        table.insert(
            "",
            "end",
            values=(total, source, destination, protocol)
        )

        # Save packet details to file
        try:
            with open("traffic_log.txt", "a", encoding="utf-8") as file:
                file.write(
                    f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
                    f"Packet: {total} | Source: {source} | "
                    f"Destination: {destination} | Protocol: {protocol}\n"
                )
        except OSError as error:
            status_label.config(text=f"Log error: {error}")

        # Keep only the latest 100 rows visible
        children = table.get_children()
        if len(children) > 100:
            table.delete(children[0])

    root.after(200, update_dashboard)


# ---------------- GUI ----------------
root = tk.Tk()
root.title("CNIP - Network Traffic Monitor")
root.geometry("1000x700")
root.minsize(800, 550)
root.configure(bg="#172033")

title_label = tk.Label(
    root,
    text="NETWORK TRAFFIC MONITOR",
    font=("Arial", 22, "bold"),
    bg="#172033",
    fg="white"
)
title_label.pack(pady=(18, 5))

tk.Label(
    root,
    text="Live Network Monitoring Dashboard",
    font=("Arial", 11),
    bg="#172033",
    fg="#b8c7e0"
).pack(pady=(0, 12))


# ---------------- STAT CARDS ----------------
stats_frame = tk.Frame(root, bg="#172033")
stats_frame.pack(pady=12)


def create_stat(parent, heading, column):
    card = tk.Frame(
        parent,
        bg="#263650",
        padx=18,
        pady=12
    )
    card.grid(row=0, column=column, padx=6)

    tk.Label(
        card,
        text=heading,
        font=("Arial", 10, "bold"),
        bg="#263650",
        fg="white"
    ).pack()

    number = tk.Label(
        card,
        text="0",
        font=("Arial", 21, "bold"),
        bg="#263650",
        fg="#55d6be"
    )
    number.pack(pady=5)

    return number


total_label = create_stat(stats_frame, "TOTAL", 0)
tcp_label = create_stat(stats_frame, "TCP", 1)
udp_label = create_stat(stats_frame, "UDP", 2)
icmp_label = create_stat(stats_frame, "ICMP", 3)
other_label = create_stat(stats_frame, "OTHER", 4)


# ---------------- PACKET TABLE ----------------
tk.Label(
    root,
    text="Live Packet Activity",
    font=("Arial", 14, "bold"),
    bg="#172033",
    fg="white"
).pack(pady=(12, 7))

table_frame = tk.Frame(root, bg="#172033")
table_frame.pack(padx=20, fill="both", expand=True)

columns = ("number", "source", "destination", "protocol")

table = ttk.Treeview(
    table_frame,
    columns=columns,
    show="headings",
    height=12
)

table.heading("number", text="Packet")
table.heading("source", text="Source IP")
table.heading("destination", text="Destination IP")
table.heading("protocol", text="Protocol")

table.column("number", width=80, anchor="center")
table.column("source", width=250, anchor="center")
table.column("destination", width=250, anchor="center")
table.column("protocol", width=120, anchor="center")

scrollbar = ttk.Scrollbar(
    table_frame,
    orient="vertical",
    command=table.yview
)
table.configure(yscrollcommand=scrollbar.set)

table.pack(side="left", fill="both", expand=True)
scrollbar.pack(side="right", fill="y")


# ---------------- STATUS ----------------
status_label = tk.Label(
    root,
    text="Ready to monitor",
    font=("Arial", 10, "bold"),
    bg="#172033",
    fg="#55d6be"
)
status_label.pack(pady=10)


# ---------------- BUTTONS ----------------
button_frame = tk.Frame(root, bg="#172033")
button_frame.pack(pady=(0, 15))

start_button = tk.Button(
    button_frame,
    text="Start Monitoring",
    command=start_monitoring,
    bg="#16856b",
    fg="white",
    activebackground="#1ca786",
    font=("Arial", 11, "bold"),
    padx=18,
    pady=9
)
start_button.grid(row=0, column=0, padx=10)

stop_button = tk.Button(
    button_frame,
    text="Stop Monitoring",
    command=stop_monitoring,
    bg="#b83b4b",
    fg="white",
    activebackground="#d64b5d",
    font=("Arial", 11, "bold"),
    padx=18,
    pady=9
)
stop_button.grid(row=0, column=1, padx=10)


# ---------------- CLOSE WINDOW SAFELY ----------------
def close_dashboard():
    if monitoring:
        stop_event.set()

        try:
            if sniffer and sniffer.running:
                sniffer.stop()
        except Exception:
            pass

    root.destroy()


root.protocol("WM_DELETE_WINDOW", close_dashboard)
root.after(200, update_dashboard)
root.mainloop()

