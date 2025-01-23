import subprocess
import tkinter as tk
import threading
import queue
import webbrowser
from DNSSpoofDetector import DNSSpoofDetector
from tkinter import PhotoImage, messagebox
import os  # To work with file paths

class DNSMonitorApp:
    def __init__(self, root, detector):
        self.root = root
        self.detector = detector
        self.filtered_queue = self.detector.filtered_queue  # Get the filtered queue

        # Set the icon for the window using a .png image
        try:
            icon_path = "/usr/share/icons/app_icon.png"
            img = PhotoImage(file=icon_path)
            self.root.iconphoto(True, img)
        except Exception as e:
            print(f"Error loading icon: {e}")

        self.red_light_on = False  # Flag to track the red light state

        self.root.title("DNS Spoof Detector")
        self.root.geometry("600x400")

        # Set the background color of the window to black
        self.root.configure(bg='black')

        # Create GUI components
        self.text_area = tk.Text(self.root, wrap="word", height=15, width=70, bg='black', fg='white')
        self.text_area.pack(padx=10, pady=10)

        # Create tags for coloring the text
        self.text_area.tag_configure("green", foreground="green")
        self.text_area.tag_configure("red", foreground="red")

        # Create a Canvas for the light bulb indicator
        self.canvas = tk.Canvas(self.root, width=20, height=20, bg='black', bd=0, highlightthickness=0)
        self.canvas.pack(pady=5)

        # Add a label for the status message
        self.status_label = tk.Label(self.root, text="Status: Monitoring DNS Queries", font=("Arial", 12), bg='black', fg='black')
        self.status_label.pack(pady=5)

        frame = tk.Frame(self.root,bg='black')
        frame.pack(pady=5)

        self.view_logs_button = tk.Button(frame, text="View Logs", command=self.view_logs)
        self.view_logs_button.pack(side=tk.LEFT, padx=5)

        self.open_log_button = tk.Button(frame, text="Open log file", command=self.open_log_file)
        self.open_log_button.pack(side=tk.LEFT, padx=5)

        self.stop_monitoring_button = tk.Button(frame, text="Stop monitoring", command=self.stop_monitoring)
        self.stop_monitoring_button.pack(side=tk.LEFT, padx=5)

        # Start a separate thread for monitoring DNS
        self.monitoring_thread = threading.Thread(target=self.start_monitoring)
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()

        # Start the Tkinter loop
        self.update_gui()

    def start_monitoring(self):
        self.detector.start_monitoring()

    def stop_monitoring(self):
        self.filtered_queue = queue.Queue() # Clear the queue
        self.detector.stop_monitoring()




    def open_log_file(self):
        try:
            log_path = os.path.expanduser("~/Desktop/dns_queries.log")
            webbrowser.open(f"file://{log_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open logs: {e}")

    def update_gui(self):
        try:
            # Check for new logs in the filtered queue (processed and filtered)
            while not self.filtered_queue.empty():
                log = self.filtered_queue.get_nowait()

                # Check if the log contains the word "INVALID" to turn on the red light
                if "INVALID" in log:
                    self.red_light_on = True
                    self.text_area.insert(tk.END, log + "\n", "red")  # Red color for INVALID logs
                else:
                    self.text_area.insert(tk.END, log + "\n", "green")  # Green color for VALID logs

                self.text_area.yview(tk.END)  # Scroll to the bottom
                self.root.update_idletasks()  # Update the window

        except queue.Empty:
            pass

        # Update the light color and status text based on the flag
        if self.red_light_on:
            self.canvas.create_oval(5, 5, 15, 15, fill="red", outline="red")  # Red light
            self.status_label.config(text="Status: Attack detected", fg="grey")
        else:
            self.canvas.create_oval(5, 5, 15, 15, fill="green", outline="green")  # Green light
            self.status_label.config(text="Status: Ok", fg="grey")

        # Update the GUI every 50ms
        self.root.after(50, self.update_gui)

    def view_logs(self):
        log_file_path = os.path.expanduser("~/Desktop/dns_queries.log")  # Absolute path to Desktop
        try:
            with open(log_file_path, "r") as log_file:
                logs = log_file.read()
            
            # Open a new window to display the logs
            log_window = tk.Toplevel(self.root)
            log_window.title("View Logs")
            log_window.geometry("600x400")

            text_area = tk.Text(log_window, wrap="word", height=15, width=70)
            text_area.pack(padx=10, pady=10)
            text_area.insert(tk.END, logs)  # Insert the logs into the text area
            text_area.config(state=tk.DISABLED)  # Make the text area read-only
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open logs: {e}")

def main():
    # Initialize the detector
    detector = DNSSpoofDetector(verbose_logs_input=False)

    # Set up the Tkinter window
    root = tk.Tk()
    app = DNSMonitorApp(root, detector)

    root.mainloop()

if __name__ == "__main__":
    main()
