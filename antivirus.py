import os
import hashlib
import requests
import threading
import queue
import flet as ft

# Constants
API_KEY = "8d660b105c3f1a824a7664f95319689550dde6a2046c6be9fa603633c7dfddc6"
FILE_EXTENSIONS = ['.exe', '.dll', '.zip', '.rar', '.msi']
THREAD_COUNT = 10

stop_scan = False  # Global variable to stop scanning
delete_button_clicked = False  # Flag to track if the delete button has been clicked

def calculate_file_hash(file_path, algorithms=['sha256', 'md5', 'sha1']):
    """Calculate multiple hashes of a file."""
    hashes = {}
    for algorithm in algorithms:
        hash_func = hashlib.new(algorithm)
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    hash_func.update(chunk)
            hashes[algorithm] = hash_func.hexdigest()
        except (FileNotFoundError, PermissionError, OSError):
            hashes[algorithm] = None
    return hashes

def check_hash_virustotal(file_hashes, api_key):
    """Check file hashes against VirusTotal."""
    headers = {'x-apikey': api_key}
    results = {}

    for algorithm, file_hash in file_hashes.items():
        if file_hash:  # Only check if the hash is valid
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            try:
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    json_response = response.json()
                    stats = json_response.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    results[algorithm] = stats.get("malicious", 0) > 0
                else:
                    results[algorithm] = False
            except requests.RequestException:
                results[algorithm] = False
    return results

def scan_worker(file_queue, infected_files, lock, api_key, progress_update):
    """Worker thread to process files."""
    while not file_queue.empty() and not stop_scan:
        file_path = file_queue.get()
        progress_update(file_path)
        file_hashes = calculate_file_hash(file_path)
        malicious_found = check_hash_virustotal(file_hashes, api_key)

        # If any hash shows malicious, add it to the infected files list
        if any(malicious_found.values()):
            with lock:
                infected_files.append(file_path)
        
        file_queue.task_done()

def scan_directory(directory, api_key, thread_count, progress_callback):
    """Scan a directory with multithreading.""" 
    file_queue = queue.Queue()
    infected_files = []
    lock = threading.Lock()

    # Enqueue files
    for root, _, files in os.walk(directory):
        for file in files:
            if any(file.lower().endswith(ext) for ext in FILE_EXTENSIONS):
                file_queue.put(os.path.join(root, file))

    # Start threads
    threads = []
    for _ in range(thread_count):
        thread = threading.Thread(target=scan_worker, args=(file_queue, infected_files, lock, api_key, progress_callback))
        thread.start()
        threads.append(thread)

    # Wait for all threads to finish
    file_queue.join()
    for thread in threads:
        thread.join()

    return infected_files

def main(page: ft.Page):
    page.title = "Antivirus Scanner"
    page.window_width = 600
    page.window_height = 400
    page.theme_mode = ft.ThemeMode.LIGHT

    # UI Components
    output_text = ft.Text(value="", size=14, expand=True)
    progress_bar = ft.ProgressBar(width=400, visible=False)
    progress_text = ft.Text(value="", size=12)
    notification = ft.SnackBar(ft.Text("Scan Completed!"), open=False)

    # Create a notification for file deletion success
    delete_notification = ft.SnackBar(
        ft.Text("Virus has been deleted."),
        open=False  # Initially not open
    )
    page.overlay.append(delete_notification)

    # File Picker
    file_picker = ft.FilePicker(on_result=lambda e: directory_selected(e.path))
    page.overlay.append(file_picker)  # Add FilePicker to the page

    # Progress callback
    def progress_callback(file_path):
        progress_text.value = f"Scanning: {file_path}"
        page.update()

    # Perform scan for all drives
    def scan_all_drives():
        global stop_scan
        stop_scan = False
        output_text.value = "Scanning all drives...\n"
        progress_bar.visible = True
        stop_scan_button.visible = True  # Make stop scan button visible when scanning starts
        page.update()

        infected_files = []
        drives = [f"{chr(d)}:\\" for d in range(65, 91) if os.path.exists(f"{chr(d)}:\\")]  # Get all drives

        for drive in drives:
            if stop_scan:
                break
            progress_text.value = f"Scanning drive: {drive}"
            page.update()
            infected_files.extend(scan_directory(drive, API_KEY, THREAD_COUNT, progress_callback))

        finalize_scan(infected_files)

    # Perform scan for selected directory
    def scan_selected_directory():
        file_picker.get_directory_path()  # Show directory picker dialog

    # Directory selected callback
    def directory_selected(selected_path):
        global stop_scan
        stop_scan = False
        if selected_path:
            output_text.value = f"Scanning directory: {selected_path}\n"
            progress_bar.visible = True
            stop_scan_button.visible = True  # Make stop scan button visible when scanning starts
            page.update()

            infected_files = scan_directory(selected_path, API_KEY, THREAD_COUNT, progress_callback)
            finalize_scan(infected_files)

    # Finalize scan
    def finalize_scan(infected_files):
        progress_bar.visible = False
        stop_scan_button.visible = False  # Hide the Stop button after scan finishes

        if infected_files:
            output_text.value += "⚠️ Infected files detected:\n" + "\n".join(infected_files)
            delete_button.visible = True  # Show Delete button if infected files are found
            ask_delete_files(infected_files)  # Pass infected files for deletion
        else:
            output_text.value = "✅ No threats detected. Your system is clean."
        notification.open = True
        page.update()

    # Prompt user to delete infected files
    def ask_delete_files(infected_files):
        global delete_button_clicked
        if delete_button_clicked:
            return  # Prevent re-clicking after deletion

        def delete_files():
            nonlocal infected_files
            if not infected_files:
                return  # If no infected files, exit early

            for file in infected_files:
                try:
                    os.remove(file)
                    print(f"Deleted: {file}")
                except Exception as e:
                    print(f"Error deleting {file}: {e}")
            delete_notification.open = True  # Show modal notification
            output_text.value = "Virus files have been deleted."
            page.update()

            delete_button_clicked = True  # Mark that the delete button was clicked
            delete_button.visible = False  # Hide delete button after it's clicked
            cancel_button.visible = False  # Hide cancel button after it's clicked
            page.update()

        def cancel_delete():
            # Hide the delete and cancel buttons when cancel is clicked
            delete_button.visible = False
            cancel_button.visible = False
            page.update()

        # Ask for confirmation to delete
        delete_button = ft.ElevatedButton("Delete Infected Files", on_click=lambda e: delete_files(), visible=True)
        cancel_button = ft.ElevatedButton("Cancel", on_click=lambda e: cancel_delete(), visible=True)

        # Disable the delete button after it's clicked
        delete_button.disabled = delete_button_clicked

        page.add(
            ft.Row([delete_button, cancel_button], alignment=ft.MainAxisAlignment.CENTER)
        )

    # Stop scanning
    def stop_scanning():
        global stop_scan
        stop_scan = True
        output_text.value = "Scan has been stopped."
        progress_bar.visible = False
        page.update()

    # Buttons
    scan_all_button = ft.ElevatedButton("Scan All Drives", on_click=lambda _: threading.Thread(target=scan_all_drives, daemon=True).start())
    scan_selected_button = ft.ElevatedButton("Scan Specific Directory", on_click=lambda _: scan_selected_directory())
    stop_scan_button = ft.ElevatedButton("Stop Scanning", on_click=lambda _: stop_scanning(), visible=False)  # Initially hidden
    delete_button = ft.ElevatedButton("Delete Files", on_click=lambda e: ask_delete_files([]), visible=False)  # Initially hidden

    # Layout
    page.add(
        ft.Column(
            [
                ft.Row([ft.Text("Antivirus Scanner", size=24)], alignment=ft.MainAxisAlignment.CENTER),
                ft.Row([scan_all_button, scan_selected_button], alignment=ft.MainAxisAlignment.CENTER),
                progress_bar,
                progress_text,
                ft.Container(output_text, expand=True, padding=10, border_radius=10, bgcolor=ft.colors.GREY_100),
                stop_scan_button,  # Add stop button to the layout
                delete_button  # Add delete button to the layout (hidden by default)
            ],
            spacing=20,
            expand=True,
        )
    )
    page.snack_bar = notification

if __name__ == "__main__":
    ft.app(target=main)
