import os

files_to_remove = [
    'scan_report.html', 
    'scan_report.json', 
    'scan_results.json', 
    'dismap_debug.log', 
    'dismap_scan.log'
]

for file in files_to_remove:
    try:
        os.remove(file)
        print(f"Removed {file}")
    except FileNotFoundError:
        print(f"{file} not found")
    except Exception as e:
        print(f"Error removing {file}: {e}")
