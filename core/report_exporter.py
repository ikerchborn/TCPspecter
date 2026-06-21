import csv
import json
import os

def export_report(filepath, format_type, processes, connections, analysis_results=None):
    """
    Exports current processes and connection states along with analysis reports to JSON or CSV.
    """
    if not filepath:
        raise ValueError("Filepath cannot be empty.")
        
    data_to_export = {
        "processes": processes,
        "connections": connections,
        "analysis_results": analysis_results or {}
    }
    
    if format_type.upper() == "JSON":
        with open(filepath, "w") as f:
            json.dump(data_to_export, f, indent=2)
            
    elif format_type.upper() == "CSV":
        # Write flat rows containing process information joined with connection details
        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)
            # Headers
            writer.writerow([
                "Type", "PID", "Process Name", "User", "CPU%", "RAM%", 
                "Proto", "Local IP", "Local Port", "Remote IP", "Remote Port", "Status"
            ])
            
            # Write processes
            for p in processes:
                writer.writerow([
                    "PROCESS", p["pid"], p["name"], p["user"], p["cpu"], p["ram"],
                    "", "", "", "", "", ""
                ])
                
            # Write connections
            for c in connections:
                writer.writerow([
                    "CONNECTION", c.get("pid", "-"), c.get("name", "-"), "", "", "",
                    c["proto"], c["laddr_ip"], c["laddr_port"], c["raddr_ip"], c["raddr_port"], c["status"]
                ])
    else:
        raise ValueError(f"Unsupported format type: {format_type}")
