import os
import stat
import pwd
import hashlib
import psutil

def get_process_exe_path(pid):
    """
    Retrieves the absolute path of the executable for the given PID.
    """
    try:
        proc = psutil.Process(pid)
        return proc.exe()
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        raise e
    except Exception as e:
        raise e

def analyze_executable(filepath):
    """
    Performs local static analysis on an executable file:
    - Absolute path
    - File size
    - Owner name
    - Permissions string
    - SUID bit check
    - SHA-256 hash (chunk-based)
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
        
    # Get stats
    file_stat = os.stat(filepath)
    size = file_stat.st_size
    
    # Get owner
    try:
        owner_name = pwd.getpwuid(file_stat.st_uid).pw_name
    except KeyError:
        owner_name = str(file_stat.st_uid)
        
    # Check permissions and SUID
    mode = file_stat.st_mode
    is_suid = bool(mode & stat.S_ISUID)
    perms_str = stat.filemode(mode)
    
    # Calculate SHA-256 in 8KB chunks
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        sha256_hash = sha256.hexdigest()
    except PermissionError as e:
        sha256_hash = f"Access Denied: {str(e)}"
    except Exception as e:
        sha256_hash = f"Error: {str(e)}"
        
    return {
        "path": os.path.abspath(filepath),
        "size": size,
        "owner": owner_name,
        "permissions": perms_str,
        "is_suid": is_suid,
        "sha256": sha256_hash
    }
